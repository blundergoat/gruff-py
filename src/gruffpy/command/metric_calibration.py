"""Developer-only metric distribution dump for threshold calibration."""

import math
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.exceptions import ConfigError
from gruffpy.config.loader import ConfigLoader
from gruffpy.config.rule_settings import RuleSettings, SeverityThreshold
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import ParseDiagnostic
from gruffpy.parser.python_parser import PythonFileParser
from gruffpy.rule.complexity._halstead import halstead_for
from gruffpy.rule.complexity._walks import FunctionLike, iter_functions
from gruffpy.rule.complexity.cyclomatic_complexity_rule import (
    CyclomaticComplexityRule,
    cyclomatic_for,
)
from gruffpy.rule.registry import RuleRegistry
from gruffpy.rule.size._lines import code_line_numbers, lines_for_size, parent_chain, qualified_symbol
from gruffpy.source.discovery import SourceDiscovery, SourceDiscoveryResult
from gruffpy.source.source_file import SourceFile
from gruffpy.version import TOOL_NAME, VERSION

MetricName = Literal["cyclomatic", "halsteadVolume", "maintainabilityIndex"]
ThresholdDirection = Literal["above", "below"]

METRIC_ORDER: tuple[MetricName, ...] = (
    "cyclomatic",
    "halsteadVolume",
    "maintainabilityIndex",
)


@dataclass(frozen=True, slots=True)
class MetricDiagnostic:
    """Non-finding run-time message from ``metric-calibration``.

    Attributes:
        type: Diagnostic category such as parse error or missing path.
        message: Human-readable diagnostic text.
        path: Optional path associated with the diagnostic.
        line: Optional one-based source line.
    """

    type: str
    message: str
    path: str | None = None
    line: int | None = None

    def to_payload(self) -> dict[str, object]:
        """Serialise the diagnostic.

        Returns:
            JSON-ready diagnostic fields.
        """
        payload: dict[str, object] = {
            "type": self.type,
            "message": self.message,
        }
        if self.path is not None:
            payload["path"] = self.path
        if self.line is not None:
            payload["line"] = self.line
        return payload


@dataclass(frozen=True, slots=True)
class MetricThreshold:
    """Threshold + severity + direction used to count crossings for one metric.

    Attributes:
        threshold: Numeric threshold value.
        severity: Severity assigned when the threshold is crossed.
        direction: Whether high or low values cross the threshold.
    """

    threshold: float
    severity: Severity
    direction: ThresholdDirection


@dataclass(frozen=True, slots=True)
class FunctionMetricRow:
    """One parsed function's location and complexity metric snapshot.

    Attributes:
        file_path: Display path containing the function.
        line: One-based start line.
        end_line: Optional one-based end line.
        symbol: Qualified function symbol.
        cyclomatic: Cyclomatic complexity value.
        halstead_volume: Halstead volume value.
        maintainability_index: Maintainability index value.
    """

    file_path: str
    line: int
    end_line: int | None
    symbol: str
    cyclomatic: int
    halstead_volume: float
    maintainability_index: float

    def value_for(self, metric: MetricName) -> float:
        """Return one metric value for this row.

        Args:
            metric: Metric name to read.

        Returns:
            Numeric value for the requested metric.
        """
        match metric:
            case "cyclomatic":
                return float(self.cyclomatic)
            case "halsteadVolume":
                return self.halstead_volume
            case "maintainabilityIndex":
                return self.maintainability_index

    def to_payload(self, metric: MetricName) -> dict[str, object]:
        """Serialise the row for a primary metric.

        Args:
            metric: Metric that should appear as the row's top-level value.

        Returns:
            JSON-ready row payload.
        """
        return {
            "filePath": self.file_path,
            "line": self.line,
            "endLine": self.end_line,
            "symbol": self.symbol,
            "value": _rounded(self.value_for(metric)),
            "metrics": {
                "cyclomatic": self.cyclomatic,
                "halsteadVolume": _rounded(self.halstead_volume),
                "maintainabilityIndex": _rounded(self.maintainability_index),
            },
        }


@dataclass(frozen=True, slots=True)
class MetricSummary:
    """Distribution summary for one metric.

    Attributes:
        metric: Metric name this summary describes.
        count: Number of values in the distribution.
        minimum: Minimum observed value.
        p50: Median observed value.
        p90: 90th percentile observed value.
        p99: 99th percentile observed value.
        maximum: Maximum observed value.
        threshold: Threshold used for crossing counts.
        threshold_severity: Severity assigned to threshold crossings.
        threshold_direction: Whether values above or below the threshold cross.
        threshold_crossings: Number of rows crossing the threshold.
    """

    metric: MetricName
    count: int
    minimum: float | None
    p50: float | None
    p90: float | None
    p99: float | None
    maximum: float | None
    threshold: float
    threshold_severity: Severity
    threshold_direction: ThresholdDirection
    threshold_crossings: int

    def to_payload(self) -> dict[str, object]:
        """Serialise this metric summary.

        Returns:
            JSON-ready summary payload.
        """
        return {
            "name": self.metric,
            "count": self.count,
            "min": _rounded_optional(self.minimum),
            "p50": _rounded_optional(self.p50),
            "p90": _rounded_optional(self.p90),
            "p99": _rounded_optional(self.p99),
            "max": _rounded_optional(self.maximum),
            "thresholdDirection": self.threshold_direction,
            "threshold": _rounded(self.threshold),
            "thresholdSeverity": self.threshold_severity.value,
            "thresholdCrossings": self.threshold_crossings,
        }


@dataclass(frozen=True, slots=True)
class MetricCalibrationReport:
    """Full output of ``metric-calibration``.

    Attributes:
        requested_paths: User-requested input paths.
        files_discovered: Count of discovered source files.
        files_parsed: Count of files parsed for metric rows.
        ignored_paths: Paths skipped by discovery.
        missing_paths: Requested paths that were not found.
        diagnostics: Non-finding diagnostics collected during the run.
        rows: Per-function metric rows.
        summaries: Per-metric distribution summaries.
        config_path: Loaded configuration path, if any.
        tool_version: gruff-py version that produced the report.
    """

    requested_paths: tuple[str, ...]
    files_discovered: int
    files_parsed: int
    ignored_paths: tuple[str, ...]
    missing_paths: tuple[str, ...]
    diagnostics: tuple[MetricDiagnostic, ...]
    rows: tuple[FunctionMetricRow, ...]
    summaries: tuple[MetricSummary, ...]
    config_path: str | None
    tool_version: str = VERSION

    @property
    def function_count(self) -> int:
        """Count parsed function rows.

        Returns:
            Number of parsed functions with metric rows.
        """
        return len(self.rows)

    def parse_error_count(self) -> int:
        """Count parse-error diagnostics.

        Returns:
            Number of parse errors collected during parsing.
        """
        return sum(1 for diagnostic in self.diagnostics if diagnostic.type == "parse-error")

    def has_input_errors(self) -> bool:
        """Return whether the report contains input-level errors.

        Returns:
            True when missing paths or diagnostics are present.
        """
        return bool(self.missing_paths or self.diagnostics)


def build_metric_calibration_report(
    *,
    paths: tuple[str, ...],
    config_path: Path | None,
    no_config: bool,
    include_ignored: bool,
    project_root: Path,
) -> MetricCalibrationReport:
    """Build metric distributions using the same discovery as analysis.

    Args:
        paths: Paths requested by the user.
        config_path: Explicit configuration path, if one was provided.
        no_config: Whether default configuration loading should be skipped.
        include_ignored: Whether discovery should include normally ignored files.
        project_root: Root directory used to resolve relative paths.

    Returns:
        Complete calibration report with rows, summaries, and diagnostics.
    """
    config, config_loaded_from, diagnostics = _load_metric_config(
        project_root=project_root,
        config_path=config_path,
        no_config=no_config,
    )
    discovery_result = _discover_metric_sources(
        paths=paths,
        include_ignored=include_ignored,
        project_root=project_root,
        config=config,
    )
    diagnostics.extend(_missing_path_diagnostics(discovery_result.missing_paths))

    files_parsed, rows, parse_diagnostics = _collect_metric_rows(discovery_result.files)
    diagnostics.extend(parse_diagnostics)

    thresholds = _metric_thresholds(config)
    summaries = tuple(_summary_for(metric, rows, thresholds[metric]) for metric in METRIC_ORDER)
    return MetricCalibrationReport(
        requested_paths=tuple(paths) if paths else (".",),
        files_discovered=len(discovery_result.files),
        files_parsed=files_parsed,
        ignored_paths=discovery_result.ignored_paths,
        missing_paths=discovery_result.missing_paths,
        diagnostics=tuple(diagnostics),
        rows=tuple(rows),
        summaries=summaries,
        config_path=config_loaded_from,
    )


def metric_calibration_payload(
    report: MetricCalibrationReport,
    *,
    top: int,
) -> dict[str, object]:
    """Build the JSON calibration payload.

    Args:
        report: Metric calibration report to serialise.
        top: Number of top rows to include per metric.

    Returns:
        JSON-ready calibration payload.
    """
    return {
        "schemaVersion": "gruff-py.metric-calibration.v1",
        "tool": {
            "name": TOOL_NAME,
            "version": report.tool_version,
        },
        "run": {
            "requestedPaths": list(report.requested_paths),
            "configPath": report.config_path,
            "filesDiscovered": report.files_discovered,
            "filesParsed": report.files_parsed,
            "ignored": len(report.ignored_paths),
            "missing": len(report.missing_paths),
            "parseErrors": report.parse_error_count(),
            "functions": report.function_count,
        },
        "metrics": [summary.to_payload() for summary in report.summaries],
        "top": {metric: [row.to_payload(metric) for row in top_rows(report, metric, top)] for metric in METRIC_ORDER},
        "diagnostics": [diagnostic.to_payload() for diagnostic in report.diagnostics],
    }


def render_metric_calibration_text(report: MetricCalibrationReport, *, top: int) -> str:
    """Render a text calibration report.

    Args:
        report: Metric calibration report to render.
        top: Number of top rows to include per metric.

    Returns:
        Human-readable calibration report.
    """
    lines = [
        f"{TOOL_NAME} {report.tool_version} metric calibration",
        (
            f"Files: {report.files_discovered} discovered, {report.files_parsed} parsed, "
            f"{len(report.ignored_paths)} ignored, {len(report.missing_paths)} missing, "
            f"{report.parse_error_count()} parse errors"
        ),
        f"Functions: {report.function_count}",
    ]
    if report.config_path is not None:
        lines.append(f"Config: {report.config_path}")

    _append_diagnostics(lines, report.diagnostics)
    _append_distribution(lines, report.summaries)
    _append_top_rows(lines, report, top)
    return "\n".join(lines) + "\n"


def top_rows(
    report: MetricCalibrationReport,
    metric: MetricName,
    top: int,
) -> tuple[FunctionMetricRow, ...]:
    """Select rows with the most noteworthy values for one metric.

    Args:
        report: Metric calibration report containing all rows.
        metric: Metric to sort by.
        top: Maximum number of rows to return.

    Returns:
        Ordered rows for the requested metric.
    """
    threshold = _threshold_for_metric(report.summaries, metric)
    if threshold == "above":
        ordered = sorted(
            report.rows,
            key=lambda row: (-row.value_for(metric), row.file_path, row.line),
        )
    else:
        ordered = sorted(
            report.rows,
            key=lambda row: (row.value_for(metric), row.file_path, row.line),
        )
    return tuple(ordered[:top])


def _load_metric_config(
    *,
    project_root: Path,
    config_path: Path | None,
    no_config: bool,
) -> tuple[AnalysisConfig, str | None, list[MetricDiagnostic]]:
    """Resolve the analysis config for a calibration run, turning a config conflict or ConfigError into a diagnostic.

    A ValueError from the loader, such as a minimum Python version below 3.11, is not caught and aborts the run.

    Args:
        project_root: Project root the config loader searches when no explicit path is given.
        config_path: Explicit config file to load; None lets the loader discover project config under project_root.
        no_config: When true, skip config loading and use the registry defaults; combining it with config_path is reported as a config-error
            diagnostic.

    Returns:
        Tuple of the config to use, the path of the config file the loader read as a string (None when the loader found no config file, no_config was
        set, or loading failed), and a list holding one config-error diagnostic when no_config conflicts with config_path or the loader raised
        ConfigError, otherwise empty. On either config error the registry defaults are returned.
    """
    registry = RuleRegistry.defaults()
    config = AnalysisConfig.from_registry(registry)
    if no_config and config_path is not None:
        return (
            config,
            None,
            [
                MetricDiagnostic(
                    type="config-error",
                    message="--no-config cannot be combined with an explicit --config path.",
                )
            ],
        )
    if no_config:
        return config, None, []

    loader = ConfigLoader(project_root, config)
    try:
        loaded_config, source = loader.load(config_path)
    except ConfigError as exc:
        return config, None, [MetricDiagnostic(type="config-error", message=str(exc))]
    return loaded_config, str(source) if source is not None else None, []


def _discover_metric_sources(
    *,
    paths: tuple[str, ...],
    include_ignored: bool,
    project_root: Path,
    config: AnalysisConfig,
) -> SourceDiscoveryResult:
    """Run the same source discovery that analysis uses, honouring the config's ignored path patterns.

    Args:
        paths: Paths requested by the user; relative paths are anchored at project_root, absolute paths are used as given, and an empty tuple makes
            discovery scan the project root.
        include_ignored: When true, discovery also returns files under default and gitignored paths.
        project_root: Root directory discovery resolves the requested paths against.
        config: Analysis config whose ignored path patterns are passed to discovery.

    Returns:
        Discovery result with the discovered source files, the ignored paths, and the requested paths that were not found.
    """
    discovery = SourceDiscovery(project_root)
    return discovery.discover(
        list(paths),
        include_ignored=include_ignored,
        configured_ignore_patterns=config.ignored_path_patterns,
    )


def _missing_path_diagnostics(missing_paths: Sequence[str]) -> list[MetricDiagnostic]:
    """Turn each requested path that discovery could not find into a missing-path diagnostic.

    Args:
        missing_paths: Requested paths reported missing by discovery.

    Returns:
        One missing-path diagnostic per missing path, with the message path not found and the path attached; empty when nothing is missing.
    """
    return [MetricDiagnostic(type="missing-path", message="path not found", path=missing) for missing in missing_paths]


def _collect_metric_rows(
    files: Sequence[SourceFile],
) -> tuple[int, list[FunctionMetricRow], list[MetricDiagnostic]]:
    """Parse each discovered file and measure every function-like node in it into a metric row.

    A file with parse errors contributes parse-error diagnostics, no rows, and is not counted as parsed.

    Args:
        files: Discovered source files to parse and measure.

    Returns:
        Tuple of the number of files parsed without errors, the metric rows for all their function-like nodes, and the parse-error diagnostics from
        files that failed to parse.
    """
    parser = PythonFileParser()
    files_parsed = 0
    rows: list[FunctionMetricRow] = []
    diagnostics: list[MetricDiagnostic] = []
    for source_file in files:
        unit = parser.parse(source_file)
        if unit.has_parse_errors():
            diagnostics.extend(_parse_error_diagnostics(source_file, unit.diagnostics))
            continue
        files_parsed += 1
        if unit.tree is not None:
            code_lines = code_line_numbers(unit.source, unit.tree)
            rows.extend(_metric_row(source_file.display_path, fn, code_lines) for fn in iter_functions(unit.tree))
    return files_parsed, rows, diagnostics


def _parse_error_diagnostics(
    source_file: SourceFile,
    diagnostics: Sequence[ParseDiagnostic],
) -> list[MetricDiagnostic]:
    """Convert one file's parser diagnostics into parse-error diagnostics tagged with the file's display path.

    Args:
        source_file: File that failed to parse; its display path is attached to every diagnostic.
        diagnostics: Parser diagnostics whose message and line are copied.

    Returns:
        One parse-error diagnostic per parser diagnostic, in the same order.
    """
    return [
        MetricDiagnostic(
            type="parse-error",
            message=diagnostic.message,
            path=source_file.display_path,
            line=diagnostic.line,
        )
        for diagnostic in diagnostics
    ]


def _append_diagnostics(lines: list[str], diagnostics: Sequence[MetricDiagnostic]) -> None:
    """Add the Diagnostics section to the text report, one indented line per diagnostic with its type, location and message.

    Args:
        lines: Text report lines, mutated in place by appending a blank line, the section heading and the diagnostic lines.
        diagnostics: Diagnostics to list; when empty, nothing is appended.
    """
    if not diagnostics:
        return
    lines.extend(["", "Diagnostics:"])
    for diagnostic in diagnostics:
        lines.append(f"  {diagnostic.type}{_diagnostic_location(diagnostic)}: {diagnostic.message}")


def _diagnostic_location(diagnostic: MetricDiagnostic) -> str:
    """Format the location part of a text diagnostic line from its optional path and line.

    Args:
        diagnostic: Diagnostic whose path and line are formatted.

    Returns:
        Empty string when the diagnostic has no path, a space and the path when it has no line, otherwise a space followed by path:line.
    """
    if diagnostic.path is None:
        return ""
    if diagnostic.line is None:
        return f" {diagnostic.path}"
    return f" {diagnostic.path}:{diagnostic.line}"


def _append_distribution(lines: list[str], summaries: Sequence[MetricSummary]) -> None:
    """Add the Metric distributions section to the text report, with a column header row and one line per metric summary.

    Args:
        lines: Text report lines, mutated in place by appending a blank line, the section heading, the header row and the summary lines.
        summaries: Metric summaries to render, in report order.
    """
    lines.extend(
        [
            "",
            "Metric distributions:",
            (f"  {'metric':<24} {'min':>8} {'p50':>8} {'p90':>8} {'p99':>8} {'max':>8} {'threshold':>18}"),
        ]
    )
    lines.extend(_summary_line(summary) for summary in summaries)


def _summary_line(summary: MetricSummary) -> str:
    """Format one metric summary as a text row aligned under the distribution header columns.

    Args:
        summary: Metric summary to render; absent statistics are shown as a dash.

    Returns:
        Indented row with the metric name, min, p50, p90, p99 and max, followed by the threshold crossing label.
    """
    threshold = _crossing_label(
        summary.threshold_direction,
        summary.threshold,
        summary.threshold_crossings,
        summary.threshold_severity,
    )
    return (
        f"  {summary.metric:<24} {_format_optional(summary.minimum):>8} "
        f"{_format_optional(summary.p50):>8} {_format_optional(summary.p90):>8} "
        f"{_format_optional(summary.p99):>8} {_format_optional(summary.maximum):>8} "
        f"{threshold:>18}"
    )


def _append_top_rows(lines: list[str], report: MetricCalibrationReport, top: int) -> None:
    """Add a Top section for each metric to the text report, listing the rows that top_rows selects for that metric.

    Rows are listed highest value first for a metric whose crossings are above its threshold and lowest value first for one whose crossings are below,
    with ties ordered by path and line. A metric with no rows to list gets a single none line.

    Args:
        lines: Text report lines, mutated in place by appending a blank line, a Top heading and the row lines for each metric.
        report: Calibration report supplying the rows and the summaries that set each metric's sort direction.
        top: Maximum number of rows listed per metric.
    """
    for metric in METRIC_ORDER:
        rows = top_rows(report, metric, top)
        lines.extend(["", f"Top {metric}:"])
        if not rows:
            lines.append("  none")
            continue
        lines.extend(_top_row_line(row, metric) for row in rows)


def _top_row_line(row: FunctionMetricRow, metric: MetricName) -> str:
    """Format one top row as its path:line location, symbol and metric value for the text report.

    Args:
        row: Metric row to render.
        metric: Metric whose name and value are shown as metric=value.

    Returns:
        Indented text line for the row.
    """
    return f"  {row.file_path}:{row.line} {row.symbol} {metric}={_format_number(row.value_for(metric))}"


def _metric_row(file_path: str, fn: FunctionLike, code_lines: frozenset[int]) -> FunctionMetricRow:
    """Measure one function-like node into a metric row.

    The row carries the node's location, qualified symbol, cyclomatic complexity, Halstead volume and maintainability index.

    Args:
        file_path: Display path of the file containing the node, recorded on the row.
        fn: Function-like node to measure.
        code_lines: The file's code line numbers, used for the maintainability index line term.

    Returns:
        Metric row for the node.
    """
    halstead = halstead_for(fn)
    return FunctionMetricRow(
        file_path=file_path,
        line=fn.lineno,
        end_line=fn.end_lineno,
        symbol=qualified_symbol(fn, parent_chain(fn)),
        cyclomatic=cyclomatic_for(fn),
        halstead_volume=halstead.volume,
        maintainability_index=_maintainability_index_for(fn, code_lines),
    )


def _maintainability_index_for(fn: FunctionLike, code_lines: frozenset[int]) -> float:
    """Compute maintainability index for a function-like node.

    Uses the shared `lines_for_size()` helper for LOC, so the line term counts
    code lines only and documenting a function never lowers its index.

    Args:
        fn: Function, async function, or lambda node to score.
        code_lines: The file's code lines, from ``code_line_numbers``.

    Returns:
        Maintainability index clamped to the range 0 through 100.
    """
    hv = halstead_for(fn).volume
    cc = cyclomatic_for(fn)
    loc = lines_for_size(fn, code_lines) if fn.end_lineno is not None else 1
    # Guard against ln(0): treat zero terms as 1.
    log_hv = math.log(hv) if hv > 0 else 0.0
    log_loc = math.log(loc) if loc > 0 else 0.0
    raw = 171 - 5.2 * log_hv - 0.23 * cc - 16.2 * log_loc
    return max(0.0, min(100.0, raw))


def _metric_thresholds(config: AnalysisConfig) -> dict[MetricName, MetricThreshold]:
    """Choose the threshold, severity and direction used to count crossings for each calibrated metric.

    Only the cyclomatic threshold reads the config: it comes from the cyclomatic complexity rule settings, falls back to warning severity when the
    rule has no configured severity threshold, and counts values above it. The Halstead volume threshold is fixed at 400 with error severity and
    counts values above it, and the maintainability index threshold is fixed at 70 with error severity and counts values below it, regardless of
    config.

    Args:
        config: Analysis config supplying the cyclomatic complexity rule settings.

    Returns:
        Mapping from every metric name to its crossing threshold.
    """
    return {
        "cyclomatic": _threshold(config, CyclomaticComplexityRule.ID, Severity.WARNING, "above"),
        "halsteadVolume": MetricThreshold(400.0, Severity.ERROR, "above"),
        "maintainabilityIndex": MetricThreshold(70.0, Severity.ERROR, "below"),
    }


def _threshold(
    config: AnalysisConfig,
    rule_id: str,
    default_severity: Severity,
    direction: ThresholdDirection,
) -> MetricThreshold:
    """Build a metric's crossing threshold from a rule's configured threshold and severity.

    Args:
        config: Analysis config holding the rule settings.
        rule_id: Rule whose settings supply the threshold.
        default_severity: Severity used when the rule has no configured severity threshold.
        direction: Whether values above or below the threshold count as crossings.

    Returns:
        Crossing threshold with the rule's active threshold value as a float, its severity, and the given direction.
    """
    settings = config.rule_settings(rule_id)
    active = _active_threshold(settings, default_severity)
    return MetricThreshold(
        threshold=float(active.threshold),
        severity=active.severity,
        direction=direction,
    )


def _summary_for(
    metric: MetricName,
    rows: Sequence[FunctionMetricRow],
    threshold: MetricThreshold,
) -> MetricSummary:
    """Summarise one metric's distribution across all rows, including how many rows cross its threshold.

    Args:
        metric: Metric to summarise.
        rows: Metric rows whose values for the metric form the distribution.
        threshold: Crossing threshold whose value, severity and direction are copied into the summary and used to count crossings.

    Returns:
        Summary with count, min, p50, p90, p99, max and crossing count; when there are no rows, count and crossings are 0 and every statistic is None.
    """
    values = [row.value_for(metric) for row in rows]
    if not values:
        return MetricSummary(
            metric=metric,
            count=0,
            minimum=None,
            p50=None,
            p90=None,
            p99=None,
            maximum=None,
            threshold=threshold.threshold,
            threshold_severity=threshold.severity,
            threshold_direction=threshold.direction,
            threshold_crossings=0,
        )

    sorted_values = sorted(values)
    return MetricSummary(
        metric=metric,
        count=len(values),
        minimum=sorted_values[0],
        p50=_percentile(sorted_values, 50),
        p90=_percentile(sorted_values, 90),
        p99=_percentile(sorted_values, 99),
        maximum=sorted_values[-1],
        threshold=threshold.threshold,
        threshold_severity=threshold.severity,
        threshold_direction=threshold.direction,
        threshold_crossings=_crossings(values, threshold.threshold, threshold.direction),
    )


def _threshold_for_metric(
    summaries: Sequence[MetricSummary],
    metric: MetricName,
) -> ThresholdDirection:
    """Look up which direction counts as a crossing for a metric, so top rows can be sorted with the most noteworthy values first.

    Args:
        summaries: Metric summaries to search.
        metric: Metric whose summary is wanted.

    Returns:
        The threshold direction of the first summary for the metric, above or below.

    Raises:
        LookupError: No summary describes the metric.
    """
    for summary in summaries:
        if summary.metric == metric:
            return summary.threshold_direction
    raise LookupError(f"Unknown metric {metric!r}.")


def _percentile(sorted_values: Sequence[float], percentile: int) -> float:
    """Compute a percentile by linear interpolation between the two nearest ranks of an ascending sequence.

    Args:
        sorted_values: Values sorted in ascending order.
        percentile: Percentile to compute, from 0 to 100.

    Returns:
        The interpolated percentile value; the only value when the sequence has one element.

    Raises:
        ValueError: sorted_values is empty.
    """
    if not sorted_values:
        raise ValueError("percentile requires at least one value")
    if len(sorted_values) == 1:
        return sorted_values[0]
    rank = (len(sorted_values) - 1) * (percentile / 100)
    lower = math.floor(rank)
    upper = math.ceil(rank)
    if lower == upper:
        return sorted_values[lower]
    lower_value = sorted_values[lower]
    upper_value = sorted_values[upper]
    return lower_value + (upper_value - lower_value) * (rank - lower)


def _crossings(
    values: Sequence[float],
    threshold: float,
    direction: ThresholdDirection,
) -> int:
    """Count how many metric values cross a threshold in the given direction.

    Args:
        values: Metric values to test.
        threshold: Threshold value; a value equal to it does not count as a crossing.
        direction: above counts values strictly greater than the threshold; below counts values strictly less.

    Returns:
        Number of values that cross the threshold.
    """
    if direction == "above":
        return sum(1 for value in values if value > threshold)
    return sum(1 for value in values if value < threshold)


def _active_threshold(settings: RuleSettings, default_severity: Severity) -> SeverityThreshold:
    """Pick the rule's configured severity threshold, or fall back to its warning threshold paired with the default severity.

    Args:
        settings: Rule settings to read.
        default_severity: Severity paired with the warning threshold when the settings carry no severity threshold.

    Returns:
        The configured severity threshold when present, otherwise a severity threshold built from the warning threshold value and default_severity.
    """
    if settings.severity_threshold is not None:
        return settings.severity_threshold
    return SeverityThreshold(
        threshold=settings.numeric_threshold("warning"),
        severity=default_severity,
    )


def _crossing_label(
    direction: ThresholdDirection,
    threshold: float,
    count: int,
    severity: Severity,
) -> str:
    """Format the threshold column of a distribution row from the direction, threshold, severity and crossing count.

    Args:
        direction: above renders the > operator; below renders <.
        threshold: Threshold value shown after the operator.
        count: Number of rows crossing the threshold.
        severity: Severity assigned to crossings, shown by its value.

    Returns:
        The operator and threshold, a space, then the severity value and crossing count joined by a colon.
    """
    operator = ">" if direction == "above" else "<"
    return f"{operator}{_format_number(threshold)} {severity.value}:{count}"


def _format_optional(value: float | None) -> str:
    """Format an optional distribution statistic for the text report.

    Args:
        value: Statistic to format; None means the distribution was empty.

    Returns:
        A dash for None, otherwise the number formatted for text output.
    """
    if value is None:
        return "-"
    return _format_number(value)


def _format_number(value: float) -> str:
    """Format a metric number for the text report.

    Args:
        value: Number to format.

    Returns:
        The integer digits for a whole number, otherwise the value with one decimal place.
    """
    if value.is_integer():
        return str(int(value))
    return f"{value:.1f}"


def _rounded(value: float) -> int | float:
    """Normalise a metric number for the JSON payload.

    Args:
        value: Number to normalise.

    Returns:
        An int for a whole number, otherwise the value rounded to two decimal places.
    """
    if value.is_integer():
        return int(value)
    return round(value, 2)


def _rounded_optional(value: float | None) -> int | float | None:
    """Normalise an optional distribution statistic for the JSON payload.

    Args:
        value: Statistic to normalise; None means the distribution was empty.

    Returns:
        None when value is None, so the payload carries null, otherwise the rounded number.
    """
    if value is None:
        return None
    return _rounded(value)
