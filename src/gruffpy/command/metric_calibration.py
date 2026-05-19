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
from gruffpy.rule.complexity.halstead_volume_rule import HalsteadVolumeRule
from gruffpy.rule.complexity.maintainability_index_rule import (
    MaintainabilityIndexRule,
    maintainability_index_for,
)
from gruffpy.rule.complexity.npath_complexity_rule import (
    _NPATH_CAP,
    NPathComplexityRule,
    npath_for,
)
from gruffpy.rule.registry import RuleRegistry
from gruffpy.rule.size._lines import parent_chain, qualified_symbol
from gruffpy.source.discovery import SourceDiscovery, SourceDiscoveryResult
from gruffpy.source.source_file import SourceFile
from gruffpy.version import TOOL_NAME, VERSION

MetricName = Literal["cyclomatic", "npath", "halsteadVolume", "maintainabilityIndex"]
ThresholdDirection = Literal["above", "below"]

METRIC_ORDER: tuple[MetricName, ...] = (
    "cyclomatic",
    "npath",
    "halsteadVolume",
    "maintainabilityIndex",
)


@dataclass(frozen=True, slots=True)
class MetricDiagnostic:
    """Non-finding run-time message from ``metric-calibration`` (parse error, missing path)."""

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
    """Threshold + severity + direction (high/low) used to count crossings for one metric."""

    threshold: float
    severity: Severity
    direction: ThresholdDirection


@dataclass(frozen=True, slots=True)
class FunctionMetricRow:
    """One parsed function's metric snapshot: location plus cyclomatic, npath, Halstead, and MI."""

    file_path: str
    line: int
    end_line: int | None
    symbol: str
    cyclomatic: int
    npath: int
    is_npath_capped: bool
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
            case "npath":
                return float(self.npath)
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
                "npath": self.npath,
                "npathCapped": self.is_npath_capped,
                "halsteadVolume": _rounded(self.halstead_volume),
                "maintainabilityIndex": _rounded(self.maintainability_index),
            },
        }


@dataclass(frozen=True, slots=True)
class MetricSummary:
    """Distribution summary for one metric: count, min/p50/p90/p99/max, threshold-crossing total."""

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
    """Full output of ``metric-calibration``: rows, summaries, diagnostics, and run metadata."""

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
        "top": {
            metric: [row.to_payload(metric) for row in top_rows(report, metric, top)]
            for metric in METRIC_ORDER
        },
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
    registry = RuleRegistry.defaults()
    config = AnalysisConfig.from_registry(registry)
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
    discovery = SourceDiscovery(project_root)
    return discovery.discover(
        list(paths),
        include_ignored=include_ignored,
        configured_ignore_patterns=config.ignored_path_patterns,
    )


def _missing_path_diagnostics(missing_paths: Sequence[str]) -> list[MetricDiagnostic]:
    return [
        MetricDiagnostic(type="missing-path", message="path not found", path=missing)
        for missing in missing_paths
    ]


def _collect_metric_rows(
    files: Sequence[SourceFile],
) -> tuple[int, list[FunctionMetricRow], list[MetricDiagnostic]]:
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
            rows.extend(
                _metric_row(source_file.display_path, fn) for fn in iter_functions(unit.tree)
            )
    return files_parsed, rows, diagnostics


def _parse_error_diagnostics(
    source_file: SourceFile,
    diagnostics: Sequence[ParseDiagnostic],
) -> list[MetricDiagnostic]:
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
    if not diagnostics:
        return
    lines.extend(["", "Diagnostics:"])
    for diagnostic in diagnostics:
        lines.append(f"  {diagnostic.type}{_diagnostic_location(diagnostic)}: {diagnostic.message}")


def _diagnostic_location(diagnostic: MetricDiagnostic) -> str:
    if diagnostic.path is None:
        return ""
    if diagnostic.line is None:
        return f" {diagnostic.path}"
    return f" {diagnostic.path}:{diagnostic.line}"


def _append_distribution(lines: list[str], summaries: Sequence[MetricSummary]) -> None:
    lines.extend(
        [
            "",
            "Metric distributions:",
            (
                f"  {'metric':<24} {'min':>8} {'p50':>8} {'p90':>8} {'p99':>8} "
                f"{'max':>8} {'threshold':>18}"
            ),
        ]
    )
    lines.extend(_summary_line(summary) for summary in summaries)


def _summary_line(summary: MetricSummary) -> str:
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
    for metric in METRIC_ORDER:
        rows = top_rows(report, metric, top)
        lines.extend(["", f"Top {metric}:"])
        if not rows:
            lines.append("  none")
            continue
        lines.extend(_top_row_line(row, metric) for row in rows)


def _top_row_line(row: FunctionMetricRow, metric: MetricName) -> str:
    return (
        f"  {row.file_path}:{row.line} {row.symbol} "
        f"{metric}={_format_number(row.value_for(metric))}"
    )


def _metric_row(file_path: str, fn: FunctionLike) -> FunctionMetricRow:
    halstead = halstead_for(fn)
    npath_raw = npath_for(fn)
    npath_capped = min(npath_raw, _NPATH_CAP)
    return FunctionMetricRow(
        file_path=file_path,
        line=fn.lineno,
        end_line=fn.end_lineno,
        symbol=qualified_symbol(fn, parent_chain(fn)),
        cyclomatic=cyclomatic_for(fn),
        npath=npath_capped,
        is_npath_capped=npath_raw >= _NPATH_CAP,
        halstead_volume=halstead.volume,
        maintainability_index=maintainability_index_for(fn),
    )


def _metric_thresholds(config: AnalysisConfig) -> dict[MetricName, MetricThreshold]:
    return {
        "cyclomatic": _threshold(config, CyclomaticComplexityRule.ID, Severity.WARNING, "above"),
        "npath": _threshold(config, NPathComplexityRule.ID, Severity.WARNING, "above"),
        "halsteadVolume": _threshold(config, HalsteadVolumeRule.ID, Severity.WARNING, "above"),
        "maintainabilityIndex": _threshold(
            config, MaintainabilityIndexRule.ID, Severity.WARNING, "below"
        ),
    }


def _threshold(
    config: AnalysisConfig,
    rule_id: str,
    default_severity: Severity,
    direction: ThresholdDirection,
) -> MetricThreshold:
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
    for summary in summaries:
        if summary.metric == metric:
            return summary.threshold_direction
    raise LookupError(f"Unknown metric {metric!r}.")


def _percentile(sorted_values: Sequence[float], percentile: int) -> float:
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
    if direction == "above":
        return sum(1 for value in values if value > threshold)
    return sum(1 for value in values if value < threshold)


def _active_threshold(settings: RuleSettings, default_severity: Severity) -> SeverityThreshold:
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
    operator = ">" if direction == "above" else "<"
    return f"{operator}{_format_number(threshold)} {severity.value}:{count}"


def _format_optional(value: float | None) -> str:
    if value is None:
        return "-"
    return _format_number(value)


def _format_number(value: float) -> str:
    if value.is_integer():
        return str(int(value))
    return f"{value:.1f}"


def _rounded(value: float) -> int | float:
    if value.is_integer():
        return int(value)
    return round(value, 2)


def _rounded_optional(value: float | None) -> int | float | None:
    if value is None:
        return None
    return _rounded(value)
