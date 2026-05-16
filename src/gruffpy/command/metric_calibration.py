"""Developer-only metric distribution dump for threshold calibration."""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.exceptions import ConfigError
from gruffpy.config.loader import ConfigLoader
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
from gruffpy.source.discovery import SourceDiscovery
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
    type: str
    message: str
    path: str | None = None
    line: int | None = None

    def to_payload(self) -> dict[str, object]:
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
    warning: float
    error: float
    direction: ThresholdDirection


@dataclass(frozen=True, slots=True)
class FunctionMetricRow:
    file_path: str
    line: int
    end_line: int | None
    symbol: str
    cyclomatic: int
    npath: int
    npath_capped: bool
    halstead_volume: float
    maintainability_index: float

    def value_for(self, metric: MetricName) -> float:
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
        return {
            "filePath": self.file_path,
            "line": self.line,
            "endLine": self.end_line,
            "symbol": self.symbol,
            "value": _rounded(self.value_for(metric)),
            "metrics": {
                "cyclomatic": self.cyclomatic,
                "npath": self.npath,
                "npathCapped": self.npath_capped,
                "halsteadVolume": _rounded(self.halstead_volume),
                "maintainabilityIndex": _rounded(self.maintainability_index),
            },
        }


@dataclass(frozen=True, slots=True)
class MetricSummary:
    metric: MetricName
    count: int
    minimum: float | None
    p50: float | None
    p90: float | None
    maximum: float | None
    warning_threshold: float
    error_threshold: float
    threshold_direction: ThresholdDirection
    warning_crossings: int
    error_crossings: int

    def to_payload(self) -> dict[str, object]:
        return {
            "name": self.metric,
            "count": self.count,
            "min": _rounded_optional(self.minimum),
            "p50": _rounded_optional(self.p50),
            "p90": _rounded_optional(self.p90),
            "max": _rounded_optional(self.maximum),
            "thresholdDirection": self.threshold_direction,
            "warningThreshold": _rounded(self.warning_threshold),
            "errorThreshold": _rounded(self.error_threshold),
            "warningCrossings": self.warning_crossings,
            "errorCrossings": self.error_crossings,
        }


@dataclass(frozen=True, slots=True)
class MetricCalibrationReport:
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
        return len(self.rows)

    def parse_error_count(self) -> int:
        return sum(1 for diagnostic in self.diagnostics if diagnostic.type == "parse-error")

    def has_input_errors(self) -> bool:
        return bool(self.missing_paths or self.diagnostics)


def build_metric_calibration_report(
    *,
    paths: tuple[str, ...],
    config_path: Path | None,
    no_config: bool,
    include_ignored: bool,
    project_root: Path,
) -> MetricCalibrationReport:
    """Build metric distributions using the same source discovery as analysis."""
    registry = RuleRegistry.defaults()
    config = AnalysisConfig.from_registry(registry)
    diagnostics: list[MetricDiagnostic] = []
    config_loaded_from: str | None = None

    if not no_config:
        loader = ConfigLoader(project_root, config)
        try:
            config, source = loader.load(config_path)
            if source is not None:
                config_loaded_from = str(source)
        except ConfigError as exc:
            diagnostics.append(MetricDiagnostic(type="config-error", message=str(exc)))

    discovery = SourceDiscovery(project_root)
    discovery_result = discovery.discover(
        list(paths),
        include_ignored=include_ignored,
        configured_ignore_patterns=config.ignored_path_patterns,
    )
    for missing in discovery_result.missing_paths:
        diagnostics.append(
            MetricDiagnostic(type="missing-path", message="path not found", path=missing)
        )

    parser = PythonFileParser()
    files_parsed = 0
    rows: list[FunctionMetricRow] = []
    for source_file in discovery_result.files:
        unit = parser.parse(source_file)
        if unit.has_parse_errors():
            for diagnostic in unit.diagnostics:
                diagnostics.append(
                    MetricDiagnostic(
                        type="parse-error",
                        message=diagnostic.message,
                        path=source_file.display_path,
                        line=diagnostic.line,
                    )
                )
            continue

        files_parsed += 1
        if unit.tree is None:
            continue

        for fn in iter_functions(unit.tree):
            rows.append(_metric_row(source_file.display_path, fn))

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

    if report.diagnostics:
        lines.extend(["", "Diagnostics:"])
        for diagnostic in report.diagnostics:
            location = ""
            if diagnostic.path is not None:
                location = f" {diagnostic.path}"
                if diagnostic.line is not None:
                    location = f"{location}:{diagnostic.line}"
            lines.append(f"  {diagnostic.type}{location}: {diagnostic.message}")

    lines.extend(
        [
            "",
            "Metric distributions:",
            (
                f"  {'metric':<24} {'min':>8} {'p50':>8} {'p90':>8} {'max':>8} "
                f"{'warning':>12} {'error':>12}"
            ),
        ]
    )
    for summary in report.summaries:
        warning = _crossing_label(
            summary.threshold_direction,
            summary.warning_threshold,
            summary.warning_crossings,
        )
        error = _crossing_label(
            summary.threshold_direction,
            summary.error_threshold,
            summary.error_crossings,
        )
        lines.append(
            f"  {summary.metric:<24} {_format_optional(summary.minimum):>8} "
            f"{_format_optional(summary.p50):>8} {_format_optional(summary.p90):>8} "
            f"{_format_optional(summary.maximum):>8} {warning:>12} {error:>12}"
        )

    for metric in METRIC_ORDER:
        rows = top_rows(report, metric, top)
        lines.extend(["", f"Top {metric}:"])
        if not rows:
            lines.append("  none")
            continue
        for row in rows:
            lines.append(
                f"  {row.file_path}:{row.line} {row.symbol} "
                f"{metric}={_format_number(row.value_for(metric))}"
            )

    return "\n".join(lines) + "\n"


def top_rows(
    report: MetricCalibrationReport,
    metric: MetricName,
    top: int,
) -> tuple[FunctionMetricRow, ...]:
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
        npath_capped=npath_raw >= _NPATH_CAP,
        halstead_volume=halstead.volume,
        maintainability_index=maintainability_index_for(fn),
    )


def _metric_thresholds(config: AnalysisConfig) -> dict[MetricName, MetricThreshold]:
    return {
        "cyclomatic": _threshold(config, CyclomaticComplexityRule.ID, "above"),
        "npath": _threshold(config, NPathComplexityRule.ID, "above"),
        "halsteadVolume": _threshold(config, HalsteadVolumeRule.ID, "above"),
        "maintainabilityIndex": _threshold(config, MaintainabilityIndexRule.ID, "below"),
    }


def _threshold(
    config: AnalysisConfig,
    rule_id: str,
    direction: ThresholdDirection,
) -> MetricThreshold:
    settings = config.rule_settings(rule_id)
    return MetricThreshold(
        warning=float(settings.numeric_threshold("warning")),
        error=float(settings.numeric_threshold("error")),
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
            maximum=None,
            warning_threshold=threshold.warning,
            error_threshold=threshold.error,
            threshold_direction=threshold.direction,
            warning_crossings=0,
            error_crossings=0,
        )

    sorted_values = sorted(values)
    return MetricSummary(
        metric=metric,
        count=len(values),
        minimum=sorted_values[0],
        p50=_percentile(sorted_values, 50),
        p90=_percentile(sorted_values, 90),
        maximum=sorted_values[-1],
        warning_threshold=threshold.warning,
        error_threshold=threshold.error,
        threshold_direction=threshold.direction,
        warning_crossings=_crossings(values, threshold.warning, threshold.direction),
        error_crossings=_crossings(values, threshold.error, threshold.direction),
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


def _crossing_label(direction: ThresholdDirection, threshold: float, count: int) -> str:
    operator = ">" if direction == "above" else "<"
    return f"{operator}{_format_number(threshold)}:{count}"


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
