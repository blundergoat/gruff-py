"""Report value object serialized as ``gruff-py.analysis.v1``."""

from dataclasses import dataclass
from typing import Any

from gruffpy.analysis.run_diagnostic import RunDiagnostic
from gruffpy.analysis.schema import ANALYSIS_SCHEMA_VERSION
from gruffpy.finding.finding import Finding
from gruffpy.finding.severity import Severity
from gruffpy.scoring.score_report import ScoreReport
from gruffpy.version import TOOL_NAME


@dataclass(frozen=True, slots=True)
class AnalysisReport:
    tool_version: str
    requested_paths: tuple[str, ...]
    format: str
    fail_on: str
    files_discovered: int
    files_parsed: int
    ignored_paths: tuple[str, ...]
    missing_paths: tuple[str, ...]
    diagnostics: tuple[RunDiagnostic, ...]
    findings: tuple[Finding, ...]
    exit_code: int
    config_path: str | None = None
    score: ScoreReport | None = None
    mutation: Any | None = None
    diff: Any | None = None
    trend: Any | None = None
    baseline: Any | None = None
    review: Any | None = None
    filters: Any | None = None

    def finding_counts(self) -> dict[str, int]:
        counts = {"advisory": 0, "warning": 0, "error": 0, "total": len(self.findings)}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def parse_error_count(self) -> int:
        return sum(1 for d in self.diagnostics if d.type == "parse-error")

    def has_findings_at_severity(self, severity: Severity) -> bool:
        return any(f.severity == severity for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        report: dict[str, Any] = {
            "schemaVersion": ANALYSIS_SCHEMA_VERSION,
            "tool": {"name": TOOL_NAME, "version": self.tool_version},
            "run": _run_payload(self),
            "summary": _summary_payload(self),
            "ignoredPaths": list(self.ignored_paths),
            "missingPaths": list(self.missing_paths),
            "diagnostics": [d.to_dict() for d in self.diagnostics],
            "findings": [f.to_dict() for f in self.findings],
        }
        report.update(_optional_payloads(self))
        return report


def _run_payload(report: AnalysisReport) -> dict[str, Any]:
    return {
        "format": report.format,
        "failOn": report.fail_on,
        "config": report.config_path,
        "paths": list(report.requested_paths),
        "filters": report.filters.to_dict() if report.filters is not None else None,
    }


def _summary_payload(report: AnalysisReport) -> dict[str, Any]:
    return {
        "filesDiscovered": report.files_discovered,
        "filesParsed": report.files_parsed,
        "ignoredPaths": len(report.ignored_paths),
        "missingPaths": len(report.missing_paths),
        "parseErrors": report.parse_error_count(),
        "findings": report.finding_counts(),
        "exitCode": report.exit_code,
    }


def _optional_payloads(report: AnalysisReport) -> dict[str, Any]:
    optional_sections = {
        "mutation": report.mutation,
        "score": report.score,
        "diff": report.diff,
        "trend": report.trend,
        "baseline": report.baseline,
        "review": report.review,
    }
    return {
        key: _to_report_value(value)
        for key, value in optional_sections.items()
        if value is not None
    }


def _to_report_value(value: Any) -> Any:
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        return to_dict()
    return value
