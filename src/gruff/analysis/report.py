from dataclasses import dataclass
from typing import Any

from gruff.analysis.run_diagnostic import RunDiagnostic
from gruff.analysis.schema import ANALYSIS_SCHEMA_VERSION
from gruff.finding.finding import Finding
from gruff.finding.severity import Severity
from gruff.scoring.score_report import ScoreReport


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
            "tool": {"name": "gruff", "version": self.tool_version},
            "run": {
                "format": self.format,
                "failOn": self.fail_on,
                "config": self.config_path,
                "paths": list(self.requested_paths),
                "filters": self.filters.to_dict() if self.filters is not None else None,
            },
            "summary": {
                "filesDiscovered": self.files_discovered,
                "filesParsed": self.files_parsed,
                "ignoredPaths": len(self.ignored_paths),
                "missingPaths": len(self.missing_paths),
                "parseErrors": self.parse_error_count(),
                "findings": self.finding_counts(),
                "exitCode": self.exit_code,
            },
            "ignoredPaths": list(self.ignored_paths),
            "missingPaths": list(self.missing_paths),
            "diagnostics": [d.to_dict() for d in self.diagnostics],
            "findings": [f.to_dict() for f in self.findings],
        }
        if self.mutation is not None:
            report["mutation"] = _to_report_value(self.mutation)
        if self.score is not None:
            report["score"] = self.score.to_dict()
        if self.diff is not None:
            report["diff"] = _to_report_value(self.diff)
        if self.trend is not None:
            report["trend"] = _to_report_value(self.trend)
        if self.baseline is not None:
            report["baseline"] = _to_report_value(self.baseline)
        if self.review is not None:
            report["review"] = _to_report_value(self.review)
        return report


def _to_report_value(value: Any) -> Any:
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        return to_dict()
    return value
