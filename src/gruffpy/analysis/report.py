"""Native analysis-run value objects projected as the ``gruff.analysis.v2`` schema.

Defines :class:`AnalysisReport` - the frozen outcome of one analysis run, carrying
requested paths, file counts, findings, score, diagnostics, ignored paths, and exit
code - and :class:`ReportExtensions` for the optional mutation, diff, trend, baseline,
and review sections. Every reporter (JSON, SARIF, text) consumes this object, and its
JSON projection is the cross-implementation ``gruff.analysis.v2`` contract, so the
field names here are a compatibility surface.
"""

from dataclasses import dataclass, field
from typing import Any

from gruffpy.analysis.run_diagnostic import RunDiagnostic
from gruffpy.analysis.schema import ANALYSIS_SCHEMA_VERSION
from gruffpy.finding.finding import Finding
from gruffpy.finding.severity import Severity
from gruffpy.scoring.score_report import ScoreReport
from gruffpy.source.discovery import IgnoredPath
from gruffpy.version import TOOL_NAME

_SEVERITY_RANK: dict[Severity, int] = {
    Severity.ADVISORY: 0,
    Severity.WARNING: 1,
    Severity.ERROR: 2,
}


@dataclass(frozen=True, slots=True)
class ReportExtensions:
    """Optional report sections omitted from JSON when absent.

    Attributes:
        mutation: Optional mutation-testing payload.
        diff: Optional diff-comparison payload.
        trend: Optional trend payload.
        baseline: Optional baseline-comparison payload.
        review: Optional review-assistance payload.
    """

    mutation: Any | None = None
    diff: Any | None = None
    trend: Any | None = None
    baseline: Any | None = None
    review: Any | None = None


@dataclass(frozen=True, slots=True)
class AnalysisReport:
    """Native analysis report value object for ``gruff.analysis.v2``.

    Attributes:
        tool_version: gruff-py version that produced the report.
        requested_paths: User-requested input paths.
        format: Requested output format.
        fail_on: Configured fail threshold.
        files_discovered: Count of discovered source files.
        files_parsed: Count of successfully parsed files.
        ignored_paths: Paths skipped by discovery.
        ignored_path_details: The skipped paths with their ignore source and
            matched pattern (serialized as additive ``ignoredPathDetails``).
        missing_paths: Requested paths that were not found.
        diagnostics: Non-finding run diagnostics.
        findings: Rule findings emitted for the run.
        exit_code: Process exit code implied by findings and diagnostics.
        config_path: Loaded configuration path, if any.
        score: Optional score payload.
        extensions: Optional report extension sections.
        filters: Optional finding-display filter metadata.
        hidden_by_display_filter: Findings hidden by display filters. Native-only;
            omitted from ``gruff.analysis.v2`` JSON unless the schema is explicitly extended.
        partial_context_caveat: Optional run-level caveat for partial project-rule context.
        suppressed_count: Optional count of changed-region out-of-scope findings.
    """

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
    extensions: ReportExtensions = field(default_factory=ReportExtensions)
    filters: Any | None = None
    hidden_by_display_filter: int = 0
    partial_context_caveat: str | None = None
    output_volume_hint_threshold: int = 50
    suppressed_count: int | None = None
    ignored_path_details: tuple[IgnoredPath, ...] = ()

    def finding_counts(self) -> dict[str, int]:
        """Return finding counts grouped by severity.

        Returns:
            Mapping containing advisory, warning, error, and total counts.
        """
        counts = {"advisory": 0, "warning": 0, "error": 0, "total": len(self.findings)}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def finding_counts_by_rule(self) -> list[dict[str, Any]]:
        """Return one row per rule that emitted at least one finding.

        Each row carries ``ruleId``, ``count``, the **worst** ``severity``
        observed across the rule's findings (so threshold-based rules that
        emit both ``warning`` and ``error`` are labelled by the highest band
        seen), and ``confidence`` taken from the first finding (confidence is
        rule-level today and does not vary across findings of the same rule).
        Rows are sorted by ``count`` descending then ``ruleId`` ascending so
        identical inputs produce identical output across runs.

        Returns:
            Deterministically ordered list of per-rule rows.
        """
        per_rule: dict[str, dict[str, Any]] = {}
        per_rule_worst: dict[str, Severity] = {}
        for finding in self.findings:
            row = per_rule.get(finding.rule_id)
            if row is None:
                per_rule[finding.rule_id] = {
                    "ruleId": finding.rule_id,
                    "count": 1,
                    "severity": finding.severity.value,
                    "confidence": finding.confidence.value,
                }
                per_rule_worst[finding.rule_id] = finding.severity
            else:
                row["count"] += 1
                worst = per_rule_worst[finding.rule_id]
                if _SEVERITY_RANK[finding.severity] > _SEVERITY_RANK[worst]:
                    per_rule_worst[finding.rule_id] = finding.severity
                    row["severity"] = finding.severity.value
        return sorted(per_rule.values(), key=lambda row: (-row["count"], row["ruleId"]))

    def parse_error_count(self) -> int:
        """Return the number of parser diagnostics in the report.

        Returns:
            Count of diagnostics whose type is ``parse-error``.
        """
        return sum(1 for d in self.diagnostics if d.type == "parse-error")

    def has_findings_at_severity(self, severity: Severity) -> bool:
        """Return whether the report contains a finding at a severity.

        Args:
            severity: Severity level to search for.

        Returns:
            True when at least one finding has the requested severity.
        """
        return any(f.severity == severity for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the report to the native JSON-compatible payload.

        Returns:
            Dictionary shaped according to ``gruff.analysis.v2``.
        """
        report: dict[str, Any] = {
            "schemaVersion": ANALYSIS_SCHEMA_VERSION,
            "tool": {"name": TOOL_NAME, "version": self.tool_version},
            "run": _run_payload(self),
            "summary": _summary_payload(self),
            "ignoredPaths": list(self.ignored_paths),
            "ignoredPathDetails": [detail.to_dict() for detail in self.ignored_path_details],
            "missingPaths": list(self.missing_paths),
            "diagnostics": [d.to_dict() for d in self.diagnostics],
            "findings": [f.to_dict() for f in self.findings],
        }
        if self.suppressed_count is not None:
            report["suppressedCount"] = self.suppressed_count
        report.update(_optional_payloads(self))
        return report


def _run_payload(report: AnalysisReport) -> dict[str, Any]:
    payload = {
        "format": report.format,
        "failOn": report.fail_on,
        "config": report.config_path,
        "paths": list(report.requested_paths),
        "filters": report.filters.to_dict() if report.filters is not None else None,
    }
    if report.partial_context_caveat is not None:
        payload["partialContextCaveat"] = report.partial_context_caveat
    return payload


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
        "mutation": report.extensions.mutation,
        "score": report.score,
        "diff": report.extensions.diff,
        "trend": report.extensions.trend,
        "baseline": report.extensions.baseline,
        "review": report.extensions.review,
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
