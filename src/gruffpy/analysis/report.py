"""Hold the frozen outcome of one `gruff-py` scan and project it to the `gruff.analysis.v3` contract.

Every command (`analyse`, `summary`, `report`, `dashboard`, and `hook`) builds an `AnalysisReport` and passes it to its renderer.
Its JSON serialization matches sibling implementations (`gruff.analysis.v3` and `gruff.summary.v3`), so field names stay fixed.

- `AnalysisReport`: carries discovered/parsed counts, findings, score, diagnostics, suppressions, and the process exit code.
- `ReportExtensions`: holds optional diff, trend, baseline, mutation, and review payloads omitted from JSON when absent.
"""

from dataclasses import dataclass, field
from typing import Any

from gruffpy.analysis.run_diagnostic import RunDiagnostic
from gruffpy.analysis.suppression_summary import SuppressedFinding, SuppressionSummary
from gruffpy.finding.finding import Finding
from gruffpy.finding.severity import Severity
from gruffpy.scoring.score_report import ScoreReport
from gruffpy.source.discovery import IgnoredPath

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
class MachineReportContext:
    """Serializer-only state that must not change native analysis behavior.

    Attributes:
        project_root: Absolute root used to make every machine path portable.
        include_ignored: Whether discovery crossed default and Git ignore boundaries.
        summary_findings: Full findings before presentation-only filtering, when different.
    """

    project_root: str = "."
    include_ignored: bool = False
    summary_findings: tuple[Finding, ...] | None = None


@dataclass(frozen=True, slots=True)
class AnalysisReport:
    """Native analysis report value object for ``gruff.analysis.v3``.

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
            represented by the canonical ``displayFilter`` section in machine JSON.
        partial_context_caveat: Optional run-level caveat for partial project-rule context.
        suppressed_count: Optional count of changed-region out-of-scope findings.
        suppressions: One audit row per configured ``sensitiveExclusions`` entry, including
            entries that matched nothing. Serialized as the family ``suppressions`` array.
        config_warnings: Non-fatal config-loader warnings (unknown rule-level
            keys downgraded by the default non-strict policy). Serialized under
            ``run.extensions.py.run.configWarnings`` only when non-empty;
            deliberately not diagnostics so they never flip the exit code.
        machine_context: Serializer-only root, include-ignore flag, and pre-display findings.
        suppressed_findings: Findings another tool's comment or a repeated claim removed (FAMILY-CONTRACT.md
            section 13c). Never serialized into the JSON envelope, which counts them in ``suppressions``;
            SARIF keeps each as a result marked suppressed.
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
    config_warnings: tuple[str, ...] = ()
    suppressions: tuple[SuppressionSummary, ...] = ()
    machine_context: MachineReportContext = field(default_factory=MachineReportContext)
    suppressed_findings: tuple[SuppressedFinding, ...] = ()

    def finding_counts(self) -> dict[str, int]:
        """Count published findings by severity so terminal summaries and JSON envelopes show totals at a glance.

        Returns:
            Mapping with `advisory`, `warning`, `error`, and `total` counts (all zero when the scan is clean).
        """
        counts = {"advisory": 0, "warning": 0, "error": 0, "total": len(self.findings)}
        # Tally each published finding under its severity bucket for the CLI header and summary totals.
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def finding_counts_by_rule(self) -> list[dict[str, Any]]:
        """Group published findings by rule ID for `gruff-py summary --group-by rule` and triage views.

        Tracks each rule's total count, worst severity, per-severity breakdown, and first-finding confidence.
        Rows sort by descending count then ascending `ruleId` so repeated runs print identical order.

        Returns:
            Deterministically ordered per-rule summary rows; an empty list when the scan has no findings.
        """
        per_rule: dict[str, dict[str, Any]] = {}
        per_rule_worst: dict[str, Severity] = {}
        # Aggregate every finding by rule ID so multi-severity rules (such as test vs production docstrings) keep accurate counts.
        for finding in self.findings:
            row = per_rule.get(finding.rule_id)
            # First time this rule appears: seed its count, per-severity map, worst severity, and confidence.
            if row is None:
                severity_counts = {"error": 0, "warning": 0, "advisory": 0}
                severity_counts[finding.severity.value] = 1
                per_rule[finding.rule_id] = {
                    "ruleId": finding.rule_id,
                    "count": 1,
                    "severity": finding.severity.value,
                    "severityCounts": severity_counts,
                    "confidence": finding.confidence.value,
                }
                per_rule_worst[finding.rule_id] = finding.severity
            else:
                row["count"] += 1
                row["severityCounts"][finding.severity.value] += 1
                worst = per_rule_worst[finding.rule_id]
                # Promote the rule's headline severity when a later finding is more severe than earlier ones.
                if _SEVERITY_RANK[finding.severity] > _SEVERITY_RANK[worst]:
                    per_rule_worst[finding.rule_id] = finding.severity
                    row["severity"] = finding.severity.value
        return sorted(per_rule.values(), key=lambda row: (-row["count"], row["ruleId"]))

    def parse_error_count(self) -> int:
        """Count fatal parse-error diagnostics shown in the summary header and machine JSON envelope.

        Returns:
            Number of diagnostics whose type is `parse-error`; zero when every Python file parsed cleanly.
        """
        return sum(1 for diagnostic in self.diagnostics if diagnostic.type == "parse-error")

    def has_findings_at_severity(self, severity: Severity) -> bool:
        """Check whether the scan emitted at least one finding at the requested severity level.

        Args:
            severity: Severity level to look for across published findings.

        Returns:
            True when any finding matches `severity`; False when none match or the report has no findings.
        """
        return any(finding.severity == severity for finding in self.findings)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the report to the canonical JSON-compatible payload.

        Returns:
            Dictionary shaped according to gruff.analysis.v3.
        """
        from gruffpy.analysis.machine_contract import analysis_payload

        return analysis_payload(self)

    def to_summary_dict(self) -> dict[str, Any]:
        """Return the sole supported findings-free projection of this report.

        Returns:
            Analysis v3 with only findings removed and its schema identifier changed.
        """
        from gruffpy.analysis.machine_contract import summary_payload

        return summary_payload(self)
