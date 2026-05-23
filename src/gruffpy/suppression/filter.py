"""Post-analysis finding filter for explicit gruff suppressions."""

from collections.abc import Mapping, Sequence

from gruffpy.finding.finding import Finding
from gruffpy.suppression.parser import ParsedSuppressions


def apply_suppressions(
    findings: Sequence[Finding],
    suppressions_by_file: Mapping[str, ParsedSuppressions],
) -> list[Finding]:
    """Return findings not suppressed by source comments.

    Args:
        findings: Findings emitted by rules and composite synthesis.
        suppressions_by_file: Parsed suppressions keyed by display path.

    Returns:
        Findings with matching suppressions removed. Unsuppressed ``Finding``
        objects are returned unchanged.
    """
    return [
        finding
        for finding in findings
        if not _is_suppressed(finding, suppressions_by_file.get(finding.file_path))
    ]


def _is_suppressed(finding: Finding, suppressions: ParsedSuppressions | None) -> bool:
    if suppressions is None:
        return False
    if finding.rule_id in suppressions.file_disabled_rule_ids:
        return True
    if finding.line is None:
        return False
    return finding.rule_id in suppressions.disabled_on_line(finding.line)
