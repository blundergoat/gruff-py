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
        findings: Findings emitted by rules.
        suppressions_by_file: Parsed suppressions keyed by display path.

    Returns:
        Findings with matching suppressions removed. Unsuppressed ``Finding``
        objects are returned unchanged.
    """
    return [finding for finding in findings if not _is_suppressed(finding, suppressions_by_file.get(finding.file_path))]


def _is_suppressed(finding: Finding, suppressions: ParsedSuppressions | None) -> bool:
    """Decide whether one finding is silenced by its file's parsed suppression comments, checking file-wide disables before line-level ones.

    A finding without a line number can only be silenced by a file-wide disable, because there is no line to match a line-level suppression against.

    Args:
        finding: The finding to test; its rule_id is matched against the disabled rule IDs, and its line (when present) selects the line-level
            suppressions to check.
        suppressions: Suppressions parsed from the finding's file, or None when the file has no parsed suppression entry, in which case nothing is
            suppressed.

    Returns:
        True when the finding's rule is disabled for the whole file or for the finding's line; False when suppressions is None, the rule is not
        disabled file-wide and the finding has no line, or no matching suppression exists.
    """
    if suppressions is None:
        return False
    if finding.rule_id in suppressions.file_disabled_rule_ids:
        return True
    if finding.line is None:
        return False
    return finding.rule_id in suppressions.disabled_on_line(finding.line)
