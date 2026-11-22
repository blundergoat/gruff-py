"""Apply native `gruff:` directives to findings from the current scan.

An ordinary finding can be left out of the report when a matching directive covers it.
Sensitive findings continue to the audited suppression policies that govern them.
"""

from collections.abc import Mapping, Sequence

from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.suppression.parser import ParsedSuppressions


def apply_suppressions(
    findings: Sequence[Finding],
    suppressions_by_file: Mapping[str, ParsedSuppressions],
) -> list[Finding]:
    """Apply the author's native source directives before baseline matching and scoring.
    Sensitive findings remain visible to the dedicated exclusion stages so their removals can be audited.

    Args:
        findings: Findings emitted by rules.
        suppressions_by_file: Parsed suppressions keyed by display path; a missing entry leaves that file's findings unsuppressed.

    Returns:
        Findings with matching native directives removed. A finding without a line can match only a file-wide directive.
        Sensitive findings stay available for the dedicated audited exclusions.
    """
    return [finding for finding in findings if not _is_suppressed(finding, suppressions_by_file.get(finding.file_path))]


def _is_suppressed(finding: Finding, suppressions: ParsedSuppressions | None) -> bool:
    """Check the native directive scope for one ordinary finding.
    A file-wide directive can cover a finding with no source line. A line directive needs an actual line to match.

    Args:
        finding: The finding to test; its rule_id is matched against the disabled rule IDs, and its line (when present) selects the line-level
            suppressions to check.
        suppressions: Suppressions parsed from the finding's file, or None when the file has no parsed suppression entry, in which case nothing is
            suppressed.

    Returns:
        True for an ordinary finding covered by a file-wide or line-level directive. Sensitive findings use their audited exclusion channels.
    """
    # A native suppression cannot hide a sensitive finding, even when the author names its rule exactly.
    if suppressions is None or finding.pillar is Pillar.SENSITIVE_DATA or finding.rule_id.startswith("sensitive-data."):
        return False
    # A file-wide directive covers every ordinary finding from that rule in the file.
    if finding.rule_id in suppressions.file_disabled_rule_ids:
        return True
    # Without a source line there is no location for a line-level directive to match.
    if finding.line is None:
        return False
    return finding.rule_id in suppressions.disabled_on_line(finding.line)
