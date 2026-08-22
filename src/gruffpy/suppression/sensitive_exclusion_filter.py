"""Drop the sensitive-data findings configuration claims, and count every drop.

``FAMILY-CONTRACT.md`` (search: ``### 13a. Sensitive exclusions``) requires that a suppressed
finding leaves scoring and exit codes exactly as the port's directive channel does, and that it is
never silently invisible: each entry publishes one audit row even when it matched nothing.

An audit row carries only the rule, path, symbol, and reason the user configured. Nothing here
reads a finding's message, so no matched value material can reach the report (section 5).
"""

from collections.abc import Sequence

from gruffpy.analysis.suppression_summary import SuppressionSummary
from gruffpy.config.sensitive_exclusions import SensitiveExclusion
from gruffpy.finding.finding import Finding


def partition_sensitive_exclusions(
    findings: Sequence[Finding],
    exclusions: Sequence[SensitiveExclusion],
) -> tuple[list[Finding], tuple[SuppressionSummary, ...]]:
    """Split findings into the ones users still see and the audit of the ones they do not.

    A finding is removed only when its rule id, its project-relative display path, and - when the
    entry names one - its symbol all match a single entry exactly. The same rule in another file
    and another rule in the same file both keep reporting.

    Args:
        findings: Findings that survived the inline-directive channel.
        exclusions: Validated ``sensitiveExclusions`` entries in user order.

    Returns:
        Tuple ``(kept, summaries)`` where ``summaries`` has one row per entry, including entries
        that matched nothing.
    """
    counts = [0] * len(exclusions)
    kept: list[Finding] = []
    for finding in findings:
        position = _first_matching_position(finding, exclusions)
        # An unclaimed finding stays in the user's results, their score, and their exit code.
        if position is None:
            kept.append(finding)
            continue
        counts[position] += 1
    summaries = tuple(
        SuppressionSummary(
            index=exclusion.index,
            rule=exclusion.rule,
            paths=(exclusion.path,),
            symbol=exclusion.symbol,
            reason=exclusion.reason,
            suppressed=counts[position],
        )
        for position, exclusion in enumerate(exclusions)
    )
    return kept, summaries


def _first_matching_position(
    finding: Finding,
    exclusions: Sequence[SensitiveExclusion],
) -> int | None:
    """Return the position of the first entry claiming *finding*, so one drop counts once."""
    for position, exclusion in enumerate(exclusions):
        if _matches(finding, exclusion):
            return position
    return None


def _matches(finding: Finding, exclusion: SensitiveExclusion) -> bool:
    """Return whether one entry claims exactly this finding."""
    if finding.rule_id != exclusion.rule:
        return False
    if finding.file_path != exclusion.path:
        return False
    return exclusion.symbol is None or finding.symbol == exclusion.symbol
