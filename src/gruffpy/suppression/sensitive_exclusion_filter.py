"""Drop the sensitive-data findings configuration claims, and count every drop.

``FAMILY-CONTRACT.md`` (search: ``### 13a. Sensitive exclusions``) requires that a suppressed
finding leaves scoring and exit codes exactly as the port's directive channel does, and that it is
never silently invisible: each entry publishes one audit row even when it matched nothing.

An audit row carries only the rule, path, symbol, and reason the user configured. Nothing here
reads a finding's message, so no matched value material can reach the report (section 5).
"""

import posixpath
from collections.abc import Sequence

from gruffpy.analysis.suppression_summary import SuppressionSummary
from gruffpy.config.sensitive_exclusions import SensitiveExclusion
from gruffpy.finding.finding import Finding

#: The one rule the family's built-in lockfile skip covers; every other sensitive-data rule still reads a lockfile.
BUILT_IN_LOCKFILE_RULE = "sensitive-data.high-entropy-string"

#: The rationale every port publishes on a built-in lockfile audit row.
BUILT_IN_LOCKFILE_REASON = "Lockfile digests are published integrity hashes, so the entropy rule skips package-manager lockfiles by name."

#: The ratified package-manager lockfile names, matched by exact base name at any depth.
BUILT_IN_LOCKFILE_NAMES = frozenset(
    {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "composer.lock",
        "Cargo.lock",
        "go.sum",
        "uv.lock",
        "poetry.lock",
    }
)


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


def apply_built_in_lockfile_skip(
    findings: Sequence[Finding],
    suppressions: Sequence[SuppressionSummary],
) -> tuple[list[Finding], tuple[SuppressionSummary, ...]]:
    """Drop the entropy rule's findings in package-manager lockfiles, and count every drop.

    A lockfile digest is a published integrity hash and a real project carries thousands of them,
    so the family skips that one rule by file name. The skip is counted on every surface rather
    than applied in silence, and a lockfile with nothing to skip publishes no row at all. Every
    other sensitive-data rule still reads the lockfile, because a credential pasted into one is as
    live as anywhere else.

    Args:
        findings: Findings that survived the configured entries, in report order.
        suppressions: The configured entries' audit rows, which the built-in rows follow.

    Returns:
        Tuple ``(kept, summaries)`` with the configured rows first, then one row per lockfile.
    """
    skipped: dict[str, int] = {}
    kept: list[Finding] = []
    for finding in findings:
        if finding.rule_id == BUILT_IN_LOCKFILE_RULE and _is_built_in_lockfile(finding.file_path):
            skipped[finding.file_path] = skipped.get(finding.file_path, 0) + 1
            continue
        kept.append(finding)
    rows = list(suppressions)
    # Built-in rows are numbered among themselves, so the index means the same thing in every port however many
    # entries the user configured. ``source`` is what tells a consumer which channel a row came from.
    for built_in_index, lockfile in enumerate(sorted(skipped)):
        rows.append(
            SuppressionSummary(
                index=built_in_index,
                rule=BUILT_IN_LOCKFILE_RULE,
                paths=(lockfile,),
                symbol=None,
                reason=BUILT_IN_LOCKFILE_REASON,
                suppressed=skipped[lockfile],
                source="built-in",
            )
        )
    return kept, tuple(rows)


def _is_built_in_lockfile(file_path: str) -> bool:
    """Return whether *file_path*'s base name is one of the ratified lockfile names."""
    return posixpath.basename(file_path.replace("\\", "/")) in BUILT_IN_LOCKFILE_NAMES


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
