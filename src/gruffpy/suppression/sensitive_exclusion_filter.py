"""Drop the sensitive-data findings configuration claims, and count every drop.

``FAMILY-CONTRACT.md`` (search: ``### 13a. Sensitive exclusions``) requires that a suppressed
finding leaves scoring and exit codes exactly as the port's directive channel does, and that it is
never silently invisible: each entry publishes one audit row even when it matched nothing.

An audit row carries only the rule, path, symbol, and reason the user configured. Nothing here
reads a finding's message, so no matched value material can reach the report (section 5).
"""

import re
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


BUILT_IN_TEST_PATH_REASON = "Test, fixture and example files hold sample credentials, so sensitive-data rules skip them by path."
"""Reason a user reads on each ``builtInTestPath[...]`` audit row; every port publishes these exact words (FAMILY-CONTRACT.md section 13a)."""

# The one sensitive-data rule that still reads test paths, because finding realistic personal data in fixtures is its job.
_BUILT_IN_TEST_PATH_EXEMPT_RULE = "sensitive-data.pii-test-fixture"
# Directory names, compared case-insensitively, that make a path test code, e.g. ``tests/`` or ``Fixtures/``.
_BUILT_IN_TEST_PATH_DIRECTORIES = frozenset({"test", "tests", "__tests__", "spec", "testdata", "fixtures", "examples"})
# Matches a whole base name that marks a test file in any family language, e.g. ``test_login.py`` or ``login_test.py``.
_BUILT_IN_TEST_FILE_NAME = re.compile(r"(?:.*_test\.go|test_.*\.py|.*_test\.py|.*Test\.php|.*\.(?:test|spec)\.(?:js|jsx|ts|tsx|mjs|cjs))")


def apply_built_in_test_path_skip(
    findings: Sequence[Finding],
    suppressions: Sequence[SuppressionSummary],
) -> tuple[list[Finding], tuple[SuppressionSummary, ...]]:
    """Hide sensitive-data findings in test, fixture and example files, and publish one audit row per hidden file and rule.

    A user scanning a project with sample keys in ``tests/fixtures/`` sees ``builtInTestPath[...]`` rows instead of findings.
    The skip is never silent, and ``sensitive-data.pii-test-fixture`` keeps reading these files (FAMILY-CONTRACT.md section 13a).

    Args:
        findings: Findings left after the user's exclusions, in report order.
        suppressions: The audit rows so far; this class's rows follow them.

    Returns:
        Tuple ``(kept, summaries)``; ``summaries`` gains no row when no test-path file had a sensitive-data finding.
    """
    skipped_count_by_file_and_rule: dict[tuple[str, str], int] = {}
    kept: list[Finding] = []
    # Each finding either stays in the report or is folded into its file's audit row.
    for finding in findings:
        # Only the pillar's findings in test code are skipped, and never the fixture-PII rule.
        if (
            finding.rule_id.startswith("sensitive-data.")
            and finding.rule_id != _BUILT_IN_TEST_PATH_EXEMPT_RULE
            and is_built_in_test_path(finding.file_path)
        ):
            file_and_rule = (finding.file_path, finding.rule_id)
            skipped_count_by_file_and_rule[file_and_rule] = skipped_count_by_file_and_rule.get(file_and_rule, 0) + 1
            continue
        kept.append(finding)
    rows = list(suppressions)
    # Built-in rows count from 0 on their own, so row 0 means the same in every port however many entries the user configured.
    next_index = 0
    # Python orders strings by code point, which is UTF-8 byte order, so rows sort as in every port.
    # Text output shows each row as ``builtInTestPath[tests/keys.py] sensitive-data.aws-access-key: 2``.
    for offset, (file_path, rule_id) in enumerate(sorted(skipped_count_by_file_and_rule)):
        rows.append(
            SuppressionSummary(
                index=next_index + offset,
                rule=rule_id,
                paths=(file_path,),
                symbol=None,
                reason=BUILT_IN_TEST_PATH_REASON,
                suppressed=skipped_count_by_file_and_rule[(file_path, rule_id)],
                source="built-in",
            )
        )
    return kept, tuple(rows)


def is_built_in_test_path(file_path: str) -> bool:
    """Return whether a finding's file is test, fixture or example code, e.g. ``tests/unit/test_keys.py`` or ``examples/demo.py``.

    Args:
        file_path: The finding's project-relative display path, as the report prints it.

    Returns:
        True for a directory named in the family list, compared case-insensitively, or a test-file base name.
    """
    *directories, base_name = file_path.replace("\\", "/").split("/")
    # Any directory on the path, compared case-insensitively, or the file name alone can mark test code.
    return any(directory.lower() in _BUILT_IN_TEST_PATH_DIRECTORIES for directory in directories) or (
        _BUILT_IN_TEST_FILE_NAME.fullmatch(base_name) is not None
    )


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
