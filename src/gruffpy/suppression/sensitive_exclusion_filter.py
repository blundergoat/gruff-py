"""Drop the sensitive-data findings configuration claims, and count every drop.

``FAMILY-CONTRACT.md`` (search: ``### 13a. Sensitive exclusions``) requires that a suppressed
finding leaves scoring and exit codes exactly as the port's directive channel does, and that it is
never silently invisible: each entry publishes one audit row even when it matched nothing.

An audit row carries only the rule, path, symbol, and reason the user configured. Nothing here
reads a finding's message, so no matched value material can reach the report (section 5).
"""

import posixpath
import re
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
        findings: Findings left after the user's exclusions and the lockfile skip, in report order.
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
    # Built-in rows are numbered among themselves, so the first test-path row follows the last lockfile row.
    next_index = sum(1 for row in rows if row.source == "built-in")
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
