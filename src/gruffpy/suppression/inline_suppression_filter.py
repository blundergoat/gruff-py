"""Apply ``FAMILY-CONTRACT.md`` section 13c: another tool's suppression comment, and one call reported under two rules.

A comment naming a check that makes a finding's claim suppresses the finding where it was written, when it sits on
the reported line or alone on the line above: a bare bandit ``# nosec`` covers every security and sensitive-data
rule, and zizmor's ``# zizmor: ignore[unpinned-uses]`` covers ``security.github-actions-unpinned-action``. A dynamic
``__import__`` reported by both ``security.dangerous-function-call`` and ``security.variable-import`` reports once, as
``security.dangerous-function-call``. Every removal is counted in one audit row per rule and file, after the
built-in rows, and kept so SARIF can show it as suppressed.
"""

import re
from collections import Counter
from collections.abc import Mapping, Sequence

from gruffpy.analysis.suppression_summary import SuppressedFinding, SuppressionSummary
from gruffpy.finding.finding import Finding

INLINE_REASON = "Another tool's suppression comment names this check, so the finding is suppressed where it was written."
"""Reason on each inline audit row; every port publishes these exact words (FAMILY-CONTRACT.md section 13c)."""

DUPLICATE_REASON = "Another rule reports the same claim on this line, so the line reports it once."
"""Reason on each repeated-claim audit row; every port publishes these exact words (FAMILY-CONTRACT.md section 13c)."""

# zizmor audits section 13c names for gruff-py, each with the workflow rule that makes the same claim.
_ZIZMOR_AUDIT_RULES = {
    "unpinned-uses": "security.github-actions-unpinned-action",
    "dangerous-triggers": "security.github-actions-pull-request-target",
}

# Captures bandit's test ids or names after ``# nosec``; a second ``#`` starts its rationale.
_BANDIT_DIRECTIVE = re.compile(r"#\s*nosec\b([^#\n]*)")

# Matches zizmor's ``# zizmor: ignore[unpinned-uses]`` and captures its audit list.
_ZIZMOR_DIRECTIVE = re.compile(r"#\s*zizmor:\s*ignore\[([^\]]*)\]")


def apply_inline_suppressions(
    findings: Sequence[Finding],
    suppressions: Sequence[SuppressionSummary],
    sources: Mapping[str, str],
) -> tuple[list[Finding], tuple[SuppressionSummary, ...], tuple[SuppressedFinding, ...]]:
    """Remove the findings another tool's comment covers, then the repeated claims, and count both.

    Args:
        findings: Findings left after the sensitive exclusions and the test-path skip.
        suppressions: The audit rows so far; this function's rows follow them.
        sources: Each scanned file's text, keyed by the display path a finding carries.

    Returns:
        Tuple ``(kept, summaries, removed)``: the surviving findings, the earlier rows followed by the inline and
        then the repeated-claim rows, and every removed finding with its audit reason.
    """
    lines_by_file: dict[str, list[str]] = {}
    kept: list[Finding] = []
    suppressed: list[SuppressedFinding] = []
    for finding in findings:
        lines = lines_by_file.setdefault(finding.file_path, sources.get(finding.file_path, "").splitlines())
        # A finding leaves only when a comment on its line, or alone on the line above, names a check making its claim.
        if _is_covered_by_comment(lines, finding):
            suppressed.append(SuppressedFinding(finding=finding, justification=INLINE_REASON))
            continue
        kept.append(finding)
    kept, merged = _merge_repeated_claims(kept)
    # Built-in rows number among themselves; section 13c's rows continue that numbering.
    next_index = sum(1 for summary in suppressions if summary.source == "built-in")
    inline_rows = _rows(suppressed, "inline", INLINE_REASON, next_index)
    duplicate_rows = _rows(merged, "duplicate", DUPLICATE_REASON, next_index + len(inline_rows))
    return kept, (*suppressions, *inline_rows, *duplicate_rows), (*suppressed, *merged)


def _is_covered_by_comment(lines: Sequence[str], finding: Finding) -> bool:
    """Decide whether a nearby inline suppression directive covers the finding.

    Args:
        lines: The finding's file, split into lines.
        finding: The finding to judge; a file-level finding has no line to carry a comment.

    Returns:
        True for a covering nosec or zizmor directive on the finding's line or on the immediately preceding comment-only line.
        False when the line number is missing or out of range, or neither line contains a covering directive.
    """
    line = finding.line
    if line is None or line < 1 or line > len(lines):
        return False
    if _has_covering_comment(lines[line - 1], finding.rule_id):
        return True
    above = lines[line - 2].strip() if line >= 2 else ""
    return above.startswith("#") and _has_covering_comment(above, finding.rule_id)


def _has_covering_comment(line: str, rule_id: str) -> bool:
    """Determine whether a Bandit or zizmor suppression on this line covers the rule.

    Args:
        line: Source line searched for suppression directives.
        rule_id: Finding's rule ID, checked by prefix for bare nosec and by exact ID for a mapped zizmor audit.

    Returns:
        True when a bare # nosec covers a security or sensitive-data rule, or a zizmor audit maps to the rule.
        False otherwise. A nosec directive naming Bandit tests provides no coverage because FAMILY-CONTRACT.md section 13c maps none of them.
    """
    is_broad = rule_id.startswith(("security.", "sensitive-data."))
    for match in _BANDIT_DIRECTIVE.finditer(line):
        if is_broad and not match.group(1).strip(" \t:,"):
            return True
    return any(_ZIZMOR_AUDIT_RULES.get(audit.strip()) == rule_id for match in _ZIZMOR_DIRECTIVE.finditer(line) for audit in match.group(1).split(","))


def _merge_repeated_claims(findings: list[Finding]) -> tuple[list[Finding], list[SuppressedFinding]]:
    """Suppress duplicate __import__ findings by pairing reports on the same file and line.
    Each security.variable-import finding uses one available security.dangerous-function-call finding.

    Args:
        findings: Findings left after the inline comments.

    Returns:
        Tuple (kept, merged); each merged finding carries the repeated-claim reason.
    """
    dangerous_imports = Counter(
        (finding.file_path, finding.line)
        for finding in findings
        if finding.rule_id == "security.dangerous-function-call" and finding.metadata.get("target") == "__import__"
    )
    kept: list[Finding] = []
    merged: list[SuppressedFinding] = []
    for finding in findings:
        key = (finding.file_path, finding.line)
        # Consuming one counterpart per match keeps surplus variable-import findings on the same line.
        if finding.rule_id == "security.variable-import" and finding.metadata.get("target") == "__import__" and dangerous_imports[key] > 0:
            dangerous_imports[key] -= 1
            merged.append(SuppressedFinding(finding=finding, justification=DUPLICATE_REASON))
            continue
        kept.append(finding)
    return kept, merged


def _rows(removed: Sequence[SuppressedFinding], source: str, reason: str, first_index: int) -> list[SuppressionSummary]:
    """Fold removed findings into one audit row per file and rule, sorted by path and then rule identifier.

    Args:
        removed: Findings one section 13c class removed.
        source: Audit row label, either inline or duplicate.
        reason: The class's exact audit reason.
        first_index: Index of the first row this class adds.

    Returns:
        One row per file and rule with its removal count and source label; an empty input produces no rows.
    """
    counts = Counter((item.finding.file_path, item.finding.rule_id) for item in removed)
    return [
        SuppressionSummary(
            index=first_index + offset,
            rule=rule_id,
            paths=(file_path,),
            symbol=None,
            reason=reason,
            suppressed=counts[(file_path, rule_id)],
            source=source,
        )
        for offset, (file_path, rule_id) in enumerate(sorted(counts))
    ]
