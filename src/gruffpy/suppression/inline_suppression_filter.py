"""Apply the suppression and duplicate-claim rules in FAMILY-CONTRACT.md section 13c.

A third-party directive can cover a finding on the same line or on the next line after a comment-only directive.
Each removal contributes an audit count. SARIF can also show the original finding as suppressed.

- Bare Bandit suppression comments cover security and sensitive-data findings.
- Supported zizmor audit names cover their corresponding workflow rules.
- A dynamic import reported by both rules becomes one dangerous-function-call finding.
"""

import re
from bisect import bisect_right
from collections import Counter
from collections.abc import Mapping, Sequence

import yaml
from yaml.tokens import ScalarToken

from gruffpy.analysis.suppression_summary import SuppressedFinding, SuppressionSummary
from gruffpy.finding.finding import Finding
from gruffpy.source.comment_scanner import scan_comments

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
    """Apply supported third-party comments and merge repeated claims before findings are reported.
    The audit counts both kinds of removal so reviewers can explain changes in what they see.

    Args:
        findings: Findings left after the sensitive exclusions and the test-path skip.
        suppressions: The audit rows so far; this function's rows follow them.
        sources: Text by display path. A missing or empty entry offers no suppressing comments for that file.

    Returns:
        Tuple ``(kept, summaries, removed)``: the surviving findings, the earlier rows followed by the inline and
        then the repeated-claim rows, and every removed finding with its audit reason.
    """
    comments_by_file: dict[str, tuple[dict[int, str], set[int]]] = {}
    kept: list[Finding] = []
    suppressed: list[SuppressedFinding] = []
    # Check findings individually because a comment can cover one result while leaving its neighbour visible.
    for finding in findings:
        path = finding.file_path
        # Read directives once per file, even if several rules reported a finding there.
        if path not in comments_by_file:
            comments_by_file[path] = _directive_comments(path, sources.get(path, ""))
        comments, standalone = comments_by_file[path]
        # Keep an audit entry when the rule is hidden so reviewers can distinguish suppression from a repair.
        if _is_covered_by_comment(comments, standalone, finding):
            suppressed.append(SuppressedFinding(finding=finding, justification=INLINE_REASON))
            continue
        kept.append(finding)
    kept, merged = _merge_repeated_claims(kept)
    # Built-in rows number among themselves; section 13c's rows continue that numbering.
    next_index = sum(1 for summary in suppressions if summary.source == "built-in")
    inline_rows = _rows(suppressed, "inline", INLINE_REASON, next_index)
    duplicate_rows = _rows(merged, "duplicate", DUPLICATE_REASON, next_index + len(inline_rows))
    return kept, (*suppressions, *inline_rows, *duplicate_rows), (*suppressed, *merged)


def _directive_comments(path: str, source: str) -> tuple[dict[int, str], set[int]]:
    """Read the third-party suppression comments that can affect findings in this file.
    Bandit directives are read from Python comments and zizmor directives from YAML comments.

    Args:
        path: Display path used to distinguish Bandit Python and zizmor YAML inputs.
        source: Source text for the file. Empty text yields no comments or matching lines.

    Returns:
        Comments by line and the subset whose lines contain no code before the comment.
    """
    comments: dict[int, str] = {}
    # A Python literal containing `# nosec` must stay visible to security rules.
    if path.lower().endswith(".py") and "nosec" in source:
        comments = {token.line: token.raw for token in scan_comments(source) if _BANDIT_DIRECTIVE.match(token.raw)}
    # Workflow directives have their own YAML comment syntax and rule names.
    elif path.lower().endswith((".yaml", ".yml")) and "zizmor:" in source:
        comments = _yaml_directive_comments(source)
    # With no recognised directive, no finding can be covered by a preceding comment.
    if not comments:
        return comments, set()
    lines = source.split("\n")
    return comments, {line for line in comments if lines[line - 1].lstrip().startswith("#")}


def _yaml_directive_comments(source: str) -> dict[int, str]:
    """Find real zizmor comments outside YAML strings and block text.
    Use the scalar boundaries so a workflow value that quotes a directive does not hide a finding.

    Args:
        source: Workflow text whose YAML tokens identify the scalar spans.

    Returns:
        Comment text by line. An unscannable workflow supplies no suppressions.
    """
    try:
        spans = [(token.start_mark.index, token.end_mark.index) for token in yaml.scan(source) if isinstance(token, ScalarToken)]
    except (yaml.YAMLError, RecursionError):
        # An unterminated YAML quote hides the boundary between text and comments, so keep all findings visible.
        return {}
    starts = [start for start, _ in spans]
    comments: dict[int, str] = {}
    offset = 0
    # Keep the source line number so a real directive covers only the finding next to it.
    for line_number, line in enumerate(source.split("\n"), 1):
        # A line may include a quoted example before its actual comment. Check each possible marker.
        for marker in _ZIZMOR_DIRECTIVE.finditer(line):
            index = offset + marker.start()
            preceding_scalar = bisect_right(starts, index) - 1
            # A marker embedded in a quoted value or block scalar is data and cannot suppress a finding.
            if preceding_scalar < 0 or index >= spans[preceding_scalar][1]:
                comments[line_number] = line[marker.start() :]
                break
        offset += len(line) + 1
    return comments


def _is_covered_by_comment(comments: dict[int, str], standalone: set[int], finding: Finding) -> bool:
    """Decide whether the author placed a directive close enough to cover this finding.
    Only the finding's line or the immediately preceding comment-only line can apply.

    Args:
        comments: Recognized source comments keyed by line.
        standalone: Lines that contain only a comment.
        finding: The finding to judge; a file-level finding has no line to carry a comment.

    Returns:
        True for a covering nosec or zizmor directive on the finding's line or on the immediately preceding comment-only line.
        False when the line number is missing or out of range, or neither line contains a covering directive.
    """
    line = finding.line
    # A file-level finding has no line on which the author could have placed this directive.
    if line is None or line < 1:
        return False
    # A recognised directive on the exact finding line applies before looking at the preceding line.
    if _has_covering_comment(comments.get(line, ""), finding.rule_id):
        return True
    return line - 1 in standalone and _has_covering_comment(comments[line - 1], finding.rule_id)


def _has_covering_comment(line: str, rule_id: str) -> bool:
    """Check whether a real comment suppresses the finding's rule under the shared contract.
    Bare Bandit comments cover security and sensitive-data findings. Zizmor names must map to the exact rule.

    Args:
        line: A source comment token or an empty string when no comment was found.
        rule_id: Finding's rule ID, checked by prefix for bare nosec and by exact ID for a mapped zizmor audit.

    Returns:
        True when a bare # nosec covers a security or sensitive-data rule, or a zizmor audit maps to the rule.
        False otherwise. A nosec directive naming Bandit tests provides no coverage because FAMILY-CONTRACT.md section 13c maps none of them.
    """
    allows_bare_nosec = rule_id.startswith(("security.", "sensitive-data."))
    bandit = _BANDIT_DIRECTIVE.match(line)
    # A bare Bandit directive covers security and sensitive data. A named Bandit test has no mapped Gruff rule.
    if allows_bare_nosec and bandit is not None and not bandit.group(1).strip(" \t:,"):
        return True
    zizmor = _ZIZMOR_DIRECTIVE.match(line)
    return zizmor is not None and any(_ZIZMOR_AUDIT_RULES.get(audit.strip()) == rule_id for audit in zizmor.group(1).split(","))


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
