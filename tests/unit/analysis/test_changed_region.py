import ast

import pytest

from gruffpy.analysis.changed_region import (
    _SYMBOL_SCOPE_ANCHOR_ONLY_RULE_IDS,
    ChangedRegionSet,
    filter_findings_for_changed_regions,
    parse_explicit_ranges,
    parse_unified_diff,
)
from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.source.source_file import SourceFile

_FILE_LEVEL_ANCHOR_ONLY_RULE_IDS = (
    "docs.missing-module-docstring",
    "docs.todo-density",
    "naming.test-naming-consistency",
    "size.file-length",
    "test-quality.naming-consistency",
)

_CLASS_LEVEL_ANCHOR_ONLY_RULE_IDS = (
    "docs.dataclass-attributes",
    "size.attribute-count",
    "size.average-function-length",
    "size.class-length",
    "size.public-method-count",
)


def test_anchor_only_fixtures_cover_every_source_rule_id() -> None:
    """Cover exactly the source's anchor-only rule set with this module's file-level and class-level rule lists.

    Returns:
        None. Checks that the fixture lists and the source anchor-only rule set contain exactly the same rule IDs.
    """
    # Guards against drift: adding a rule to the source set without covering it
    # here (or vice versa) fails loudly instead of leaving the new rule untested.
    covered = set(_FILE_LEVEL_ANCHOR_ONLY_RULE_IDS) | set(_CLASS_LEVEL_ANCHOR_ONLY_RULE_IDS)
    assert covered == set(_SYMBOL_SCOPE_ANCHOR_ONLY_RULE_IDS)


def test_symbol_scope_keeps_signature_finding_when_body_changed() -> None:
    """Keep a function's signature-line finding under symbol scope when only its body changed.

    Returns:
        None. Checks that symbol-scope filtering keeps the signature finding and records zero suppressions.
    """
    unit = _unit("def changed():\n    return eval('x')\n")
    finding = _finding("sample.py", line=1, symbol="changed")
    changed = parse_explicit_ranges(("sample.py",), "2-2")

    result = filter_findings_for_changed_regions([finding], [unit], changed, "symbol")

    assert result.findings == [finding]
    assert result.suppressed_count == 0


@pytest.mark.parametrize("rule_id", _FILE_LEVEL_ANCHOR_ONLY_RULE_IDS)
def test_symbol_scope_excludes_file_level_findings_when_edit_misses_anchor(
    rule_id: str,
) -> None:
    """Suppress a file-level finding under symbol scope when the edit misses its line-1 anchor.

    Args:
        rule_id: File-level rule; the cases cover every one in this module's file-level list.

    Returns:
        None. Checks that symbol scope suppresses the file-level finding when the edit misses its anchor.
    """
    unit = _unit("def changed():\n    return 1\n")
    finding = _finding("sample.py", rule_id=rule_id, line=1, end_line=10, symbol=None)
    changed = parse_explicit_ranges(("sample.py",), "2-2")

    result = filter_findings_for_changed_regions([finding], [unit], changed, "symbol")

    assert result.findings == []
    assert result.suppressed_count == 1


@pytest.mark.parametrize("rule_id", _CLASS_LEVEL_ANCHOR_ONLY_RULE_IDS)
def test_symbol_scope_excludes_class_level_findings_when_edit_misses_anchor(
    rule_id: str,
) -> None:
    """Suppress a class-level finding under symbol scope when the edit misses its class line.

    Args:
        rule_id: Class-level rule; the cases cover every one in this module's class-level list.

    Returns:
        None. Checks that symbol scope suppresses the class-level finding when the edit misses the class line.
    """
    unit = _unit("class Big:\n    value = 1\n    other = 2\n")
    finding = _finding("sample.py", rule_id=rule_id, line=1, end_line=3, symbol="Big")
    changed = parse_explicit_ranges(("sample.py",), "2-2")

    result = filter_findings_for_changed_regions([finding], [unit], changed, "symbol")

    assert result.findings == []
    assert result.suppressed_count == 1


def test_symbol_scope_keeps_decorated_class_aggregate_when_class_header_changed() -> None:
    """Keep a decorated class's length finding under symbol scope when the edit touches its class line below the decorator.

    Returns:
        None. Checks that editing the decorated class's header retains its length finding under symbol scope.
    """
    unit = _unit("@decorator\nclass Big:\n    value = 1\n")
    finding = _finding("sample.py", rule_id="size.class-length", line=1, end_line=3, symbol="Big")
    changed = parse_explicit_ranges(("sample.py",), "2-2")

    result = filter_findings_for_changed_regions([finding], [unit], changed, "symbol")

    assert result.findings == [finding]
    assert result.suppressed_count == 0


def test_symbol_scope_keeps_file_level_finding_when_anchor_changed() -> None:
    """Keep a file-level finding under symbol scope when the edit touches line 1.

    Returns:
        None. Checks that symbol scope keeps the file-level finding when line 1 changes.
    """
    unit = _unit("x = 1\n")
    finding = _finding("sample.py", rule_id="size.file-length", line=1, end_line=10, symbol=None)
    changed = parse_explicit_ranges(("sample.py",), "1-1")

    result = filter_findings_for_changed_regions([finding], [unit], changed, "symbol")

    assert result.findings == [finding]
    assert result.suppressed_count == 0


def test_full_scan_keeps_file_level_finding() -> None:
    """Keep a file-level finding, suppressing nothing, when the changed-region set has no source.

    Returns:
        None. Checks that a full scan keeps the file-level finding with zero suppressions.
    """
    unit = _unit("x = 1\n")
    finding = _finding("sample.py", rule_id="size.file-length", line=1, end_line=10, symbol=None)
    changed = ChangedRegionSet(source="")

    result = filter_findings_for_changed_regions([finding], [unit], changed, "symbol")

    assert result.findings == [finding]
    assert result.suppressed_count == 0


def test_symbol_scope_keeps_line_level_finding_on_changed_line() -> None:
    """Keep a line-level finding on the changed line under symbol scope.

    Returns:
        None. Checks that symbol scope keeps the line-level finding on the edited line.
    """
    unit = _unit("x = 1\ny = eval('x')\n")
    finding = _finding("sample.py", rule_id="security.dangerous-function-call", line=2, symbol=None)
    changed = parse_explicit_ranges(("sample.py",), "2-2")

    result = filter_findings_for_changed_regions([finding], [unit], changed, "symbol")

    assert result.findings == [finding]
    assert result.suppressed_count == 0


def test_hunk_scope_still_keeps_file_level_span_when_edit_intersects_it() -> None:
    """Keep a file-level finding under hunk scope when the edit falls inside its line span.

    Returns:
        None. Checks that hunk scope keeps the file-level finding when the edit overlaps its reported span.
    """
    unit = _unit("x = 1\n")
    finding = _finding("sample.py", rule_id="size.file-length", line=1, end_line=10, symbol=None)
    changed = parse_explicit_ranges(("sample.py",), "5-5")

    result = filter_findings_for_changed_regions([finding], [unit], changed, "hunk")

    assert result.findings == [finding]
    assert result.suppressed_count == 0


def test_hunk_scope_excludes_signature_finding_when_only_body_changed() -> None:
    """Suppress a function's signature-line finding under hunk scope when only its body changed.

    Returns:
        None. Checks that hunk scope suppresses the signature-line finding after a body-only edit.
    """
    unit = _unit("def changed():\n    return eval('x')\n")
    finding = _finding("sample.py", line=1, symbol="changed")
    changed = parse_explicit_ranges(("sample.py",), "2-2")

    result = filter_findings_for_changed_regions([finding], [unit], changed, "hunk")

    assert result.findings == []
    assert result.suppressed_count == 1


def test_symbol_scope_excludes_sibling_function_findings() -> None:
    """Suppress a sibling function's finding under symbol scope while keeping the changed function's finding.

    Returns:
        None. Checks that symbol scope keeps the edited function's finding and suppresses the sibling's.
    """
    unit = _unit("def old_bad():\n    return 1\n\n\ndef changed():\n    return eval('x')\n")
    old_finding = _finding("sample.py", line=1, symbol="old_bad")
    changed_finding = _finding("sample.py", line=5, symbol="changed")
    changed = parse_explicit_ranges(("sample.py",), "6-6")

    result = filter_findings_for_changed_regions(
        [old_finding, changed_finding],
        [unit],
        changed,
        "symbol",
    )

    assert result.findings == [changed_finding]
    assert result.suppressed_count == 1


def test_new_file_diff_marks_whole_file_in_scope() -> None:
    """Keep a finding on a line that a new-file diff adds, under symbol scope.

    Returns:
        None. Checks that symbol scope retains the finding on a line added by the new-file diff.
    """
    unit = _unit("def old_bad():\n    return 1\n")
    finding = _finding("sample.py", line=1, symbol="old_bad")
    changed = parse_unified_diff(
        "stdin",
        "diff --git a/sample.py b/sample.py\nnew file mode 100644\n--- /dev/null\n+++ b/sample.py\n@@ -0,0 +1,2 @@\n+def old_bad():\n+    return 1\n",
    )

    result = filter_findings_for_changed_regions([finding], [unit], changed, "symbol")

    assert result.findings == [finding]
    assert result.suppressed_count == 0


def test_symbol_scope_keeps_findings_for_deletion_only_hunk() -> None:
    """Keep a function's finding under symbol scope when the diff only deletes a line from it.

    Returns:
        None. Checks that symbol scope keeps the function's finding after a deletion-only hunk.
    """
    unit = _unit("def changed():\n    return eval('x')\n")
    finding = _finding("sample.py", line=1, symbol="changed")
    changed = parse_unified_diff(
        "stdin",
        "diff --git a/sample.py b/sample.py\n--- a/sample.py\n+++ b/sample.py\n@@ -2 +1,0 @@\n-    x = 1\n",
    )

    result = filter_findings_for_changed_regions([finding], [unit], changed, "symbol")

    assert result.findings == [finding]
    assert result.suppressed_count == 0


def test_quoted_diff_path_is_decoded_without_the_b_prefix() -> None:
    """Decode a C-quoted, octal-escaped diff path to its UTF-8 name without the b/ prefix.

    Returns:
        None. Checks that the changed-file key is café.py.
    """
    # Decode the octal bytes and strip b/ so the diff key matches the project-relative path used to look up findings.
    changed = parse_unified_diff(
        "stdin",
        'diff --git "a/caf\\303\\251.py" "b/caf\\303\\251.py"\n--- "a/caf\\303\\251.py"\n+++ "b/caf\\303\\251.py"\n@@ -1 +1 @@\n-x = 1\n+x = 2\n',
    )

    assert changed.changed_files == ("café.py",)


def _unit(source: str) -> AnalysisUnit:
    """Parse source into an analysis unit for sample.py, linking every non-root AST node to its parent.

    Args:
        source: Python source to parse.

    Returns:
        The unit, whose non-root tree nodes carry a parent attribute.
    """
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent
    return AnalysisUnit(
        file=SourceFile(absolute_path="/tmp/sample.py", display_path="sample.py"),
        source=source,
        tree=tree,
    )


def _finding(
    file_path: str,
    *,
    line: int,
    symbol: str | None,
    rule_id: str = "docs.missing-function-docstring",
    end_line: int | None = None,
) -> Finding:
    """Build a warning-level documentation finding with a fixed message.

    Args:
        file_path: Display path used when matching the finding to changed files.
        line: Reported start line used for changed-range matching.
        symbol: Name used to match declarations. None leaves anchor-only findings on the start line and lets other findings match by location.
        rule_id: Rule identifier used to select anchor-only or declaration-aware filtering.
        end_line: Last reported line. None limits direct and anchor-only matches to the start line. Other findings can still match by declaration.

    Returns:
        A warning-level documentation finding with the supplied location and rule identifier.
    """
    return Finding(
        rule_id=rule_id,
        message="Function needs a brief intent description in its docstring.",
        file_path=file_path,
        line=line,
        severity=Severity.WARNING,
        pillar=Pillar.DOCUMENTATION,
        tier=RuleTier.V01,
        confidence=Confidence.HIGH,
        end_line=end_line,
        symbol=symbol,
    )
