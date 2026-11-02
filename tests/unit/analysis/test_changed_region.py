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
    "naming.module-name-mismatch",
    "size.attribute-count",
    "size.average-function-length",
    "size.class-length",
    "size.public-method-count",
)


def test_anchor_only_fixtures_cover_every_source_rule_id() -> None:
    """Cover exactly the source's anchor-only rule set with this module's file-level and class-level rule lists."""
    # Guards against drift: adding a rule to the source set without covering it
    # here (or vice versa) fails loudly instead of leaving the new rule untested.
    covered = set(_FILE_LEVEL_ANCHOR_ONLY_RULE_IDS) | set(_CLASS_LEVEL_ANCHOR_ONLY_RULE_IDS)
    assert covered == set(_SYMBOL_SCOPE_ANCHOR_ONLY_RULE_IDS)


def test_symbol_scope_keeps_signature_finding_when_body_changed() -> None:
    """Keep a function's signature-line finding under symbol scope when only its body changed."""
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
    """
    unit = _unit("class Big:\n    value = 1\n    other = 2\n")
    finding = _finding("sample.py", rule_id=rule_id, line=1, end_line=3, symbol="Big")
    changed = parse_explicit_ranges(("sample.py",), "2-2")

    result = filter_findings_for_changed_regions([finding], [unit], changed, "symbol")

    assert result.findings == []
    assert result.suppressed_count == 1


def test_symbol_scope_keeps_decorated_class_aggregate_when_class_header_changed() -> None:
    """Keep a decorated class's length finding under symbol scope when the edit touches its class line below the decorator."""
    unit = _unit("@decorator\nclass Big:\n    value = 1\n")
    finding = _finding("sample.py", rule_id="size.class-length", line=1, end_line=3, symbol="Big")
    changed = parse_explicit_ranges(("sample.py",), "2-2")

    result = filter_findings_for_changed_regions([finding], [unit], changed, "symbol")

    assert result.findings == [finding]
    assert result.suppressed_count == 0


def test_symbol_scope_keeps_file_level_finding_when_anchor_changed() -> None:
    """Keep a file-level finding under symbol scope when the edit touches line 1."""
    unit = _unit("x = 1\n")
    finding = _finding("sample.py", rule_id="size.file-length", line=1, end_line=10, symbol=None)
    changed = parse_explicit_ranges(("sample.py",), "1-1")

    result = filter_findings_for_changed_regions([finding], [unit], changed, "symbol")

    assert result.findings == [finding]
    assert result.suppressed_count == 0


def test_full_scan_keeps_file_level_finding() -> None:
    """Keep a file-level finding, suppressing nothing, when the changed-region set has no source."""
    unit = _unit("x = 1\n")
    finding = _finding("sample.py", rule_id="size.file-length", line=1, end_line=10, symbol=None)
    changed = ChangedRegionSet(source="")

    result = filter_findings_for_changed_regions([finding], [unit], changed, "symbol")

    assert result.findings == [finding]
    assert result.suppressed_count == 0


def test_symbol_scope_keeps_line_level_finding_on_changed_line() -> None:
    """Keep a line-level finding on the changed line under symbol scope."""
    unit = _unit("x = 1\ny = eval('x')\n")
    finding = _finding("sample.py", rule_id="security.dangerous-function-call", line=2, symbol=None)
    changed = parse_explicit_ranges(("sample.py",), "2-2")

    result = filter_findings_for_changed_regions([finding], [unit], changed, "symbol")

    assert result.findings == [finding]
    assert result.suppressed_count == 0


def test_hunk_scope_still_keeps_file_level_span_when_edit_intersects_it() -> None:
    """Keep a file-level finding under hunk scope when the edit falls inside its line span."""
    unit = _unit("x = 1\n")
    finding = _finding("sample.py", rule_id="size.file-length", line=1, end_line=10, symbol=None)
    changed = parse_explicit_ranges(("sample.py",), "5-5")

    result = filter_findings_for_changed_regions([finding], [unit], changed, "hunk")

    assert result.findings == [finding]
    assert result.suppressed_count == 0


def test_hunk_scope_excludes_signature_finding_when_only_body_changed() -> None:
    """Suppress a function's signature-line finding under hunk scope when only its body changed."""
    unit = _unit("def changed():\n    return eval('x')\n")
    finding = _finding("sample.py", line=1, symbol="changed")
    changed = parse_explicit_ranges(("sample.py",), "2-2")

    result = filter_findings_for_changed_regions([finding], [unit], changed, "hunk")

    assert result.findings == []
    assert result.suppressed_count == 1


def test_symbol_scope_excludes_sibling_function_findings() -> None:
    """Suppress a sibling function's finding under symbol scope while keeping the changed function's finding."""
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
    """Keep a finding on a line that a new-file diff adds, under symbol scope."""
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
    """Keep a function's finding under symbol scope when the diff only deletes a line from it."""
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
    """Decode a C-quoted, octal-escaped diff path to its UTF-8 name without the ``b/`` prefix."""
    # Git C-quotes non-ASCII paths and octal-escapes the bytes; the parsed key must
    # decode to the UTF-8 display path with no leading b/, or the file is dropped.
    changed = parse_unified_diff(
        "stdin",
        'diff --git "a/caf\\303\\251.py" "b/caf\\303\\251.py"\n--- "a/caf\\303\\251.py"\n+++ "b/caf\\303\\251.py"\n@@ -1 +1 @@\n-x = 1\n+x = 2\n',
    )

    assert changed.changed_files == ("café.py",)


def _unit(source: str) -> AnalysisUnit:
    """Parse source into an analysis unit for ``sample.py``, linking every non-root AST node to its parent.

    Args:
        source: Python source to parse.

    Returns:
        The unit, whose non-root tree nodes carry a ``parent`` attribute.
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
        file_path: Finding path.
        line: Start line.
        symbol: Symbol, or None for a finding not tied to a declaration.
        rule_id: Rule id; the missing-function-docstring rule by default.
        end_line: End line, or None.

    Returns:
        The finding.
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
