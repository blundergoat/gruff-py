import ast

from gruffpy.analysis.changed_region import (
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


def test_symbol_scope_keeps_signature_finding_when_body_changed() -> None:
    unit = _unit("def changed():\n    return eval('x')\n")
    finding = _finding("sample.py", line=1, symbol="changed")
    changed = parse_explicit_ranges(("sample.py",), "2-2")

    result = filter_findings_for_changed_regions([finding], [unit], changed, "symbol")

    assert result.findings == [finding]
    assert result.suppressed_count == 0


def test_hunk_scope_excludes_signature_finding_when_only_body_changed() -> None:
    unit = _unit("def changed():\n    return eval('x')\n")
    finding = _finding("sample.py", line=1, symbol="changed")
    changed = parse_explicit_ranges(("sample.py",), "2-2")

    result = filter_findings_for_changed_regions([finding], [unit], changed, "hunk")

    assert result.findings == []
    assert result.suppressed_count == 1


def test_symbol_scope_excludes_sibling_function_findings() -> None:
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
    unit = _unit("def old_bad():\n    return 1\n")
    finding = _finding("sample.py", line=1, symbol="old_bad")
    changed = parse_unified_diff(
        "stdin",
        "diff --git a/sample.py b/sample.py\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        "+++ b/sample.py\n"
        "@@ -0,0 +1,2 @@\n"
        "+def old_bad():\n"
        "+    return 1\n",
    )

    result = filter_findings_for_changed_regions([finding], [unit], changed, "symbol")

    assert result.findings == [finding]
    assert result.suppressed_count == 0


def test_symbol_scope_keeps_findings_for_deletion_only_hunk() -> None:
    unit = _unit("def changed():\n    return eval('x')\n")
    finding = _finding("sample.py", line=1, symbol="changed")
    changed = parse_unified_diff(
        "stdin",
        "diff --git a/sample.py b/sample.py\n"
        "--- a/sample.py\n"
        "+++ b/sample.py\n"
        "@@ -2 +1,0 @@\n"
        "-    x = 1\n",
    )

    result = filter_findings_for_changed_regions([finding], [unit], changed, "symbol")

    assert result.findings == [finding]
    assert result.suppressed_count == 0


def test_quoted_diff_path_is_decoded_without_the_b_prefix() -> None:
    # Git C-quotes non-ASCII paths and octal-escapes the bytes; the parsed key must
    # decode to the UTF-8 display path with no leading b/, or the file is dropped.
    changed = parse_unified_diff(
        "stdin",
        'diff --git "a/caf\\303\\251.py" "b/caf\\303\\251.py"\n'
        '--- "a/caf\\303\\251.py"\n'
        '+++ "b/caf\\303\\251.py"\n'
        "@@ -1 +1 @@\n"
        "-x = 1\n"
        "+x = 2\n",
    )

    assert changed.changed_files == ("café.py",)


def _unit(source: str) -> AnalysisUnit:
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent
    return AnalysisUnit(
        file=SourceFile(absolute_path="/tmp/sample.py", display_path="sample.py"),
        source=source,
        tree=tree,
    )


def _finding(file_path: str, *, line: int, symbol: str) -> Finding:
    return Finding(
        rule_id="docs.missing-function-docstring",
        message="Function needs a brief intent description in its docstring.",
        file_path=file_path,
        line=line,
        severity=Severity.WARNING,
        pillar=Pillar.DOCUMENTATION,
        tier=RuleTier.V01,
        confidence=Confidence.HIGH,
        symbol=symbol,
    )
