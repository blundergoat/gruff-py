import ast

from gruff.config.analysis_config import AnalysisConfig
from gruff.config.rule_settings import RuleSettings
from gruff.finding.severity import Severity
from gruff.parser.analysis_unit import AnalysisUnit
from gruff.rule.context import RuleContext
from gruff.rule.waste.unreachable_code_rule import UnreachableCodeRule
from gruff.source.source_file import SourceFile


def _make_unit(source: str) -> AnalysisUnit:
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]
    return AnalysisUnit(
        file=SourceFile(absolute_path="/x.py", display_path="x.py", type="python"),
        source=source,
        tree=tree,
    )


def _ctx() -> RuleContext:
    rule = UnreachableCodeRule()
    return RuleContext(
        project_root="/",
        config=AnalysisConfig(
            rules={rule.definition().id: RuleSettings(enabled=True)},
        ),
    )


def test_no_unreachable_code_returns_empty():
    src = "def f():\n    x = 1\n    return x\n"
    assert UnreachableCodeRule().analyse(_make_unit(src), _ctx()) == []


def test_after_return_is_unreachable():
    src = "def f():\n    return 1\n    x = 2\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].severity == Severity.WARNING
    assert findings[0].metadata["terminator"] == "return"
    assert findings[0].line == 3


def test_after_raise_is_unreachable():
    src = "def f():\n    raise ValueError()\n    x = 2\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["terminator"] == "raise"


def test_after_continue_in_loop():
    src = "def f():\n    for x in [1]:\n        continue\n        y = 2\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["terminator"] == "continue"


def test_after_break_in_loop():
    src = "def f():\n    for x in [1]:\n        break\n        y = 2\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["terminator"] == "break"


def test_only_first_unreachable_reported_per_block():
    src = "def f():\n    return 1\n    x = 2\n    y = 3\n    z = 4\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    # Only one finding per block, even if 3 unreachable statements follow.
    assert len(findings) == 1


def test_unreachable_in_branch_separate_from_other_branch():
    src = (
        "def f(x):\n"
        "    if x:\n"
        "        return 1\n"
        "        a = 2\n"
        "    else:\n"
        "        return 3\n"
        "        b = 4\n"
    )
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert len(findings) == 2


def test_return_at_end_of_block_is_fine():
    src = "def f(x):\n    if x:\n        return 1\n    return 0\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert findings == []


def test_definition():
    d = UnreachableCodeRule().definition()
    assert d.id == "waste.unreachable-code"
