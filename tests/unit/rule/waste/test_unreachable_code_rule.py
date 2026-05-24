import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.waste.unreachable_code_rule import UnreachableCodeRule
from gruffpy.source.source_file import SourceFile


def _make_unit(source: str) -> AnalysisUnit:
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]  # AST parent links
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


def test_if_false_body_is_unreachable():
    src = "def f():\n    if False:\n        x = 1\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.WARNING
    assert finding.line == 3
    assert finding.metadata["cause"] == "literal-false-condition"
    assert finding.metadata["causeLine"] == 2


def test_while_false_body_is_unreachable():
    src = "def f():\n    while False:\n        x = 1\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["cause"] == "literal-false-condition"


def test_if_true_else_branch_is_unreachable():
    src = "def f():\n    if True:\n        x = 1\n    else:\n        y = 2\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert len(findings) == 1
    finding = findings[0]
    assert finding.line == 5
    assert finding.metadata["cause"] == "literal-true-condition"
    assert finding.metadata["causeLine"] == 2


def test_if_zero_body_is_unreachable():
    src = "def f():\n    if 0:\n        x = 1\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["cause"] == "literal-false-condition"


def test_if_one_else_branch_is_unreachable():
    src = "def f():\n    if 1:\n        x = 1\n    else:\n        y = 2\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["cause"] == "literal-true-condition"


def test_if_none_body_is_unreachable():
    src = "def f():\n    if None:\n        x = 1\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["cause"] == "literal-false-condition"


def test_if_empty_string_body_is_unreachable():
    src = 'def f():\n    if "":\n        x = 1\n'
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["cause"] == "literal-false-condition"


def test_if_nonempty_string_else_is_unreachable():
    src = 'def f():\n    if "x":\n        x = 1\n    else:\n        y = 2\n'
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["cause"] == "literal-true-condition"


def test_if_true_without_else_emits_nothing():
    # No orelse means no unreachable branch - body executes, that's normal.
    src = "def f():\n    if True:\n        x = 1\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert findings == []


def test_if_name_does_not_fire():
    # Dynamic condition; even if the name resolves to False at runtime,
    # the rule stays out of it. Conservative scope.
    src = "def f():\n    FLAG = False\n    if FLAG:\n        x = 1\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert findings == []


def test_if_call_does_not_fire():
    src = "def f():\n    if bool():\n        x = 1\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert findings == []


def test_if_comparison_does_not_fire():
    src = "def f():\n    if 1 == 1:\n        x = 1\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert findings == []


def test_if_not_false_does_not_fire():
    # `not False` is True at runtime but isn't a syntactic constant.
    src = "def f():\n    if not False:\n        x = 1\n    else:\n        y = 2\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert findings == []


def test_if_boolop_does_not_fire():
    src = "def f():\n    if True and False:\n        x = 1\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert findings == []


def test_if_attribute_does_not_fire():
    # `os.path.exists(...)` shape - dynamic, conservative.
    src = "import os\ndef f():\n    if os.environ:\n        x = 1\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert findings == []


def test_literal_false_only_first_stmt_reported():
    src = "def f():\n    if False:\n        a = 1\n        b = 2\n        c = 3\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].line == 3


def test_terminator_metadata_unchanged_by_new_cases():
    # Existing statement-after-terminator behavior keeps the old metadata.
    src = "def f():\n    return 1\n    x = 2\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert findings[0].metadata == {"terminator": "return", "terminatorLine": 2}
