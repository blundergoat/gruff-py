import ast

from gruff.config.analysis_config import AnalysisConfig
from gruff.config.rule_settings import RuleSettings
from gruff.parser.analysis_unit import AnalysisUnit
from gruff.rule.context import RuleContext
from gruff.rule.waste.redundant_variable_rule import RedundantVariableRule
from gruff.source.source_file import SourceFile


def _unit(source: str) -> AnalysisUnit:
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
    rule = RedundantVariableRule()
    return RuleContext(
        project_root="/",
        config=AnalysisConfig(rules={rule.definition().id: RuleSettings(enabled=True)}),
    )


def test_assign_then_return_fires():
    src = "def f():\n    x = 1 + 2\n    return x\n"
    findings = RedundantVariableRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["variable"] == "x"


def test_assign_then_return_with_complex_rhs_fires():
    src = "def f(items):\n    result = sorted(items, key=lambda x: x.id)\n    return result\n"
    findings = RedundantVariableRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["variable"] == "result"


def test_variable_used_elsewhere_does_not_fire():
    # x is used in the print statement BEFORE the return — not redundant.
    src = "def f():\n    x = 1\n    print(x)\n    x = 2\n    return x\n"
    findings = RedundantVariableRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_assigned_then_returned_in_last_two_stmts_fires():
    # The strict shape matches only the last assign + return pair.
    # `y = 2; return y` qualifies; the earlier `x = 1` is incidental.
    src = "def f():\n    x = 1\n    y = 2\n    return y\n"
    findings = RedundantVariableRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["variable"] == "y"


def test_target_name_used_earlier_does_not_fire():
    # The returned variable IS referenced earlier in the body -> not redundant.
    src = "def f():\n    x = 1\n    print(x)\n    x = x + 1\n    return x\n"
    findings = RedundantVariableRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_short_function_no_match():
    src = "def f():\n    return 1\n"
    findings = RedundantVariableRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_multiple_assignment_targets_skipped():
    # x, y = 1, 2 is not the strict shape we match
    src = "def f():\n    x, y = 1, 2\n    return x\n"
    findings = RedundantVariableRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_return_no_value_skipped():
    src = "def f():\n    x = 1\n    return\n"
    findings = RedundantVariableRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_method_in_class_fires():
    src = "class C:\n    def m(self):\n        x = self.a + 1\n        return x\n"
    findings = RedundantVariableRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].symbol == "C.m"


def test_definition():
    d = RedundantVariableRule().definition()
    assert d.id == "waste.redundant-variable"
