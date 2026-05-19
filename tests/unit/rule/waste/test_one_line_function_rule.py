import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.waste.one_line_function_rule import OneLineFunctionRule
from gruffpy.source.source_file import SourceFile


def _unit(source: str) -> AnalysisUnit:
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
    rule = OneLineFunctionRule()
    return RuleContext(
        project_root="/",
        config=AnalysisConfig(rules={rule.definition().id: RuleSettings(enabled=True)}),
    )


def test_passthrough_wrapper_fires():
    src = "def foo(x):\n    return bar(x)\n"
    findings = OneLineFunctionRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].symbol == "foo"


def test_passthrough_with_two_args_fires():
    src = "def foo(x, y):\n    return bar(x, y)\n"
    findings = OneLineFunctionRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1


def test_different_arg_order_does_not_fire():
    src = "def foo(x, y):\n    return bar(y, x)\n"
    findings = OneLineFunctionRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_additional_constant_arg_does_not_fire():
    src = "def foo(x):\n    return bar(x, default=1)\n"
    findings = OneLineFunctionRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_method_wrapper_fires():
    src = "class C:\n    def foo(self, x):\n        return bar(x)\n"
    findings = OneLineFunctionRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].symbol == "C.foo"


def test_multi_statement_body_does_not_fire():
    src = "def foo(x):\n    log(x)\n    return bar(x)\n"
    findings = OneLineFunctionRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_return_without_call_does_not_fire():
    src = "def foo(x):\n    return x + 1\n"
    findings = OneLineFunctionRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_decorator_skips_rule():
    src = "import pytest\n@pytest.fixture\ndef foo(x):\n    return bar(x)\n"
    findings = OneLineFunctionRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_kwonly_passthrough_fires():
    src = "def foo(*, x):\n    return bar(x=x)\n"
    findings = OneLineFunctionRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1


def test_kwonly_mismatch_does_not_fire():
    src = "def foo(*, x):\n    return bar(x=1)\n"
    findings = OneLineFunctionRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_definition():
    d = OneLineFunctionRule().definition()
    assert d.id == "waste.one-line-function"
