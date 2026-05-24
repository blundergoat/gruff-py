import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.waste.unused_parameter_rule import UnusedParameterRule
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
    rule = UnusedParameterRule()
    return RuleContext(
        project_root="/",
        config=AnalysisConfig(rules={rule.definition().id: RuleSettings(enabled=True)}),
    )


def test_unused_parameter_fires():
    src = "def f(x, y):\n    return x + 1\n"
    findings = UnusedParameterRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["parameter"] == "y"


def test_underscore_prefixed_does_not_fire():
    src = "def f(x, _y):\n    return x\n"
    findings = UnusedParameterRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_self_does_not_fire_in_method():
    src = "class C:\n    def m(self):\n        return 1\n"
    findings = UnusedParameterRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_cls_does_not_fire_in_classmethod():
    src = "class C:\n    @classmethod\n    def m(cls):\n        return 1\n"
    findings = UnusedParameterRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_abstract_method_does_not_fire():
    src = (
        "from abc import ABC, abstractmethod\n"
        "class A(ABC):\n"
        "    @abstractmethod\n"
        "    def m(self, x, y): ...\n"
    )
    findings = UnusedParameterRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_protocol_method_does_not_fire():
    src = "from typing import Protocol\nclass P(Protocol):\n    def m(self, x, y): ...\n"
    findings = UnusedParameterRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_pytest_fixture_does_not_fire():
    src = "import pytest\n@pytest.fixture\ndef setup(request): return 1\n"
    findings = UnusedParameterRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_rule_interface_method_does_not_fire():
    src = (
        "class Rule: ...\n"
        "class R(Rule):\n"
        "    def analyse(self, unit, context):\n"
        "        return []\n"
    )
    findings = UnusedParameterRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_http_handler_override_does_not_fire():
    src = (
        "class BaseHTTPRequestHandler: ...\n"
        "class H(BaseHTTPRequestHandler):\n"
        "    def log_message(self, format, *args):\n"
        "        return None\n"
    )
    findings = UnusedParameterRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_parameter_used_by_nested_closure_does_not_fire():
    src = (
        "def create(initial_state):\n"
        "    class Handler:\n"
        "        def get(self):\n"
        "            return initial_state\n"
        "    return Handler\n"
    )
    findings = UnusedParameterRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_kwonly_unused_fires():
    src = "def f(x, *, key=None):\n    return x\n"
    findings = UnusedParameterRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["parameter"] == "key"


def test_multiple_unused_each_emits():
    src = "def f(x, y, z):\n    return 1\n"
    findings = UnusedParameterRule().analyse(_unit(src), _ctx())
    assert {f.metadata["parameter"] for f in findings} == {"x", "y", "z"}
