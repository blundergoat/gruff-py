import ast

from gruff.config.analysis_config import AnalysisConfig
from gruff.config.rule_settings import RuleSettings
from gruff.parser.analysis_unit import AnalysisUnit
from gruff.rule.context import RuleContext
from gruff.rule.waste.unused_parameter_rule import UnusedParameterRule
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


def test_kwonly_unused_fires():
    src = "def f(x, *, key=None):\n    return x\n"
    findings = UnusedParameterRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["parameter"] == "key"


def test_multiple_unused_each_emits():
    src = "def f(x, y, z):\n    return 1\n"
    findings = UnusedParameterRule().analyse(_unit(src), _ctx())
    assert {f.metadata["parameter"] for f in findings} == {"x", "y", "z"}


def test_definition():
    d = UnusedParameterRule().definition()
    assert d.id == "waste.unused-parameter"
