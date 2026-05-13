import ast

from gruff.config.analysis_config import AnalysisConfig
from gruff.config.rule_settings import RuleSettings
from gruff.parser.analysis_unit import AnalysisUnit
from gruff.rule.context import RuleContext
from gruff.rule.dead_code.unused_private_attribute_rule import UnusedPrivateAttributeRule
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
    rule = UnusedPrivateAttributeRule()
    return RuleContext(
        project_root="/",
        config=AnalysisConfig(rules={rule.definition().id: RuleSettings(enabled=True)}),
    )


def test_assigned_never_read_fires():
    src = (
        "class C:\n"
        "    def __init__(self):\n"
        "        self._x = 1\n"
        "    def m(self):\n"
        "        return 1\n"
    )
    findings = UnusedPrivateAttributeRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["attribute"] == "_x"


def test_assigned_and_read_does_not_fire():
    src = (
        "class C:\n"
        "    def __init__(self):\n"
        "        self._x = 1\n"
        "    def m(self):\n"
        "        return self._x\n"
    )
    findings = UnusedPrivateAttributeRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_public_attribute_skipped():
    src = "class C:\n    def __init__(self):\n        self.x = 1\n"
    findings = UnusedPrivateAttributeRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_dataclass_skipped():
    src = "from dataclasses import dataclass\n@dataclass\nclass C:\n    _x: int = 0\n"
    findings = UnusedPrivateAttributeRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_abc_subclass_skipped():
    src = "from abc import ABC\nclass C(ABC):\n    def __init__(self):\n        self._x = 1\n"
    findings = UnusedPrivateAttributeRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_property_backing_field_skipped():
    src = (
        "class C:\n"
        "    @property\n"
        "    def x(self):\n"
        "        return self._x\n"
        "    @x.setter\n"
        "    def x(self, value):\n"
        "        self._x = value\n"
    )
    findings = UnusedPrivateAttributeRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_assigned_in_one_method_read_in_another():
    src = (
        "class C:\n"
        "    def setup(self):\n"
        "        self._cached = compute()\n"
        "    def use(self):\n"
        "        return self._cached\n"
    )
    findings = UnusedPrivateAttributeRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_definition():
    d = UnusedPrivateAttributeRule().definition()
    assert d.id == "dead-code.unused-private-attribute"
