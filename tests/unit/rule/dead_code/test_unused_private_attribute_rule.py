import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.dead_code.unused_private_attribute_rule import UnusedPrivateAttributeRule
from gruffpy.source.source_file import SourceFile


def _unit(source: str) -> AnalysisUnit:
    """Parse source, link every non-root AST node to its parent and wrap it as an analysis unit for ``x.py``.

    Args:
        source: Python source to parse.

    Returns:
        The analysis unit.
    """
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
    """Build a rule context with the unused private attribute rule enabled.

    Returns:
        The rule context.
    """
    rule = UnusedPrivateAttributeRule()
    return RuleContext(
        project_root="/",
        config=AnalysisConfig(rules={rule.definition().id: RuleSettings(enabled=True)}),
    )


def test_assigned_never_read_fires():
    """Report one finding naming ``_x`` for a private attribute that is assigned but never read."""
    src = "class C:\n    def __init__(self):\n        self._x = 1\n    def m(self):\n        return 1\n"
    findings = UnusedPrivateAttributeRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["attribute"] == "_x"


def test_assigned_and_read_does_not_fire():
    """Report nothing for a private attribute set in ``__init__`` and read in another method."""
    src = "class C:\n    def __init__(self):\n        self._x = 1\n    def m(self):\n        return self._x\n"
    findings = UnusedPrivateAttributeRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_public_attribute_skipped():
    """Report nothing for an unread public attribute."""
    src = "class C:\n    def __init__(self):\n        self.x = 1\n"
    findings = UnusedPrivateAttributeRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_dataclass_skipped():
    """Report nothing for an unread private field of a dataclass."""
    src = "from dataclasses import dataclass\n@dataclass\nclass C:\n    _x: int = 0\n"
    findings = UnusedPrivateAttributeRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_abc_subclass_skipped():
    """Report nothing for an unread private attribute of an ``ABC`` subclass."""
    src = "from abc import ABC\nclass C(ABC):\n    def __init__(self):\n        self._x = 1\n"
    findings = UnusedPrivateAttributeRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_property_backing_field_skipped():
    """Report nothing for a private field behind a property getter and setter."""
    src = "class C:\n    @property\n    def x(self):\n        return self._x\n    @x.setter\n    def x(self, value):\n        self._x = value\n"
    findings = UnusedPrivateAttributeRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_assigned_in_one_method_read_in_another():
    """Report nothing for a private attribute set from a call in one method and read in another."""
    src = "class C:\n    def setup(self):\n        self._cached = compute()\n    def use(self):\n        return self._cached\n"
    findings = UnusedPrivateAttributeRule().analyse(_unit(src), _ctx())
    assert findings == []
