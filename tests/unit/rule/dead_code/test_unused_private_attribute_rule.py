import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.dead_code.unused_private_attribute_rule import UnusedPrivateAttributeRule
from gruffpy.source.source_file import SourceFile


def _unit(source: str) -> AnalysisUnit:
    """Parse source, link every non-root AST node to its parent and wrap it as an analysis unit for x.py.

    Args:
        source: Python source to parse.

    Returns:
        Unit for x.py containing the supplied source and its parent-linked AST.
    """
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]  # The rule needs this undeclared AST attribute to qualify class names.
    return AnalysisUnit(
        file=SourceFile(absolute_path="/x.py", display_path="x.py", type="python"),
        source=source,
        tree=tree,
    )


def _ctx() -> RuleContext:
    """Build a rule context with the unused private attribute rule enabled.

    Returns:
        A context with settings for the unused private attribute rule alone.
    """
    rule = UnusedPrivateAttributeRule()
    return RuleContext(
        project_root="/",
        config=AnalysisConfig(rules={rule.definition().id: RuleSettings(enabled=True)}),
    )


def test_assigned_never_read_fires():
    """Report one finding naming _x for a private attribute that is assigned but never read.

    Returns:
        None after all assertions pass.
    """
    src = "class C:\n    def __init__(self):\n        self._x = 1\n    def m(self):\n        return 1\n"
    findings = UnusedPrivateAttributeRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["attribute"] == "_x"


def test_assigned_and_read_does_not_fire():
    """Report nothing for a private attribute set during initialization and read in another method.

    Returns:
        None after all assertions pass.
    """
    src = "class C:\n    def __init__(self):\n        self._x = 1\n    def m(self):\n        return self._x\n"
    findings = UnusedPrivateAttributeRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_public_attribute_skipped():
    """Report nothing for an unread public attribute.

    Returns:
        None after all assertions pass.
    """
    src = "class C:\n    def __init__(self):\n        self.x = 1\n"
    findings = UnusedPrivateAttributeRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_dataclass_skipped():
    """Report nothing for an unread private field of a dataclass.

    Returns:
        None after all assertions pass.
    """
    src = "from dataclasses import dataclass\n@dataclass\nclass C:\n    _x: int = 0\n"
    findings = UnusedPrivateAttributeRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_abc_subclass_skipped():
    """Report nothing for an unread private attribute of an ABC subclass.

    Returns:
        None after all assertions pass.
    """
    src = "from abc import ABC\nclass C(ABC):\n    def __init__(self):\n        self._x = 1\n"
    findings = UnusedPrivateAttributeRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_property_backing_field_skipped():
    """Report nothing for a private field behind a property getter and setter.

    Returns:
        None after all assertions pass.
    """
    src = "class C:\n    @property\n    def x(self):\n        return self._x\n    @x.setter\n    def x(self, value):\n        self._x = value\n"
    findings = UnusedPrivateAttributeRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_assigned_in_one_method_read_in_another():
    """Report nothing for a private attribute set from a call in one method and read in another.

    Returns:
        None after all assertions pass.
    """
    src = "class C:\n    def setup(self):\n        self._cached = compute()\n    def use(self):\n        return self._cached\n"
    findings = UnusedPrivateAttributeRule().analyse(_unit(src), _ctx())
    assert findings == []
