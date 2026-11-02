"""Allowlist filtering for the private dead-code rule, ``dead-code.unused-private-attribute``. See ADR-015."""

import ast

import pytest

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.dead_code_allowlist import DeadCodeAllowlist
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.dead_code.unused_private_attribute_rule import UnusedPrivateAttributeRule
from gruffpy.source.source_file import SourceFile

# A class whose private attribute is written and never read, so the rule reports `Service._cached`.
_UNREAD_ATTRIBUTE = "class Service:\n    def __init__(self):\n        self._cached = None\n    def run(self):\n        return 1\n"


def _unit(source: str, display_path: str = "x.py") -> AnalysisUnit:
    """Parse source, link every non-root AST node to its parent and wrap it as an analysis unit at display_path.

    Args:
        source: Python source to parse.
        display_path: Project-relative path of the unit; defaults to ``x.py``.

    Returns:
        The analysis unit.
    """
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]  # AST parent links
    return AnalysisUnit(
        file=SourceFile(absolute_path="/" + display_path, display_path=display_path, type="python"),
        source=source,
        tree=tree,
    )


def _ctx(*, allowlist: DeadCodeAllowlist | None = None) -> RuleContext:
    """Build a rule context with the unused private attribute rule enabled and the given dead-code allowlist.

    Args:
        allowlist: Dead-code allowlist to apply; None applies an empty allowlist.

    Returns:
        The rule context.
    """
    attribute_rule = UnusedPrivateAttributeRule()
    config = AnalysisConfig(
        rules={attribute_rule.definition().id: RuleSettings(enabled=True)},
        dead_code_allowlist=allowlist or DeadCodeAllowlist(),
    )
    return RuleContext(project_root="/", config=config)


def _decorated_handler(decorator: str) -> str:
    """Return module source defining a ``Handler`` class under decorator, whose private attribute is written and never read.

    Args:
        decorator: Decorator expression placed above the class.

    Returns:
        The module source.
    """
    return (
        "import app\n"
        "def register_event(cls):\n"
        "    return cls\n"
        f"@{decorator}\n"
        "class Handler:\n"
        "    def __init__(self):\n"
        "        self._token = 1\n"
        "    def run(self):\n"
        "        return 2\n"
    )


def test_attribute_allowlisted_by_qualified_symbol():
    """Suppress the unread ``Service._cached`` finding when the allowlist names that qualified symbol."""
    allowlist = DeadCodeAllowlist(symbols=("Service._cached",))
    findings = UnusedPrivateAttributeRule().analyse(_unit(_UNREAD_ATTRIBUTE), _ctx(allowlist=allowlist))
    assert findings == []


def test_attribute_not_allowlisted_when_symbol_differs():
    """Still report the unread attribute once when the allowlist names a different symbol."""
    allowlist = DeadCodeAllowlist(symbols=("Service._other",))
    findings = UnusedPrivateAttributeRule().analyse(_unit(_UNREAD_ATTRIBUTE), _ctx(allowlist=allowlist))
    assert len(findings) == 1


@pytest.mark.parametrize(
    ("decorator", "allowlisted"),
    [("register_event", "register_event"), ("app.register", "app.register"), ("app.register", "register")],
    ids=["bare-name", "dotted-name", "rightmost-segment"],
)
def test_attribute_allowlisted_by_class_decorator(decorator: str, allowlisted: str) -> None:
    """Suppress the finding when the allowlist names the class decorator by bare name, dotted name or rightmost segment.

    Args:
        decorator: Decorator applied to the class.
        allowlisted: Decorator name the allowlist holds for that case.
    """
    allowlist = DeadCodeAllowlist(decorators=(allowlisted,))
    findings = UnusedPrivateAttributeRule().analyse(_unit(_decorated_handler(decorator)), _ctx(allowlist=allowlist))
    assert findings == []


def test_attribute_allowlisted_by_path():
    """Suppress the finding for a file under an allowlisted ``src/legacy/**`` glob."""
    allowlist = DeadCodeAllowlist(paths=("src/legacy/**",))
    findings = UnusedPrivateAttributeRule().analyse(
        _unit(_UNREAD_ATTRIBUTE, display_path="src/legacy/service.py"),
        _ctx(allowlist=allowlist),
    )
    assert findings == []


def test_attribute_path_glob_does_not_match_other_paths():
    """Still report the attribute once when the allowlisted path glob does not match the file."""
    allowlist = DeadCodeAllowlist(paths=("tests/fixtures/*.py",))
    findings = UnusedPrivateAttributeRule().analyse(
        _unit(_UNREAD_ATTRIBUTE, display_path="src/app.py"),
        _ctx(allowlist=allowlist),
    )
    assert len(findings) == 1


def test_empty_allowlist_does_not_affect_findings():
    """Report the unread attribute once with an empty allowlist."""
    findings = UnusedPrivateAttributeRule().analyse(_unit(_UNREAD_ATTRIBUTE), _ctx())
    assert len(findings) == 1


def test_decorator_allowlist_does_not_fire_when_decorator_absent():
    """Still report the attribute once when the allowlist names a decorator the class does not carry."""
    # The allowlist names a decorator, but this class carries none, so its unread attribute still reports.
    allowlist = DeadCodeAllowlist(decorators=("register_event",))
    findings = UnusedPrivateAttributeRule().analyse(_unit(_UNREAD_ATTRIBUTE), _ctx(allowlist=allowlist))
    assert len(findings) == 1
