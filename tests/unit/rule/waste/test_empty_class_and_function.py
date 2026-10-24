import ast

import pytest

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.waste.empty_function_rule import EmptyFunctionRule
from gruffpy.source.source_file import SourceFile


def _unit(source: str, display_path: str = "x.py") -> AnalysisUnit:
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]  # AST parent links
    return AnalysisUnit(
        file=SourceFile(absolute_path=f"/{display_path}", display_path=display_path, type="python"),
        source=source,
        tree=tree,
    )


def _ctx_for(rule_id: str) -> RuleContext:
    return RuleContext(
        project_root="/",
        config=AnalysisConfig(rules={rule_id: RuleSettings(enabled=True)}),
    )


def test_empty_function_pass_fires():
    src = "def f():\n    pass\n"
    findings = EmptyFunctionRule().analyse(_unit(src), _ctx_for("waste.empty-function"))
    assert len(findings) == 1
    assert findings[0].symbol == "f"


def test_empty_function_ellipsis_fires():
    src = "def f():\n    ...\n"
    findings = EmptyFunctionRule().analyse(_unit(src), _ctx_for("waste.empty-function"))
    assert len(findings) == 1


def test_abstract_method_does_not_fire():
    src = "from abc import ABC, abstractmethod\nclass A(ABC):\n    @abstractmethod\n    def m(self): ...\n"
    findings = EmptyFunctionRule().analyse(_unit(src), _ctx_for("waste.empty-function"))
    assert findings == []


def test_overload_stub_does_not_fire():
    src = "from typing import overload\n@overload\ndef f(x: int) -> int: ...\ndef f(x): return x\n"
    findings = EmptyFunctionRule().analyse(_unit(src), _ctx_for("waste.empty-function"))
    assert findings == []


def test_protocol_method_stub_does_not_fire():
    src = "from typing import Protocol\nclass P(Protocol):\n    def m(self):\n        ...\n"
    findings = EmptyFunctionRule().analyse(_unit(src), _ctx_for("waste.empty-function"))
    assert findings == []


def test_pytest_fixture_does_not_fire():
    src = "import pytest\n@pytest.fixture\ndef setup():\n    ...\n"
    findings = EmptyFunctionRule().analyse(_unit(src), _ctx_for("waste.empty-function"))
    assert findings == []


def test_function_with_body_does_not_fire():
    src = "def f():\n    return 1\n"
    findings = EmptyFunctionRule().analyse(_unit(src), _ctx_for("waste.empty-function"))
    assert findings == []


def test_function_with_docstring_and_pass_fires():
    # Docstring + pass should still count as empty (the docstring is just a
    # comment for the purposes of this rule).
    src = '''def f():
    """A function."""
    pass
'''
    findings = EmptyFunctionRule().analyse(_unit(src), _ctx_for("waste.empty-function"))
    assert len(findings) == 1


def test_test_double_empty_method_does_not_fire():
    src = "class FakeTerminal:\n    def close(self):\n        pass\n"
    findings = EmptyFunctionRule().analyse(
        _unit(src, "tests/unit/test_terminal.py"),
        _ctx_for("waste.empty-function"),
    )
    assert findings == []


def test_production_test_double_name_still_fires():
    src = "class FakeTerminal:\n    def close(self):\n        pass\n"
    findings = EmptyFunctionRule().analyse(
        _unit(src, "src/gruffpy/terminal.py"),
        _ctx_for("waste.empty-function"),
    )
    assert len(findings) == 1


@pytest.mark.parametrize(
    "source, exempt",
    [
        (
            'from pluggy import HookspecMarker\nhookspec = HookspecMarker("pytest")\n'
            'def pytest_exception_interact(node):\n    """Plugin hook specification."""\n',
            True,
        ),
        ('def pytest_exception_interact(node):\n    """Plugin hook specification."""\n', False),
        (
            'from elsewhere import HookspecMarker\nhookspec = HookspecMarker("pytest")\n'
            'def pytest_exception_interact(node):\n    """Plugin hook specification."""\n',
            False,
        ),
        ('from pluggy import HookspecMarker\nhookspec = HookspecMarker("pytest")\ndef ordinary(node):\n    """Unimplemented function."""\n', False),
        ("from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    def instance_dict(instance): ...\n", True),
        ('import typing\nif typing.TYPE_CHECKING:\n    async def instance_dict(instance):\n        """Typing declaration."""\n        ...\n', True),
        ("if TYPE_CHECKING:\n    pass\nelse:\n    def instance_dict(instance): ...\n", False),
        ("if TYPE_CHECKING:\n    def instance_dict(instance): pass\n", False),
        ("if DEBUG:\n    def instance_dict(instance): ...\n", False),
    ],
    ids=[
        "pluggy-hookspec",
        "hook-name-without-marker",
        "non-pluggy-marker",
        "pluggy-marker-ordinary-function",
        "type-checking-stub",
        "typing-attribute-async-stub",
        "type-checking-else-branch",
        "type-checking-pass-body",
        "unrelated-guard",
    ],
)
def test_source_proven_declarations(source: str, exempt: bool) -> None:
    findings = EmptyFunctionRule().analyse(_unit(source), _ctx_for("waste.empty-function"))
    assert (not findings) is exempt


def test_nested_inner_test_double_class_exempts_its_method():
    src = "class Suite:\n    class FakeClient:\n        def close(self):\n            pass\n"
    findings = EmptyFunctionRule().analyse(
        _unit(src, "tests/unit/test_terminal.py"),
        _ctx_for("waste.empty-function"),
    )
    assert findings == []


def test_nested_plain_class_in_test_double_outer_still_fires():
    src = "class FakeSuite:\n    class Helper:\n        def close(self):\n            pass\n"
    findings = EmptyFunctionRule().analyse(
        _unit(src, "tests/unit/test_terminal.py"),
        _ctx_for("waste.empty-function"),
    )
    assert len(findings) == 1
