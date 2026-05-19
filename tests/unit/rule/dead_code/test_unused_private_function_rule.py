import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.dead_code.unused_private_function_rule import UnusedPrivateFunctionRule
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
    rule = UnusedPrivateFunctionRule()
    return RuleContext(
        project_root="/",
        config=AnalysisConfig(rules={rule.definition().id: RuleSettings(enabled=True)}),
    )


def test_unused_private_module_function_fires():
    src = "def _helper():\n    pass\ndef main():\n    return 1\n"
    findings = UnusedPrivateFunctionRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["name"] == "_helper"


def test_used_private_function_does_not_fire():
    src = "def _helper():\n    return 1\ndef main():\n    return _helper()\n"
    findings = UnusedPrivateFunctionRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_public_function_skipped():
    src = "def helper():\n    pass\n"
    findings = UnusedPrivateFunctionRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_dunder_method_skipped():
    src = "class C:\n    def __init__(self):\n        pass\n"
    findings = UnusedPrivateFunctionRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_unused_private_method_fires():
    src = (
        "class C:\n"
        "    def _helper(self):\n        return 1\n"
        "    def main(self):\n        return 2\n"
    )
    findings = UnusedPrivateFunctionRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].symbol == "C._helper"


def test_used_private_method_via_self_does_not_fire():
    src = (
        "class C:\n"
        "    def _helper(self):\n        return 1\n"
        "    def main(self):\n        return self._helper()\n"
    )
    findings = UnusedPrivateFunctionRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_used_private_method_via_getattr_literal_does_not_fire():
    src = (
        "class C:\n"
        "    def _helper(self):\n        return 1\n"
        "    def main(self):\n        return getattr(self, '_helper')()\n"
    )
    findings = UnusedPrivateFunctionRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_dispatcher_prefix_suppresses_matching_private_methods_only():
    src = (
        "class C:\n"
        "    def main(self, kind):\n"
        "        return getattr(self, f'_handle_{kind}')()\n"
        "    def _handle_a(self):\n        return 1\n"
        "    def _unrelated(self):\n        return 2\n"
    )
    findings = UnusedPrivateFunctionRule().analyse(_unit(src), _ctx())

    assert [finding.metadata["name"] for finding in findings] == ["_unrelated"]


def test_in_all_skipped():
    src = "__all__ = ['_helper']\ndef _helper():\n    pass\n"
    findings = UnusedPrivateFunctionRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_protocol_method_skipped():
    src = "from typing import Protocol\nclass P(Protocol):\n    def _hook(self): ...\n"
    findings = UnusedPrivateFunctionRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_pytest_fixture_skipped():
    src = "import pytest\n@pytest.fixture\ndef _setup(): return 1\n"
    findings = UnusedPrivateFunctionRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_definition():
    d = UnusedPrivateFunctionRule().definition()
    assert d.id == "dead-code.unused-private-function"
