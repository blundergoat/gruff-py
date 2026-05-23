"""Allowlist filtering for the two private dead-code rules. See ADR-015."""

import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.dead_code_allowlist import DeadCodeAllowlist
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.dead_code.unused_private_attribute_rule import UnusedPrivateAttributeRule
from gruffpy.rule.dead_code.unused_private_function_rule import UnusedPrivateFunctionRule
from gruffpy.source.source_file import SourceFile


def _unit(source: str, display_path: str = "x.py") -> AnalysisUnit:
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
    function_rule = UnusedPrivateFunctionRule()
    attribute_rule = UnusedPrivateAttributeRule()
    config = AnalysisConfig(
        rules={
            function_rule.definition().id: RuleSettings(enabled=True),
            attribute_rule.definition().id: RuleSettings(enabled=True),
        },
        dead_code_allowlist=allowlist or DeadCodeAllowlist(),
    )
    return RuleContext(project_root="/", config=config)


def test_function_allowlisted_by_symbol():
    src = "def _helper():\n    pass\n"
    allowlist = DeadCodeAllowlist(symbols=("_helper",))
    findings = UnusedPrivateFunctionRule().analyse(_unit(src), _ctx(allowlist=allowlist))
    assert findings == []


def test_function_allowlisted_by_qualified_class_symbol():
    src = "class C:\n    def _helper(self):\n        pass\n"
    allowlist = DeadCodeAllowlist(symbols=("C._helper",))
    findings = UnusedPrivateFunctionRule().analyse(_unit(src), _ctx(allowlist=allowlist))
    assert findings == []


def test_function_not_allowlisted_when_symbol_differs():
    src = "def _helper():\n    pass\n"
    allowlist = DeadCodeAllowlist(symbols=("_other",))
    findings = UnusedPrivateFunctionRule().analyse(_unit(src), _ctx(allowlist=allowlist))
    assert len(findings) == 1


def test_function_allowlisted_by_decorator_bare_name():
    src = "def register(f):\n    return f\n@register\ndef _hook():\n    pass\n"
    allowlist = DeadCodeAllowlist(decorators=("register",))
    findings = UnusedPrivateFunctionRule().analyse(_unit(src), _ctx(allowlist=allowlist))
    assert findings == []


def test_function_allowlisted_by_dotted_decorator():
    src = "import app\n@app.route('/')\ndef _index():\n    return 'ok'\n"
    allowlist = DeadCodeAllowlist(decorators=("app.route",))
    findings = UnusedPrivateFunctionRule().analyse(_unit(src), _ctx(allowlist=allowlist))
    assert findings == []


def test_function_allowlisted_by_rightmost_decorator_segment():
    src = "import app\n@app.route('/')\ndef _index():\n    return 'ok'\n"
    allowlist = DeadCodeAllowlist(decorators=("route",))
    findings = UnusedPrivateFunctionRule().analyse(_unit(src), _ctx(allowlist=allowlist))
    assert findings == []


def test_function_allowlisted_by_path_glob():
    src = "def _helper():\n    pass\n"
    allowlist = DeadCodeAllowlist(paths=("tests/fixtures/*.py",))
    findings = UnusedPrivateFunctionRule().analyse(
        _unit(src, display_path="tests/fixtures/sample.py"),
        _ctx(allowlist=allowlist),
    )
    assert findings == []


def test_function_path_glob_does_not_match_other_paths():
    src = "def _helper():\n    pass\n"
    allowlist = DeadCodeAllowlist(paths=("tests/fixtures/*.py",))
    findings = UnusedPrivateFunctionRule().analyse(
        _unit(src, display_path="src/app.py"),
        _ctx(allowlist=allowlist),
    )
    assert len(findings) == 1


def test_attribute_allowlisted_by_qualified_symbol():
    src = (
        "class Service:\n"
        "    def __init__(self):\n"
        "        self._cached = None\n"
        "    def run(self):\n"
        "        return 1\n"
    )
    allowlist = DeadCodeAllowlist(symbols=("Service._cached",))
    findings = UnusedPrivateAttributeRule().analyse(_unit(src), _ctx(allowlist=allowlist))
    assert findings == []


def test_attribute_allowlisted_by_class_decorator():
    src = (
        "def register_event(cls):\n"
        "    return cls\n"
        "@register_event\n"
        "class Handler:\n"
        "    def __init__(self):\n"
        "        self._token = 1\n"
        "    def run(self):\n"
        "        return 2\n"
    )
    allowlist = DeadCodeAllowlist(decorators=("register_event",))
    findings = UnusedPrivateAttributeRule().analyse(_unit(src), _ctx(allowlist=allowlist))
    assert findings == []


def test_attribute_allowlisted_by_path():
    src = (
        "class Service:\n"
        "    def __init__(self):\n"
        "        self._cached = None\n"
        "    def run(self):\n"
        "        return 1\n"
    )
    allowlist = DeadCodeAllowlist(paths=("src/legacy/**",))
    findings = UnusedPrivateAttributeRule().analyse(
        _unit(src, display_path="src/legacy/service.py"),
        _ctx(allowlist=allowlist),
    )
    assert findings == []


def test_empty_allowlist_does_not_affect_findings():
    src = "def _helper():\n    pass\n"
    findings = UnusedPrivateFunctionRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1


def test_decorator_allowlist_does_not_fire_when_decorator_absent():
    # decorator allowlist set, but the function isn't decorated; should still fire.
    src = "def _helper():\n    pass\n"
    allowlist = DeadCodeAllowlist(decorators=("register_event",))
    findings = UnusedPrivateFunctionRule().analyse(_unit(src), _ctx(allowlist=allowlist))
    assert len(findings) == 1
