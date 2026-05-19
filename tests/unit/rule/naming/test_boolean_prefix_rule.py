import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.naming.boolean_prefix_rule import BooleanPrefixRule
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


def _ctx() -> RuleContext:
    rule = BooleanPrefixRule()
    return RuleContext(
        project_root="/",
        config=AnalysisConfig(rules={rule.definition().id: RuleSettings(enabled=True)}),
    )


def test_bool_return_without_prefix_fires():
    src = "def status(x) -> bool:\n    return True\n"
    findings = BooleanPrefixRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["identifier"] == "status"


def test_is_prefix_does_not_fire():
    src = "def is_valid(x) -> bool:\n    return True\n"
    findings = BooleanPrefixRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_has_prefix_does_not_fire():
    src = "def has_value() -> bool:\n    return True\n"
    findings = BooleanPrefixRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_verb_predicate_does_not_fire():
    src = (
        "def uses_quoted_placeholder() -> bool:\n"
        "    return True\n"
        "def check_rules_markdown() -> bool:\n"
        "    return True\n"
    )
    findings = BooleanPrefixRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_bool_adjective_attribute_does_not_fire():
    src = "class C:\n    enabled: bool = True\n    report_interactive: bool = False\n"
    findings = BooleanPrefixRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_flag_prefix_and_suffix_patterns_do_not_fire():
    src = (
        "class C:\n"
        "    include_ignored: bool = True\n"
        "    no_config: bool = False\n"
        "    query_bool: bool = True\n"
        "    feature_flag: bool = False\n"
    )
    findings = BooleanPrefixRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_test_files_are_exempt():
    src = "def _number_is_rendered() -> bool:\n    return True\n"
    findings = BooleanPrefixRule().analyse(_unit(src, "tests/unit/test_widget.py"), _ctx())
    assert findings == []


def test_can_prefix_does_not_fire():
    src = "def can_edit() -> bool:\n    return True\n"
    findings = BooleanPrefixRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_no_return_annotation_does_not_fire():
    src = "def valid(x):\n    return True\n"
    findings = BooleanPrefixRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_non_bool_return_does_not_fire():
    src = "def name() -> str:\n    return 'x'\n"
    findings = BooleanPrefixRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_optional_bool_return_fires():
    src = "from typing import Optional\ndef maybe_status() -> Optional[bool]:\n    return None\n"
    findings = BooleanPrefixRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1


def test_bool_or_none_return_fires():
    src = "def maybe_status() -> bool | None:\n    return None\n"
    findings = BooleanPrefixRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1


def test_string_annotation_fires():
    src = 'def status() -> "bool":\n    return True\n'
    findings = BooleanPrefixRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1


def test_bool_typed_attribute_fires():
    src = "class C:\n    status: bool = True\n"
    findings = BooleanPrefixRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["kind"] == "attribute"


def test_bool_typed_attribute_with_prefix_does_not_fire():
    src = "class C:\n    is_valid: bool = True\n"
    findings = BooleanPrefixRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_override_decorator_skips_rule():
    src = (
        "from typing import override\n"
        "class C:\n"
        "    @override\n"
        "    def valid(self) -> bool:\n"
        "        return True\n"
    )
    findings = BooleanPrefixRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_dunder_skipped():
    src = "class C:\n    def __bool__(self) -> bool:\n        return True\n"
    findings = BooleanPrefixRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_definition():
    d = BooleanPrefixRule().definition()
    assert d.id == "naming.boolean-prefix"
