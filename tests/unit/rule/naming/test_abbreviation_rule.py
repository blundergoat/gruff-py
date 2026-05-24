import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.naming.abbreviation_rule import AbbreviationRule
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


def _ctx(accepted: tuple[str, ...] = ()) -> RuleContext:
    rule = AbbreviationRule()
    return RuleContext(
        project_root="/",
        config=AnalysisConfig(
            rules={rule.definition().id: RuleSettings(enabled=True)},
            accepted_abbreviations=accepted,
        ),
    )


def test_function_abbreviation_fires():
    src = "def load_cfg() -> None:\n    pass\n"
    findings = AbbreviationRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata == {
        "identifier": "load_cfg",
        "kind": "function",
        "abbreviation": "cfg",
    }


def test_parameter_abbreviation_fires():
    src = "def handle(req: object) -> None:\n    pass\n"
    findings = AbbreviationRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["kind"] == "parameter"
    assert findings[0].metadata["abbreviation"] == "req"


def test_standard_variadic_names_are_skipped():
    src = "def build(*args: object, **kwargs: object) -> None:\n    pass\n"
    findings = AbbreviationRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_local_variable_abbreviation_fires_once_per_identifier():
    src = "def f() -> None:\n    msg = 'hello'\n    msg = 'again'\n"
    findings = AbbreviationRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert {finding.metadata["abbreviation"] for finding in findings} == {"msg"}


def test_tuple_assignment_abbreviation_fires():
    src = "def f() -> None:\n    req, response = pair\n"
    findings = AbbreviationRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["identifier"] == "req"


def test_accepted_abbreviation_suppresses_finding():
    src = "def load_cfg(ctx: object) -> None:\n    msg = 'hello'\n"
    findings = AbbreviationRule().analyse(_unit(src), _ctx(accepted=("cfg", "ctx", "msg")))
    assert findings == []


def test_clear_identifier_does_not_fire():
    src = "def load_config(request: object) -> None:\n    message = 'hello'\n"
    findings = AbbreviationRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_class_names_are_skipped():
    src = "class Cfg:\n    pass\n"
    findings = AbbreviationRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_module_level_assignments_are_skipped():
    src = "cfg = object()\n"
    findings = AbbreviationRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_test_files_are_skipped():
    src = "def test_uses_cfg(req: object) -> None:\n    msg = 'hello'\n"
    findings = AbbreviationRule().analyse(_unit(src, "tests/test_widget.py"), _ctx())
    assert findings == []


def test_dunder_names_are_skipped():
    src = "def __ctx__() -> None:\n    pass\n"
    findings = AbbreviationRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_definition_is_default_enabled():
    definition = AbbreviationRule().definition()
    assert definition.id == "naming.abbreviation"
    assert definition.default_enabled is True
