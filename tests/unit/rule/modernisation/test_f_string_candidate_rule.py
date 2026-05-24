import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.modernisation.f_string_candidate_rule import FStringCandidateRule
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
    rule = FStringCandidateRule()
    return RuleContext(
        project_root="/",
        config=AnalysisConfig(rules={rule.definition().id: RuleSettings(enabled=True)}),
    )


def test_literal_format_with_positional_arg_fires():
    src = 'msg = "Hello, {}!".format(name)\n'
    findings = FStringCandidateRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].rule_id == "modernisation.f-string-candidate"
    assert findings[0].line == 1


def test_literal_format_with_keyword_arg_fires():
    src = 'msg = "Hello, {name}!".format(name=name)\n'
    findings = FStringCandidateRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1


def test_literal_format_with_no_args_does_not_fire():
    src = 'msg = "Hello".format()\n'
    assert FStringCandidateRule().analyse(_unit(src), _ctx()) == []


def test_variable_receiver_format_does_not_fire():
    src = 'template = "Hello, {}!"\nmsg = template.format(name)\n'
    assert FStringCandidateRule().analyse(_unit(src), _ctx()) == []


def test_f_string_does_not_fire():
    src = 'msg = f"Hello, {name}!"\n'
    assert FStringCandidateRule().analyse(_unit(src), _ctx()) == []


def test_non_format_method_does_not_fire():
    src = 'msg = "hello".upper()\n'
    assert FStringCandidateRule().analyse(_unit(src), _ctx()) == []


def test_format_on_non_string_constant_does_not_fire():
    src = "msg = (1).bit_length()\n"
    assert FStringCandidateRule().analyse(_unit(src), _ctx()) == []


def test_multiple_format_calls_each_fire():
    src = 'a = "x={}".format(x)\nb = "y={}".format(y)\n'
    findings = FStringCandidateRule().analyse(_unit(src), _ctx())
    assert len(findings) == 2
    assert {f.line for f in findings} == {1, 2}
