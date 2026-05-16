import ast

from gruff.config.analysis_config import AnalysisConfig
from gruff.config.rule_settings import RuleSettings
from gruff.parser.analysis_unit import AnalysisUnit
from gruff.rule.context import RuleContext
from gruff.rule.naming.short_variable_rule import ShortVariableRule
from gruff.source.source_file import SourceFile


def _unit(source: str, display_path: str = "x.py") -> AnalysisUnit:
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]
    return AnalysisUnit(
        file=SourceFile(absolute_path=f"/{display_path}", display_path=display_path, type="python"),
        source=source,
        tree=tree,
    )


def _ctx(options: dict | None = None) -> RuleContext:
    rule = ShortVariableRule()
    return RuleContext(
        project_root="/",
        config=AnalysisConfig(
            rules={rule.definition().id: RuleSettings(enabled=True, options=options or {})}
        ),
    )


def test_q_variable_fires():
    src = "q = 1\n"
    findings = ShortVariableRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1


def test_short_variable_in_test_file_is_skipped():
    src = "def test_example():\n    d = {}\n    assert d == {}\n"
    findings = ShortVariableRule().analyse(_unit(src, display_path="tests/test_example.py"), _ctx())
    assert findings == []


def test_i_does_not_fire():
    src = "i = 0\n"
    findings = ShortVariableRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_x_does_not_fire():
    src = "x = 1\n"
    findings = ShortVariableRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_underscore_does_not_fire():
    src = "_ = compute()\n"
    findings = ShortVariableRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_two_char_does_not_fire():
    src = "qq = 1\n"
    findings = ShortVariableRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_tuple_assignment_each_checked():
    src = "a, b, q = 1, 2, 3\n"
    findings = ShortVariableRule().analyse(_unit(src), _ctx())
    # a, b, q -> a NOT in default accepted, b NOT in accepted, q NOT in accepted
    # default accepted: i,j,k,n,m,x,y,z,e,_,f
    names = {f.metadata["identifier"] for f in findings}
    assert names == {"a", "b", "q"}


def test_configurable_accepted_list():
    src = "q = 1\nr = 2\n"
    findings = ShortVariableRule().analyse(_unit(src), _ctx(options={"acceptedShortNames": ["q"]}))
    names = {f.metadata["identifier"] for f in findings}
    assert names == {"r"}


def test_ann_assign_fires():
    src = "q: int = 1\n"
    findings = ShortVariableRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1


def test_function_param_does_not_fire():
    # Parameters are out of scope for this rule.
    src = "def f(q): return q\n"
    findings = ShortVariableRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_definition():
    d = ShortVariableRule().definition()
    assert d.id == "naming.short-variable"
