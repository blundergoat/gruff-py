import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.naming.hungarian_notation_rule import HungarianNotationRule
from gruffpy.source.source_file import SourceFile


def _unit(source: str) -> AnalysisUnit:
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]
    return AnalysisUnit(
        file=SourceFile(absolute_path="/x.py", display_path="x.py", type="python"),
        source=source,
        tree=tree,
    )


def _ctx() -> RuleContext:
    rule = HungarianNotationRule()
    return RuleContext(
        project_root="/",
        config=AnalysisConfig(rules={rule.definition().id: RuleSettings(enabled=True)}),
    )


def test_i_prefix_fires():
    src = "i_count = 0\n"
    findings = HungarianNotationRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["prefix"] == "i"


def test_s_name_fires():
    src = "s_name = 'x'\n"
    findings = HungarianNotationRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1


def test_str_message_fires():
    src = "str_message = 'hello'\n"
    findings = HungarianNotationRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1


def test_arr_items_fires():
    src = "arr_items = []\n"
    findings = HungarianNotationRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1


def test_lst_items_fires():
    src = "lst_items = []\n"
    findings = HungarianNotationRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1


def test_dict_users_fires():
    src = "dict_users = {}\n"
    findings = HungarianNotationRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1


def test_list_verb_name_does_not_fire():
    src = "def list_commands():\n    return []\n"
    findings = HungarianNotationRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_set_verb_name_does_not_fire():
    src = "def set_status(value):\n    return value\n"
    findings = HungarianNotationRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_parameter_name_fires():
    src = "def f(b_is_valid):\n    return b_is_valid\n"
    findings = HungarianNotationRule().analyse(_unit(src), _ctx())
    assert len(findings) >= 1
    assert any(f.metadata["identifier"] == "b_is_valid" for f in findings)


def test_function_name_fires():
    src = "def s_format(x): return str(x)\n"
    findings = HungarianNotationRule().analyse(_unit(src), _ctx())
    assert any(f.metadata["identifier"] == "s_format" for f in findings)


def test_class_name_does_not_fire():
    # Class names are NOT scanned (StrSerializer is fine).
    src = "class StrSerializer:\n    pass\n"
    findings = HungarianNotationRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_clean_name_does_not_fire():
    src = "count = 0\nname = 'x'\nitems = []\n"
    findings = HungarianNotationRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_dunder_does_not_fire():
    src = "class C:\n    __init__ = None\n"
    findings = HungarianNotationRule().analyse(_unit(src), _ctx())
    # __init__ isn't Hungarian; should not fire
    assert findings == []


def test_private_with_hungarian_prefix_fires():
    src = "_i_count = 0\n"
    findings = HungarianNotationRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1


def test_unrelated_underscore_does_not_fire():
    # ``id_field`` is not Hungarian — id is the leading segment but not a type
    # prefix.
    src = "id_field = 0\n"
    findings = HungarianNotationRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_ann_assign_fires():
    src = "n_count: int = 0\n"
    findings = HungarianNotationRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1


def test_definition():
    d = HungarianNotationRule().definition()
    assert d.id == "naming.hungarian-notation"
    assert d.pillar.value == "naming"
