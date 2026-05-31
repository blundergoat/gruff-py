import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.waste.commented_out_code_rule import CommentedOutCodeRule
from gruffpy.source.source_file import SourceFile

_TASK_MARKER = "".join(("TO", "DO"))


def _unit(source: str) -> AnalysisUnit:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        tree = None
    return AnalysisUnit(
        file=SourceFile(absolute_path="/x.py", display_path="x.py", type="python"),
        source=source,
        tree=tree,
    )


def _ctx() -> RuleContext:
    rule = CommentedOutCodeRule()
    return RuleContext(
        project_root="/",
        config=AnalysisConfig(rules={rule.definition().id: RuleSettings(enabled=True)}),
    )


def test_commented_assignment_fires():
    src = "# x = 1\n"
    findings = CommentedOutCodeRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["preview"] == "x = 1"


def test_commented_call_fires():
    src = "# print(x)\n"
    findings = CommentedOutCodeRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1


def test_commented_import_fires():
    src = "# import os\n"
    findings = CommentedOutCodeRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1


def test_commented_return_fires():
    src = "def f():\n    # return 1\n    return 0\n"
    findings = CommentedOutCodeRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1


def test_english_comment_does_not_fire():
    src = "# This function does something important.\n"
    findings = CommentedOutCodeRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_todo_comment_does_not_fire():
    src = f"# {_TASK_MARKER}: x = 1\n"
    findings = CommentedOutCodeRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_type_comment_does_not_fire():
    src = "# type: ignore\n"
    findings = CommentedOutCodeRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_noqa_comment_does_not_fire():
    src = "x = 1  # noqa\n"
    findings = CommentedOutCodeRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_shebang_does_not_fire():
    src = "#!/usr/bin/env python\n"
    findings = CommentedOutCodeRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_coding_declaration_does_not_fire():
    src = "# -*- coding: utf-8 -*-\n"
    findings = CommentedOutCodeRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_dash_separator_does_not_fire():
    src = "# ------------------------------\n"
    findings = CommentedOutCodeRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_equals_separator_does_not_fire():
    src = "# ==============================\n"
    findings = CommentedOutCodeRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_prose_starting_with_keyword_does_not_fire():
    # Trips the code-like pre-filter (`return`) but fails `ast.parse`, so the
    # second stage is what keeps prose from firing - not the pre-filter alone.
    src = "# return the widget to the pool when the caller is done\n"
    findings = CommentedOutCodeRule().analyse(_unit(src), _ctx())
    assert findings == []
