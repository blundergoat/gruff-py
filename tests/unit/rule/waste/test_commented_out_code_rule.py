import ast

import pytest

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


def test_commented_if_fires():
    src = "# if enabled:\n"
    findings = CommentedOutCodeRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1


def test_commented_return_fires():
    src = "def f():\n    # return 1\n    return 0\n"
    findings = CommentedOutCodeRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1


def test_indented_real_comment_preserves_line_number():
    src = "def f():\n    x = 1\n    # value = call()\n    return x\n"
    findings = CommentedOutCodeRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].line == 3
    assert findings[0].metadata["preview"] == "value = call()"


def test_docstring_comment_looking_example_does_not_fire():
    src = 'def f():\n    """Example:\n    # array([0])\n    """\n    return 1\n'
    findings = CommentedOutCodeRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_markdown_code_fence_inside_docstring_does_not_fire():
    src = 'def f():\n    """Example:\n    ```python\n    # import os\n    ```\n    """\n    return 1\n'
    findings = CommentedOutCodeRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_string_literal_containing_comment_code_does_not_fire():
    src = 'example = "# import os"\n'
    findings = CommentedOutCodeRule().analyse(_unit(src), _ctx())
    assert findings == []


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


def test_comment_before_tokenizer_error_is_still_scanned():
    # Unbalanced paren raises TokenError at EOF; the comment tokenized before
    # the failure must still be scanned instead of discarding the whole file.
    src = "# total = compute_total()\nx = (\n"
    findings = CommentedOutCodeRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].line == 1


def test_task_marker_header_covers_its_whole_block():
    """Skip commented-out lines beneath a task-marker header, the pytest ``test_mark.py`` shape."""
    src = (
        "def test_keywords():\n"
        f"    # {_TASK_MARKER.lower()}: fixed\n"
        "    # keywords smear - expected behaviour\n"
        '    # reprec_keywords = pytester.inline_run("-k", "FOO")\n'
        "    # assert passed_k == 2\n"
        "    return None\n"
    )
    assert CommentedOutCodeRule().analyse(_unit(src), _ctx()) == []


def test_line_continuing_an_unfinished_prose_sentence_does_not_fire():
    """Skip a call reference that ends a sentence begun on the line above, the fastapi ``_compat/v2.py`` shape."""
    src = (
        "def dump_python(self, value):\n"
        "    # What calls this code passes a value that already called\n"
        "    # self._type_adapter.validate_python(value)\n"
        "    # but mypy complains about general str, although DefsRef is just str:\n"
        "    # DefsRef = NewType('DefsRef', str)\n"
        "    return value\n"
    )
    assert CommentedOutCodeRule().analyse(_unit(src), _ctx()) == []


def test_indented_snippets_under_an_example_cue_header_do_not_fire():
    """Skip quoted examples, the django ``compiler.py`` and pytest ini/toml shapes."""
    src = (
        "def get_group_by(self):\n"
        "    # Some examples:\n"
        "    #     SomeModel.objects.annotate(Count('somecol'))\n"
        "    #     GROUP BY: all fields of the model\n"
        "    #\n"
        "    #    SomeModel.objects.values('name').annotate(Count('somecol'))\n"
        "    #    GROUP BY: name\n"
        "    # str values arrive split differently. For example:\n"
        "    #\n"
        "    #   ini:\n"
        '    #     a_line_list = "tests acceptance"\n'
        "    #\n"
        "    # in this case, we need to split the string to obtain a list of strings.\n"
        "    #\n"
        "    #   toml (ini mode):\n"
        '    #     a_line_list = ["tests", "acceptance"]\n'
        "    return None\n"
    )
    assert CommentedOutCodeRule().analyse(_unit(src), _ctx()) == []


@pytest.mark.parametrize(
    "source",
    [
        "# Counting in the opposite direction works in conjunction with\n# distinct()\n",
        "# A case like\n# Restaurant.objects.filter(place=restaurant_instance), where\n# place is a OneToOneField.\n",
        "# Nested operation, trailing comma is handled in upper\n# OperationWriter._write()\n",
    ],
    ids=["sentence-stops-on-with", "sentence-stops-on-like", "reference-without-arguments"],
)
def test_expression_finishing_a_running_sentence_does_not_fire(source: str) -> None:
    """Skip the django ``many_to_one``, ``related_lookups`` and ``serializer.py`` sentence tails.

    Args:
        source: Comment block whose expression line completes the sentence above it.
    """
    assert CommentedOutCodeRule().analyse(_unit(source), _ctx()) == []


@pytest.mark.parametrize(
    ("source", "lines"),
    [
        (
            'def repr_locals(lines, name):\n    lines.append(name)\n    # else:\n    #    self._line("%-10s =" % (name,))\n    return lines\n',
            [4],
        ),
        (
            "# For local development\n"
            '# github_sponsors_path = Path("../docs/en/data/github_sponsors.yml")\n'
            'github_sponsors_path = Path("./docs/en/data/github_sponsors.yml")\n',
            [2],
        ),
        (
            "class VerboseNameField(models.Model):\n"
            "    # Don't want to depend on Pillow in this test\n"
            '    # field_image = models.ImageField("verbose field")\n'
            '    field11 = models.IntegerField("verbose field11")\n',
            [3],
        ),
        (
            "def test_load_only(self):\n"
            "    # prior to 1.0 we'd search in the result for this column\n"
            "    # self.sql_count_(0, go)\n"
            "    self.sql_count_(1, go)\n",
            [3],
        ),
        (
            "def test_collision(t1, t2):\n"
            "    # add_hash  has to be below 16 bits.\n"
            "    # eq_(\n"
            "    #     t1._anon_label('hi', add_hash=65537),\n"
            "    #     t2._anon_label('hi', add_hash=1)\n"
            "    # )\n"
            "    return None\n",
            [4, 5],
        ),
        (
            "# def _generate_columns_plus_names(\n"
            "#    self, anon_for_dupe_key: bool\n"
            "# ) -> List[Tuple[str, str, str, ColumnElement[Any], bool]]:\n"
            "#    return self.element._generate_columns_plus_names(anon_for_dupe_key)\n",
            [4],
        ),
    ],
    ids=[
        "keyword-fragment-above",
        "label-above-assignment",
        "remark-above-assignment",
        "finished-remark-above-call",
        "open-bracket-above-argument",
        "signature-close-above-return",
    ],
)
def test_code_under_a_non_introducing_line_still_fires(source: str, lines: list[int]) -> None:
    """Keep findings a looser prose test lost in pytest, fastapi, django and sqlalchemy.

    Args:
        source: Comment block whose code follows a keyword fragment, a finished remark, or an unclosed code line.
        lines: The lines that must still report.
    """
    findings = CommentedOutCodeRule().analyse(_unit(source), _ctx())
    assert [finding.line for finding in findings] == lines


def test_tombstoned_function_still_fires_per_line():
    """Keep reporting each code line of a function commented out without a prose or example header."""
    src = (
        "# def legacy_total(items):\n"
        "#     total = 0\n"
        "#     for item in items:\n"
        "#         total += item.price\n"
        "#     return total\n"
        "# To be enabled in the next major release.\n"
        '# warnings.filterwarnings("error", category=DeprecationWarning)\n'
        "# ---------------------------------------------\n"
        "# cache.clear()\n"
    )
    findings = CommentedOutCodeRule().analyse(_unit(src), _ctx())
    assert [finding.line for finding in findings] == [2, 3, 4, 5, 7, 9]


def test_tokenizer_indentation_error_does_not_crash():
    # The tokenizer raises IndentationError (not TokenError) on a bad dedent;
    # the rule runs on unparseable files, so this must not escape the rule.
    src = "def f():\n    pass\n  bad = 1\n# z = frob()\n"
    findings = CommentedOutCodeRule().analyse(_unit(src), _ctx())
    assert findings == []
