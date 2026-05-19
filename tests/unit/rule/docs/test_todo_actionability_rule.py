from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.rule.context import RuleContext
from gruffpy.rule.docs.todo_actionability_rule import TodoActionabilityRule
from tests.unit.rule.docs._helpers import default_ctx, make_unit


def _marker(*parts: str) -> str:
    return "".join(parts)


def test_vague_todo_emits():
    marker = _marker("TO", "DO")
    src = f"# {marker}: fix later\nvalue = 1\n"

    findings = TodoActionabilityRule().analyse(make_unit(src), default_ctx())

    assert len(findings) == 1
    assert findings[0].metadata == {
        "marker": "TODO",
        "comment": "fix later",
        "hasIssue": False,
        "hasOwner": False,
    }


def test_issue_reference_is_actionable():
    marker = _marker("TO", "DO")
    src = f"# {marker}(#123): remove fallback after parser migration\nvalue = 1\n"

    assert TodoActionabilityRule().analyse(make_unit(src), default_ctx()) == []


def test_owner_reference_is_actionable():
    marker = _marker("FIX", "ME")
    src = f"# {marker} @alice: preserve py311 path until downstream pins py312\nvalue = 1\n"

    assert TodoActionabilityRule().analyse(make_unit(src), default_ctx()) == []


def test_detailed_imperative_action_is_actionable():
    marker = _marker("HAC", "K")
    src = f"# {marker}: keep raw ast nodes because source spans are required\nvalue = 1\n"

    assert TodoActionabilityRule().analyse(make_unit(src), default_ctx()) == []


def test_require_issue_or_owner_rejects_plain_action():
    marker = _marker("HAC", "K")
    src = f"# {marker}: keep raw ast nodes because source spans are required\nvalue = 1\n"
    rule = TodoActionabilityRule()
    ctx = RuleContext(
        project_root="/",
        config=AnalysisConfig(
            rules={
                rule.definition().id: RuleSettings(
                    options={
                        "markers": ["TODO", "FIXME", "HACK"],
                        "require_issue_or_owner": True,
                        "minimum_detail_words": 5,
                    },
                )
            }
        ),
    )

    findings = rule.analyse(make_unit(src), ctx)

    assert len(findings) == 1


def test_marker_inside_string_literal_is_skipped():
    marker = _marker("TO", "DO")
    src = f"text = '# {marker}: fix later'\n"

    assert TodoActionabilityRule().analyse(make_unit(src), default_ctx()) == []
