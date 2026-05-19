from gruffpy.rule.docs.ignore_directive_reason_rule import IgnoreDirectiveReasonRule
from tests.unit.rule.docs._helpers import default_ctx, make_unit


def test_noqa_without_reason_emits():
    src = "import os  # noqa\n"

    findings = IgnoreDirectiveReasonRule().analyse(make_unit(src), default_ctx())

    assert len(findings) == 1
    assert findings[0].metadata == {"directive": "noqa", "reasonPresent": False, "reason": ""}


def test_noqa_with_substantive_reason_is_skipped():
    src = "from package import name  # noqa: F401 - re-exported public API\n"

    assert IgnoreDirectiveReasonRule().analyse(make_unit(src), default_ctx()) == []


def test_type_ignore_with_generic_reason_still_emits():
    src = "value = plugin.attr  # type: ignore[attr-defined]  # ignore\n"

    findings = IgnoreDirectiveReasonRule().analyse(make_unit(src), default_ctx())

    assert len(findings) == 1
    assert findings[0].metadata["directive"] == "type: ignore[attr-defined]"
    assert findings[0].metadata["reasonPresent"] is True
    assert findings[0].metadata["reason"] == "ignore"


def test_pragma_no_cover_with_double_dash_reason_is_skipped():
    src = "if __name__ == '__main__':  # pragma: no cover -- subprocess smoke only\n    pass\n"

    assert IgnoreDirectiveReasonRule().analyse(make_unit(src), default_ctx()) == []


def test_gruff_disable_without_reason_emits():
    src = "# gruff: disable=docs.missing-function-docstring\n"

    findings = IgnoreDirectiveReasonRule().analyse(make_unit(src), default_ctx())

    assert len(findings) == 1
    assert findings[0].metadata["directive"] == "gruff: disable=docs.missing-function-docstring"


def test_directive_inside_string_literal_is_skipped():
    src = "text = '# noqa'\n"

    assert IgnoreDirectiveReasonRule().analyse(make_unit(src), default_ctx()) == []
