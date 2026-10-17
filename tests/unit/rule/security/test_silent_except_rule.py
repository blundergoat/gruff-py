import pytest

from gruffpy.rule.security.silent_except_rule import SilentExceptRule
from tests.unit.rule.security._helpers import default_ctx, make_unit


def test_bare_except_pass_emits():
    src = "try:\n    x = 1\nexcept:\n    pass\n"
    findings = SilentExceptRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_except_exception_pass_emits():
    src = "try:\n    x = 1\nexcept Exception:\n    pass\n"
    findings = SilentExceptRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_except_ellipsis_emits():
    src = "try:\n    x = 1\nexcept Exception:\n    ...\n"
    findings = SilentExceptRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_specific_exception_skipped():
    src = "try:\n    x = 1\nexcept KeyError:\n    pass\n"
    assert SilentExceptRule().analyse(make_unit(src), default_ctx()) == []


def test_except_with_logging_skipped():
    src = "import logging\nlogger = logging.getLogger(__name__)\ntry:\n    x = 1\nexcept Exception:\n    logger.exception('oops')\n    pass\n"
    # Note: body is not pass-only when logger.exception precedes pass, so rule doesn't fire.
    assert SilentExceptRule().analyse(make_unit(src), default_ctx()) == []


@pytest.mark.parametrize(
    "source",
    [
        "try:\n    value = loads(value)\nexcept Exception:\n    # Keep the value as a string if loading failed.\n    pass\n",
        (
            "try:\n    return_value = signing.loads(session_data)\nexcept Exception:\n"
            "    # ValueError, unpickling exceptions. If any of these happen, just\n"
            "    # return an empty dictionary (an empty session).\n    pass\n"
        ),
        (
            "try:\n    conn.close()\nexcept Exception:\n"
            "    # pysqlite won't even let you close a conn from a thread\n"
            "    # that didn't create it\n    pass\n"
        ),
    ],
    ids=["flask-string-fallback", "django-empty-session", "sqlalchemy-thread-cleanup"],
)
def test_documented_corpus_fallback_skipped(source):
    assert SilentExceptRule().analyse(make_unit(source), default_ctx()) == []


@pytest.mark.parametrize(
    "comment",
    [
        "ignore",
        "ignore if error",
        f"{''.join(('TO', 'DO'))}: Keep the value as a string if loading failed.",
        "value = loads(value) if loading_failed else value",
        "if loading_failed:",
    ],
    ids=["stock-phrase", "condition-without-reason", "unfinished-handling", "disabled-assignment", "disabled-compound-header"],
)
def test_comment_without_explanation_still_reports(comment):
    source = f"try:\n    value = loads(value)\nexcept Exception:\n    # {comment}\n    pass\n"
    assert len(SilentExceptRule().analyse(make_unit(source), default_ctx())) == 1


def test_comment_text_inside_string_does_not_explain_handler():
    source = 'reason = "# Keep the value as a string if loading failed."\ntry:\n    value = loads(value)\nexcept Exception:\n    pass\n'
    assert len(SilentExceptRule().analyse(make_unit(source), default_ctx())) == 1


def test_explanation_does_not_belong_to_later_handler():
    source = (
        "try:\n    value = loads(value)\nexcept Exception:\n"
        "    # Keep the value as a string if loading failed.\n    pass\n"
        "try:\n    value = loads(value)\nexcept Exception:\n    pass\n"
    )
    findings = SilentExceptRule().analyse(make_unit(source), default_ctx())
    assert len(findings) == 1
    assert findings[0].line == 8
