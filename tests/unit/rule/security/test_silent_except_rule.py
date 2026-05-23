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
    src = (
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "try:\n    x = 1\nexcept Exception:\n    logger.exception('oops')\n    pass\n"
    )
    # Note: body is not pass-only when logger.exception precedes pass, so rule doesn't fire.
    assert SilentExceptRule().analyse(make_unit(src), default_ctx()) == []
