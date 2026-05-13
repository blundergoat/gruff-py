from gruff.rule.security.error_suppression_rule import ErrorSuppressionRule
from tests.unit.rule.security._helpers import default_ctx, make_unit


def test_contextlib_suppress_exception_emits():
    src = "from contextlib import suppress\nwith suppress(Exception):\n    do_thing()\n"
    findings = ErrorSuppressionRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_contextlib_suppress_specific_skipped():
    src = "from contextlib import suppress\nwith suppress(KeyError):\n    do_thing()\n"
    assert ErrorSuppressionRule().analyse(make_unit(src), default_ctx()) == []


def test_tuple_with_exception_emits():
    src = "try:\n    x = 1\nexcept (KeyError, Exception):\n    handle()\n"
    findings = ErrorSuppressionRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_tuple_of_specific_skipped():
    src = "try:\n    x = 1\nexcept (KeyError, ValueError):\n    handle()\n"
    assert ErrorSuppressionRule().analyse(make_unit(src), default_ctx()) == []
