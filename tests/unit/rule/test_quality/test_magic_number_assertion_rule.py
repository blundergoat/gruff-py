from gruff.rule.test_quality.magic_number_assertion_rule import MagicNumberAssertionRule
from tests.unit.rule.test_quality._helpers import default_ctx, make_unit


def test_magic_number_emits():
    src = "def test_foo():\n    assert result == 17\n"
    findings = MagicNumberAssertionRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert 17 in findings[0].metadata["numbers"]


def test_http_status_skipped():
    src = "def test_foo():\n    assert response.status_code == 200\n"
    assert MagicNumberAssertionRule().analyse(make_unit(src), default_ctx()) == []


def test_zero_and_one_skipped():
    src = "def test_foo():\n    assert count == 0\n    assert other == 1\n"
    assert MagicNumberAssertionRule().analyse(make_unit(src), default_ctx()) == []


def test_named_constant_skipped():
    src = "MAX = 42\ndef test_foo():\n    assert result == MAX\n"
    assert MagicNumberAssertionRule().analyse(make_unit(src), default_ctx()) == []
