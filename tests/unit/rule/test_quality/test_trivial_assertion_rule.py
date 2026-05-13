from gruff.rule.test_quality.trivial_assertion_rule import TrivialAssertionRule
from tests.unit.rule.test_quality._helpers import default_ctx, make_unit


def test_assert_true_emits():
    src = "def test_foo():\n    assert True\n"
    findings = TrivialAssertionRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_assert_1_emits():
    src = "def test_foo():\n    assert 1\n"
    findings = TrivialAssertionRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_assert_not_false_emits():
    src = "def test_foo():\n    assert not False\n"
    findings = TrivialAssertionRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_assert_compare_constants_emits():
    src = "def test_foo():\n    assert 1 == 1\n"
    findings = TrivialAssertionRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_assert_actual_computation_skipped():
    src = "def test_foo():\n    x = compute()\n    assert x == 42\n"
    assert TrivialAssertionRule().analyse(make_unit(src), default_ctx()) == []
