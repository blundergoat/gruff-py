from gruff.rule.test_quality.conditional_logic_rule import ConditionalLogicRule
from tests.unit.rule.test_quality._helpers import default_ctx, make_unit


def test_if_in_test_emits():
    src = "def test_foo():\n    if cond:\n        assert True\n"
    findings = ConditionalLogicRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_match_in_test_emits():
    src = "def test_foo():\n    match x:\n        case 1:\n            assert True\n"
    findings = ConditionalLogicRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_no_conditional_skipped():
    src = "def test_foo():\n    assert True\n"
    assert ConditionalLogicRule().analyse(make_unit(src), default_ctx()) == []


def test_one_finding_per_test():
    src = "def test_foo():\n    if a:\n        if b:\n            pass\n"
    findings = ConditionalLogicRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
