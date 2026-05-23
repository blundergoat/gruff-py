from gruffpy.rule.test_quality.tautological_type_assertion_rule import (
    TautologicalTypeAssertionRule,
)
from tests.unit.rule.test_quality._helpers import default_ctx, make_unit


def test_isinstance_type_same_expression_emits():
    src = "def test_value():\n    value = object()\n    assert isinstance(value, type(value))\n"
    findings = TautologicalTypeAssertionRule().analyse(make_unit(src), default_ctx())

    assert len(findings) == 1
    assert findings[0].rule_id == "test-quality.tautological-type-assertion"


def test_same_method_call_on_different_receivers_is_not_tautological():
    src = (
        "def test_value():\n"
        "    a = make_a()\n"
        "    b = make_b()\n"
        "    assert a.fingerprint() == b.fingerprint()\n"
    )

    assert TautologicalTypeAssertionRule().analyse(make_unit(src), default_ctx()) == []
