"""Cumulative M09b fixture exercising the mock/lifecycle rules.

Plants patterns for the high-confidence rules and asserts each fires once.
Also confirms the memoisation gate (M09a invariant) still holds after layering
18 more rules on the helper.
"""

from gruff.rule.registry import RuleRegistry
from gruff.rule.test_quality._test_quality_node_helper import (
    compute_count,
    reset_compute_count,
)
from tests.unit.rule.test_quality._helpers import default_ctx, make_unit

_FIXTURE = """import pytest
from unittest.mock import Mock


@pytest.mark.parametrize("x", [])
def test_empty_cases(x):
    assert True


def test_unused_mock():
    m = Mock()
    assert 1 + 1 == 2


def test_private_reflection():
    assert obj._secret == 1


def test_wide_exception():
    with pytest.raises(Exception):
        do_thing()


def test_tautology():
    assert isinstance(x, type(x))


class TestProduction(Service):
    def test_x(self):
        assert True


def test_global():
    global y
    y = 1
    assert y == 1
"""

_EXPECTED_M09B_FIRES = {
    "test-quality.empty-parametrize",
    "test-quality.unused-mock",
    "test-quality.private-reflection",
    "test-quality.exception-type-only",
    "test-quality.tautological-type-assertion",
    "test-quality.extends-production-class",
    "test-quality.global-state-mutation",
}


def test_m09b_rules_fire_on_cumulative_fixture():
    findings = RuleRegistry.defaults().analyse([make_unit(_FIXTURE)], default_ctx())
    fired = {f.rule_id for f in findings}
    missing = _EXPECTED_M09B_FIRES - fired
    assert not missing, f"Missing M09b fires: {sorted(missing)}"


def test_memoisation_gate_still_holds_after_m09b():
    """The M09a memoisation invariant must survive the M09b helper extension."""
    reset_compute_count()
    unit = make_unit(_FIXTURE)
    before = compute_count()
    RuleRegistry.defaults().analyse([unit], default_ctx())
    after = compute_count()
    # One compute regardless of how many test-quality rules consumed the scope.
    assert after - before == 1, f"Memoisation broken: {after - before} computes"


def test_registry_has_28_test_quality_rules():
    ids = {
        r.definition().id
        for r in RuleRegistry.defaults().all()
        if r.definition().id.startswith("test-quality.")
    }
    assert len(ids) == 28, f"Expected 28 test-quality rules; got {len(ids)}: {sorted(ids)}"
