"""Cumulative fixture exercising the mock + lifecycle test-quality rules.

Plants patterns for the high-confidence rules and asserts each fires once.
Also re-checks the memoisation invariant after the full test-quality rule set
is layered onto the helper - single scope computation per unit.
"""

from gruffpy.rule.registry import RuleRegistry
from gruffpy.rule.test_quality._test_quality_node_helper import (
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

_EXPECTED_MOCK_LIFECYCLE_FIRES = {
    "test-quality.empty-parametrize",
    "test-quality.unused-mock",
    "test-quality.private-reflection",
    "test-quality.exception-type-only",
    "test-quality.tautological-type-assertion",
    "test-quality.extends-production-class",
    "test-quality.global-state-mutation",
}


def test_mock_lifecycle_rules_fire_on_cumulative_fixture():
    findings = RuleRegistry.defaults().analyse([make_unit(_FIXTURE)], default_ctx())
    fired = {f.rule_id for f in findings}
    missing = _EXPECTED_MOCK_LIFECYCLE_FIRES - fired
    assert not missing, f"Missing fires: {sorted(missing)}"


def test_memoisation_invariant_holds_for_full_pillar():
    """Single scope computation per unit even with mock-aware rules in the registry."""
    reset_compute_count()
    unit = make_unit(_FIXTURE)
    before = compute_count()
    RuleRegistry.defaults().analyse([unit], default_ctx())
    after = compute_count()
    # One compute regardless of how many test-quality rules consumed the scope.
    assert after - before == 1, f"Memoisation broken: {after - before} computes"


# Floor for v0.1: 28 default-on test-quality rules. The full catalogue ships 34.
_MIN_TEST_QUALITY_RULE_COUNT = 28


def test_registry_has_full_test_quality_rule_set():
    """v0.1 ships at least 28 default-on test-quality rules; the full set is 34."""
    ids = {
        r.definition().id
        for r in RuleRegistry.defaults().all()
        if r.definition().id.startswith("test-quality.")
    }
    assert len(ids) >= _MIN_TEST_QUALITY_RULE_COUNT, (
        f"Expected ≥{_MIN_TEST_QUALITY_RULE_COUNT} test-quality rules; got "
        f"{len(ids)}: {sorted(ids)}"
    )
