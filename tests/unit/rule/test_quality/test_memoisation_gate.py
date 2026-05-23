"""Scope detection must run exactly once per AnalysisUnit per analyse run.

The helper MUST memoise across rules. This test diffs the ``compute_count``
counter before/after invoking the full registry on a single unit and asserts
the delta is 1, not N - proving every test-quality rule shares the cached scope.
"""

from gruffpy.rule.registry import RuleRegistry
from gruffpy.rule.test_quality._test_quality_node_helper import (
    compute_count,
    reset_compute_count,
)
from tests.unit.rule.test_quality._helpers import default_ctx, make_unit

_TEST_FIXTURE = """
def test_foo():
    assert 1 + 1 == 2


def test_bar():
    pass


class TestThings:
    def test_method(self):
        assert True


class MyTestCase:
    def testCamel(self):
        self.assertEqual(1, 1)
"""


def test_scope_computed_exactly_once_per_unit():
    reset_compute_count()
    unit = make_unit(_TEST_FIXTURE)
    registry = RuleRegistry.defaults()
    before = compute_count()
    registry.analyse([unit], default_ctx())
    after = compute_count()
    # Exactly one scope-map computation for this unit, regardless of how many
    # test-quality rules consumed it.
    assert after - before == 1, f"Expected 1 compute; saw {after - before}"


def test_scope_cache_persists_across_calls_for_same_tree():
    reset_compute_count()
    unit = make_unit(_TEST_FIXTURE)
    registry = RuleRegistry.defaults()
    registry.analyse([unit], default_ctx())
    first = compute_count()
    registry.analyse([unit], default_ctx())
    second = compute_count()
    # Same tree → cache hit; no additional computation.
    assert second == first, f"Cache miss across analyse calls: {first} -> {second}"
