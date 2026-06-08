"""Cumulative full-pillar fixture for every test-quality rule."""

from collections import Counter
from pathlib import Path

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.rule.context import RuleContext
from gruffpy.rule.registry import RuleRegistry
from gruffpy.rule.test_quality._pytest_config import reset_cache
from tests.unit.rule.test_quality._helpers import make_unit

_EXPECTED_COUNTS = {
    "test-quality.conditional-logic": 1,
    "test-quality.eager-test": 2,
    "test-quality.empty-parametrize": 1,
    "test-quality.exception-type-only": 1,
    "test-quality.excessive-mocking": 1,
    "test-quality.extends-production-class": 1,
    "test-quality.global-state-mutation": 1,
    "test-quality.loop-assertion-without-message": 1,
    "test-quality.loop-in-test": 2,
    "test-quality.magic-number-assertion": 1,
    "test-quality.mock-only-test": 1,
    "test-quality.mock-without-expectation": 2,
    "test-quality.mocking-domain-object": 1,
    "test-quality.multiple-aaa-cycles": 1,
    "test-quality.mystery-guest": 1,
    "test-quality.naming-consistency": 1,
    "test-quality.no-assertions": 1,
    "test-quality.parametrize-annotation": 1,
    "test-quality.private-reflection": 1,
    "test-quality.pytest-coverage-source-missing": 1,
    "test-quality.pytest-deprecations-not-fatal": 1,
    "test-quality.pytest-strict-config-missing": 1,
    "test-quality.repeated-structure-missing-parametrize": 3,
    "test-quality.setup-bloat": 1,
    "test-quality.skipped-without-reason": 1,
    "test-quality.sleep-in-test": 1,
    "test-quality.static-analysis-redundant-test": 1,
    "test-quality.sut-not-called": 1,
    "test-quality.tautological-type-assertion": 1,
    "test-quality.test-function-too-long": 1,
    "test-quality.test-longer-than-sut": 1,
    "test-quality.trivial-assertion": 1,
    "test-quality.trivial-snapshot": 1,
    "test-quality.unused-mock": 1,
}


def test_full_pillar_fixture_exercises_every_test_quality_rule(tmp_path: Path):
    registry = RuleRegistry.defaults()
    ctx = _ctx_with_opt_in_rules(tmp_path, registry)
    findings = registry.analyse(
        [make_unit(_full_pillar_source(), "tests/test_full_pillar.py")],
        ctx,
    )

    counts = Counter(
        finding.rule_id for finding in findings if finding.rule_id.startswith("test-quality.")
    )

    assert counts == _EXPECTED_COUNTS
    assert set(counts) == {
        rule.definition().id
        for rule in registry.all()
        if rule.definition().id.startswith("test-quality.")
    }


def _ctx_with_opt_in_rules(tmp_path: Path, registry: RuleRegistry) -> RuleContext:
    (tmp_path / "pyproject.toml").write_text(
        '[tool.pytest.ini_options]\naddopts = "-q"\n',
    )
    reset_cache()
    config = AnalysisConfig.from_registry(registry)
    for rule_id, options in {
        "test-quality.mocking-domain-object": {"domain_namespaces": ["billing"]},
        "test-quality.multiple-aaa-cycles": {},
    }.items():
        settings = config.rule_settings(rule_id)
        config = config.with_rule_settings(
            rule_id,
            RuleSettings(
                enabled=True,
                thresholds=dict(settings.thresholds),
                options={**dict(settings.options), **options},
            ),
        )
    return RuleContext(project_root=str(tmp_path), config=config)


def _full_pillar_source() -> str:
    setup_body = "".join("    value += 1\n" for _ in range(31))
    long_test_body = "".join("    step = 1\n" for _ in range(101))
    return _FULL_PILLAR_SOURCE.format(
        setup_body=setup_body,
        long_test_body=long_test_body,
    )


_FULL_PILLAR_SOURCE = """import pytest
import time
from unittest.mock import Mock


class Service:
    pass


class billing:
    class Invoice:
        pass


def exercise(value=1):
    return value


def tiny_sut():
    value = 1
    value += 1
    value += 1
    value += 1
    value -= 1
    return value


def test_conditional_logic_branch_case():
    result = exercise()
    if result:
        assert result == 1


def test_eager_asserts_many_values():
    value = exercise()
    assert value == 1
    assert value == 1
    assert value == 1
    assert value == 1
    assert value == 1
    assert value == 1


@pytest.mark.parametrize("value", [])
def test_empty_parametrize_cases_are_rejected(value):
    assert exercise(value) == value


def test_wide_exception_without_match():
    with pytest.raises(Exception):
        exercise()


def test_excessive_mocking_with_many_doubles():
    a = Mock()
    b = Mock()
    c = Mock()
    d = Mock()
    e = Mock()
    exercise()
    a.assert_not_called()
    b.assert_not_called()
    c.assert_not_called()
    d.assert_not_called()
    e.assert_not_called()
    assert a is not None


class TestProduction(Service):
    def test_extends_production_class_case(self):
        assert exercise() == 1


def test_global_state_mutation_case():
    global shared_value
    shared_value = exercise()
    assert shared_value == 1


def test_loop_assertion_without_message_case():
    for value in [1, 1]:
        assert value
    exercise()


def test_loop_in_test_case():
    total = 0
    for value in [1, 1]:
        total += value
    assert exercise(total) == total


def test_magic_number_assertion_case():
    value = exercise(42)
    assert value == 42


def test_mock_only_interaction_case():
    collaborator = Mock()
    collaborator.run()
    collaborator.run.assert_called_once()


def test_mock_without_expectation_case():
    collaborator = Mock()
    exercise(collaborator)
    assert collaborator is not None


def test_mocking_domain_object_case():
    invoice = Mock(spec=billing.Invoice)
    exercise(invoice)
    invoice.assert_not_called()
    assert invoice is not None


def test_multiple_aaa_cycles_case():
    first = exercise()
    assert first == 1
    second = exercise()
    assert second == 1
    third = exercise()
    assert third == 1


def test_mystery_guest_external_file_case():
    data = open("/tmp/example.txt").read()
    assert exercise(data) == data


def test_contains_no_assertions_case():
    exercise()


@pytest.mark.parametrize("value", [1, 1, 1])
def test_parametrize_without_case_ids(value):
    assert exercise(value) == value


def test_private_reflection_case_is_detected():
    subject = exercise()
    assert subject._secret == 1


def test_repeated_structure_alpha_case():
    assert exercise(1) == 1


def test_repeated_structure_beta_case():
    assert exercise(1) == 1


def test_repeated_structure_gamma_case():
    assert exercise(1) == 1


def setup_method(self):
    value = 1
{setup_body}    return value


@pytest.mark.skip
def test_skipped_without_reason_case():
    assert exercise() == 1


def test_sleep_in_test_case():
    time.sleep(1)
    assert exercise() == 1


def test_system_under_test_not_called_case():
    assert len([1]) == 1


def test_tautological_type_assertion_case():
    value = exercise()
    assert isinstance(value, type(value))


def test_function_too_long_case():
{long_test_body}    assert exercise() == 1


def test_tiny_sut():
    a = exercise()
    b = exercise()
    c = exercise()
    d = exercise()
    e = exercise()
    f = exercise()
    g = exercise()
    h = exercise()
    i = exercise()
    j = exercise()
    k = exercise()
    l = exercise()
    m = exercise()
    assert tiny_sut() == 1


def test_x():
    assert exercise() == 1


def test_trivial_assertion_case_is_detected():
    exercise()
    assert True


def test_trivial_snapshot_case_is_detected():
    assert exercise() == ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"]


def test_unused_mock_case_is_detected():
    unused = Mock()
    assert exercise() == 1


def testCamelCaseExample():
    assert exercise() == 1


class RedundantFact:
    def render(self):
        return "shape"


def test_static_analysis_redundant_case():
    exercise()
    assert hasattr(RedundantFact, "render")
"""
