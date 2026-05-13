"""Tests for project-config rules + opt-in test-quality heuristics + gating."""

from pathlib import Path

from gruff.config.analysis_config import AnalysisConfig
from gruff.config.rule_settings import RuleSettings
from gruff.rule.context import RuleContext
from gruff.rule.registry import RuleRegistry
from gruff.rule.test_quality._pytest_config import reset_cache
from gruff.rule.test_quality.multiple_aaa_cycles_rule import MultipleAaaCyclesRule
from gruff.rule.test_quality.pytest_coverage_source_missing_rule import (
    PytestCoverageSourceMissingRule,
)
from gruff.rule.test_quality.pytest_deprecations_not_fatal_rule import (
    PytestDeprecationsNotFatalRule,
)
from gruff.rule.test_quality.pytest_strict_config_missing_rule import (
    PytestStrictConfigMissingRule,
)
from gruff.rule.test_quality.testdox_readability_rule import TestdoxReadabilityRule
from tests.unit.rule.test_quality._helpers import make_unit

_TEST_FIXTURE = "def test_something():\n    assert 1 + 1 == 2\n"
_NON_TEST_FIXTURE = "def helper():\n    return 1\n"


def _ctx_with_pyproject(tmp_path: Path, contents: str) -> RuleContext:
    (tmp_path / "pyproject.toml").write_text(contents)
    reset_cache()
    return RuleContext(
        project_root=str(tmp_path),
        config=AnalysisConfig.from_registry(RuleRegistry.defaults()),
    )


def test_strict_config_missing_emits_when_pytest_block_lacks_flags(tmp_path: Path):
    ctx = _ctx_with_pyproject(
        tmp_path,
        "[tool.pytest.ini_options]\naddopts = '-ra -q'\n",
    )
    findings = PytestStrictConfigMissingRule().analyse(make_unit(_TEST_FIXTURE), ctx)
    assert len(findings) == 1


def test_strict_config_present_skips(tmp_path: Path):
    ctx = _ctx_with_pyproject(
        tmp_path,
        '[tool.pytest.ini_options]\naddopts = "--strict-config --strict-markers"\n',
    )
    assert PytestStrictConfigMissingRule().analyse(make_unit(_TEST_FIXTURE), ctx) == []


def test_strict_config_rule_skipped_on_non_test_unit(tmp_path: Path):
    """Project-config rules must not fire on non-test units — gating regression."""
    ctx = _ctx_with_pyproject(
        tmp_path,
        "[tool.pytest.ini_options]\naddopts = '-ra'\n",
    )
    assert PytestStrictConfigMissingRule().analyse(make_unit(_NON_TEST_FIXTURE), ctx) == []


def test_deprecations_not_fatal_emits_when_filterwarnings_silent(tmp_path: Path):
    ctx = _ctx_with_pyproject(
        tmp_path,
        "[tool.pytest.ini_options]\naddopts = '--strict-config'\n",
    )
    findings = PytestDeprecationsNotFatalRule().analyse(make_unit(_TEST_FIXTURE), ctx)
    assert len(findings) == 1


def test_deprecations_not_fatal_skipped_with_filterwarnings(tmp_path: Path):
    ctx = _ctx_with_pyproject(
        tmp_path,
        ('[tool.pytest.ini_options]\nfilterwarnings = ["error::DeprecationWarning"]\n'),
    )
    assert PytestDeprecationsNotFatalRule().analyse(make_unit(_TEST_FIXTURE), ctx) == []


def test_coverage_source_missing_emits(tmp_path: Path):
    ctx = _ctx_with_pyproject(
        tmp_path,
        "[tool.pytest.ini_options]\naddopts = '-q'\n",
    )
    findings = PytestCoverageSourceMissingRule().analyse(make_unit(_TEST_FIXTURE), ctx)
    assert len(findings) == 1


def test_coverage_source_present_skips(tmp_path: Path):
    ctx = _ctx_with_pyproject(
        tmp_path,
        '[tool.coverage.run]\nsource = ["my_package"]\n',
    )
    assert PytestCoverageSourceMissingRule().analyse(make_unit(_TEST_FIXTURE), ctx) == []


def test_opt_in_rules_default_off():
    """The opt-in test-quality rules must default to enabled=False."""
    for rule_cls in (MultipleAaaCyclesRule, TestdoxReadabilityRule):
        assert rule_cls().definition().default_enabled is False


def test_multiple_aaa_cycles_requires_opt_in(tmp_path: Path):
    """Default-off rules don't fire through the registry unless explicitly enabled."""
    config = AnalysisConfig.from_registry(RuleRegistry.defaults())
    # Verify the rule is in defaults() but its settings.enabled is False.
    settings = config.rule_settings(MultipleAaaCyclesRule.ID)
    assert settings.enabled is False


def test_multiple_aaa_cycles_fires_when_enabled(tmp_path: Path):
    """When opted in, the rule does fire on multi-cycle tests."""
    rule = MultipleAaaCyclesRule()
    config = AnalysisConfig(
        rules={
            rule.definition().id: RuleSettings(enabled=True, thresholds={"warning": 1}),
        }
    )
    ctx = RuleContext(project_root=str(tmp_path), config=config)
    src = (
        "def test_x():\n"
        "    x = 1\n"
        "    assert x == 1\n"
        "    y = 2\n"
        "    assert y == 2\n"
        "    z = 3\n"
        "    assert z == 3\n"
    )
    findings = rule.analyse(make_unit(src), ctx)
    assert len(findings) == 1
    assert findings[0].metadata["cycles"] >= 2


def test_testdox_readability_skipped_when_default(tmp_path: Path):
    """testdox-readability is default-off; even short test names don't fire by default."""
    rule = TestdoxReadabilityRule()
    registry = RuleRegistry.defaults()
    config = AnalysisConfig.from_registry(registry)
    ctx = RuleContext(project_root=str(tmp_path), config=config)
    # Default-off rule must NOT appear in any finding produced by the full registry.
    findings = registry.analyse([make_unit("def test_x():\n    pass\n")], ctx)
    assert all(f.rule_id != rule.definition().id for f in findings)
