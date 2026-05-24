"""Tests for project-config rules and test-quality heuristic gating."""

from pathlib import Path

import pytest

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.rule.context import RuleContext
from gruffpy.rule.registry import RuleRegistry
from gruffpy.rule.test_quality._pytest_config import reset_cache
from gruffpy.rule.test_quality.mocking_domain_object_rule import MockingDomainObjectRule
from gruffpy.rule.test_quality.multiple_aaa_cycles_rule import MultipleAaaCyclesRule
from gruffpy.rule.test_quality.pytest_coverage_source_missing_rule import (
    PytestCoverageSourceMissingRule,
)
from gruffpy.rule.test_quality.pytest_deprecations_not_fatal_rule import (
    PytestDeprecationsNotFatalRule,
)
from gruffpy.rule.test_quality.pytest_strict_config_missing_rule import (
    PytestStrictConfigMissingRule,
)
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
    assert findings[0].file_path == "pyproject.toml"


def test_strict_config_present_skips(tmp_path: Path):
    ctx = _ctx_with_pyproject(
        tmp_path,
        '[tool.pytest.ini_options]\naddopts = "--strict-config --strict-markers"\n',
    )
    assert PytestStrictConfigMissingRule().analyse(make_unit(_TEST_FIXTURE), ctx) == []


def test_strict_config_rule_skipped_on_non_test_unit(tmp_path: Path):
    """Project-config rules must not fire on non-test units - gating regression.

    Args:
        tmp_path: Pytest-provided per-test directory holding the synthetic ``pyproject.toml``.
    """
    ctx = _ctx_with_pyproject(
        tmp_path,
        "[tool.pytest.ini_options]\naddopts = '-ra'\n",
    )
    assert PytestStrictConfigMissingRule().analyse(make_unit(_NON_TEST_FIXTURE), ctx) == []


def test_all_project_config_rules_skip_non_test_units(tmp_path: Path):
    ctx = _ctx_with_pyproject(
        tmp_path,
        "[tool.pytest.ini_options]\naddopts = '-ra'\n",
    )
    unit = make_unit(_NON_TEST_FIXTURE)

    assert PytestStrictConfigMissingRule().analyse(unit, ctx) == []
    assert PytestDeprecationsNotFatalRule().analyse(unit, ctx) == []
    assert PytestCoverageSourceMissingRule().analyse(unit, ctx) == []


def test_deprecations_not_fatal_emits_when_filterwarnings_silent(tmp_path: Path):
    ctx = _ctx_with_pyproject(
        tmp_path,
        "[tool.pytest.ini_options]\naddopts = '--strict-config'\n",
    )
    findings = PytestDeprecationsNotFatalRule().analyse(make_unit(_TEST_FIXTURE), ctx)
    assert len(findings) == 1
    assert findings[0].file_path == "pyproject.toml"


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
    assert findings[0].file_path == "pyproject.toml"


def test_project_config_rules_skip_when_pyproject_has_no_pytest_config(tmp_path: Path):
    ctx = _ctx_with_pyproject(
        tmp_path,
        '[tool.coverage.run]\nsource = ["my_package"]\n',
    )
    unit = make_unit(_TEST_FIXTURE)

    assert PytestStrictConfigMissingRule().analyse(unit, ctx) == []
    assert PytestDeprecationsNotFatalRule().analyse(unit, ctx) == []
    assert PytestCoverageSourceMissingRule().analyse(unit, ctx) == []


def test_coverage_source_present_skips(tmp_path: Path):
    ctx = _ctx_with_pyproject(
        tmp_path,
        '[tool.coverage.run]\nsource = ["my_package"]\n',
    )
    assert PytestCoverageSourceMissingRule().analyse(make_unit(_TEST_FIXTURE), ctx) == []


@pytest.mark.parametrize(
    "rule_cls",
    [MockingDomainObjectRule, MultipleAaaCyclesRule],
    ids=lambda c: c.__name__,
)
def test_test_quality_rules_default_on(rule_cls: type) -> None:
    """The test-quality rules must default to enabled=True.

    Args:
        rule_cls: Rule class expected to ship with ``default_enabled=True``.
    """
    assert rule_cls().definition().default_enabled is True


def test_multiple_aaa_cycles_enabled_by_default():
    """Default config keeps multiple-AAA-cycles enabled in the registry."""
    config = AnalysisConfig.from_registry(RuleRegistry.defaults())
    settings = config.rule_settings(MultipleAaaCyclesRule.ID)
    assert settings.enabled is True


def test_multiple_aaa_cycles_fires_when_configured(tmp_path: Path):
    """The rule fires on multi-cycle tests when its threshold is tight.

    Args:
        tmp_path: Pytest-provided per-test directory used as the project root.
    """
    rule = MultipleAaaCyclesRule()
    config = AnalysisConfig(
        rules={
            rule.definition().id: RuleSettings(enabled=True, thresholds={"maxCycles": 1}),
        }
    )
    ctx = RuleContext(project_root=str(tmp_path), config=config)
    src = (
        "def test_x():\n"
        "    x = compute()\n"
        "    assert x == 1\n"
        "    y = compute()\n"
        "    assert y == 2\n"
        "    z = compute()\n"
        "    assert z == 3\n"
    )
    findings = rule.analyse(make_unit(src), ctx)
    assert len(findings) == 1
    assert findings[0].metadata["cycles"] >= 2
