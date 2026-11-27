"""Tests for the ``failOn:`` config block and ``schemaVersion`` gate (ADR-019)."""

from pathlib import Path

import pytest

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.exceptions import ConfigError
from gruffpy.config.loader import ConfigLoader
from gruffpy.finding.fail_threshold import FailThreshold
from gruffpy.rule.registry import RuleRegistry


def _defaults() -> AnalysisConfig:
    """Build the analysis config the registry's defaults produce.

    Returns:
        The default configuration.
    """
    return AnalysisConfig.from_registry(RuleRegistry.defaults())


def _write_yaml(tmp_path: Path, body: str) -> Path:
    """Write raw text as the project's .gruff-py.yaml.

    Args:
        tmp_path: Project root that receives the config.
        body: Complete config text.

    Returns:
        The written config path.
    """
    path = tmp_path / ".gruff-py.yaml"
    path.write_text(body)
    return path


def test_fail_on_yaml_parses_into_analysis_config(tmp_path: Path) -> None:
    """Load the YAML failOn levels for analyse, report and dashboard into the config's minimum-severity map.

    Args:
        tmp_path: Project root whose config sets a fail-on level for each gated command.

    Returns:
        None. Checks that the loaded thresholds for analyse, report and dashboard match the YAML settings.
    """
    _write_yaml(
        tmp_path,
        "schemaVersion: gruff-py.config.v0.1\nfailOn:\n  analyse: error\n  report: warning\n  dashboard: none\n",
    )

    config, _ = ConfigLoader(tmp_path, _defaults()).load()

    assert config.minimum_severity == {
        "analyse": FailThreshold.ERROR,
        "report": FailThreshold.WARNING,
        "dashboard": FailThreshold.NONE,
    }


def test_fail_on_pyproject_toml_parses_into_analysis_config(tmp_path: Path) -> None:
    """Load the pyproject.toml failOn levels into the config's minimum-severity map.

    Args:
        tmp_path: Project root whose pyproject.toml sets a fail-on level for each gated command.

    Returns:
        None. Checks that the loaded thresholds for analyse, report and dashboard match the pyproject.toml settings.
    """
    (tmp_path / "pyproject.toml").write_text(
        '[tool.gruff-py]\nschemaVersion = "gruff-py.config.v0.1"\n[tool.gruff-py.failOn]\nanalyse = "advisory"\nreport = "none"\ndashboard = "none"\n'
    )

    config, _ = ConfigLoader(tmp_path, _defaults()).load()

    assert config.minimum_severity == {
        "analyse": FailThreshold.ADVISORY,
        "report": FailThreshold.NONE,
        "dashboard": FailThreshold.NONE,
    }


def test_fail_on_absent_yields_empty_map(tmp_path: Path) -> None:
    """Leave the minimum-severity map empty when the config has no failOn section.

    Args:
        tmp_path: Project root whose config holds only the schema version.

    Returns:
        None. Checks that omitting failOn leaves the minimum-severity map empty.
    """
    _write_yaml(tmp_path, "schemaVersion: gruff-py.config.v0.1\n")

    config, _ = ConfigLoader(tmp_path, _defaults()).load()

    assert config.minimum_severity == {}


def test_fail_on_rejects_non_gating_summary_key(tmp_path: Path) -> None:
    """Refuse a failOn entry for the non-gating summary command.

    Args:
        tmp_path: Project root whose config sets a fail-on level for summary.

    Returns:
        None. Checks that the loader raises ConfigError identifying summary as a non-gating command.
    """
    _write_yaml(
        tmp_path,
        "schemaVersion: gruff-py.config.v0.1\nfailOn:\n  summary: advisory\n",
    )

    with pytest.raises(ConfigError, match=r"'summary'.*non-gating"):
        ConfigLoader(tmp_path, _defaults()).load()


def test_fail_on_rejection_lists_allowed_gateable_commands(tmp_path: Path) -> None:
    """List the gateable commands in the error for a failOn entry naming another command.

    Args:
        tmp_path: Project root whose config sets a fail-on level for list-rules.

    Returns:
        None. Checks that the error for list-rules lists analyse, dashboard and report as the allowed commands.
    """
    _write_yaml(
        tmp_path,
        "schemaVersion: gruff-py.config.v0.1\nfailOn:\n  list-rules: advisory\n",
    )

    with pytest.raises(ConfigError, match=r"\['analyse', 'dashboard', 'report'\]"):
        ConfigLoader(tmp_path, _defaults()).load()


def test_fail_on_rejects_unknown_value(tmp_path: Path) -> None:
    """Refuse an unknown failOn level, listing the allowed levels in the error.

    Args:
        tmp_path: Project root whose config sets the analyse level to medium.

    Returns:
        None. Checks that the error names medium and lists the allowed failOn levels.
    """
    _write_yaml(
        tmp_path,
        "schemaVersion: gruff-py.config.v0.1\nfailOn:\n  analyse: medium\n",
    )

    with pytest.raises(ConfigError, match=r"'medium'.*\['advisory', 'error', 'none', 'warning'\]"):
        ConfigLoader(tmp_path, _defaults()).load()


def test_fail_on_rejects_never_alias(tmp_path: Path) -> None:
    """Refuse never as a failOn level.

    Args:
        tmp_path: Project root whose config sets the analyse level to never.

    Returns:
        None. Checks that the loader raises ConfigError naming never as the rejected level.
    """
    # The shared failOn contract uses 'none' to disable exit gating.
    _write_yaml(
        tmp_path,
        "schemaVersion: gruff-py.config.v0.1\nfailOn:\n  analyse: never\n",
    )

    with pytest.raises(ConfigError, match=r"'never'"):
        ConfigLoader(tmp_path, _defaults()).load()


def test_fail_on_surfaces_multiple_errors_at_once(tmp_path: Path) -> None:
    """Report both failOn problems in one error: the non-gating command and the unknown level.

    Args:
        tmp_path: Project root whose config holds both problems.

    Returns:
        None. Checks that one ConfigError mentions both the non-gating command and the unknown level.
    """
    _write_yaml(
        tmp_path,
        "schemaVersion: gruff-py.config.v0.1\nfailOn:\n  summary: advisory\n  analyse: medium\n",
    )

    with pytest.raises(ConfigError) as excinfo:
        ConfigLoader(tmp_path, _defaults()).load()
    message = str(excinfo.value)
    assert "summary" in message
    assert "medium" in message


def test_schema_version_missing_points_at_format_correct_recovery(tmp_path: Path) -> None:
    """Check the recovery guidance for a missing schema version.

    Args:
        tmp_path: Project root where the test writes YAML without a schemaVersion key.

    Returns:
        None. Checks that the error names the missing schemaVersion, mentions gruff-py migrate-config and TOML, and omits init --force.
    """
    _write_yaml(tmp_path, "minimumPythonVersion: '3.11'\n")

    with pytest.raises(ConfigError) as excinfo:
        ConfigLoader(tmp_path, _defaults()).load()
    message = str(excinfo.value)
    assert "missing required 'schemaVersion'" in message
    assert "gruff-py migrate-config" in message
    assert "TOML" in message
    assert "init --force" not in message


def test_schema_version_wrong_value_names_expected_literal(tmp_path: Path) -> None:
    """Refuse a wrong schema version with an error naming the found and expected values.

    Args:
        tmp_path: Project root whose config names schema version 0.2.

    Returns:
        None. Checks that the error names the supplied and expected schema versions.
    """
    _write_yaml(tmp_path, "schemaVersion: gruff-py.config.v0.2\n")

    with pytest.raises(
        ConfigError,
        match=r"schemaVersion 'gruff-py.config.v0.2'.*expected 'gruff-py.config.v0.1'",
    ):
        ConfigLoader(tmp_path, _defaults()).load()
