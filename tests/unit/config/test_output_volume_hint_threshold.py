from pathlib import Path

import pytest

from gruffpy.config.analysis_config import (
    DEEP_SCAN_DEFAULT_MAX_BYTES,
    DEEP_SCAN_DEFAULT_MAX_LINES,
    AnalysisConfig,
)
from gruffpy.config.exceptions import ConfigError
from gruffpy.config.loader import ConfigLoader
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


def test_default_threshold_is_50_when_key_absent(tmp_path: Path) -> None:
    """Default the output volume hint threshold to 50 when the config does not set it.

    Args:
        tmp_path: Project root whose config holds only the schema version.

    Returns:
        None. Checks that the loaded threshold is 50 when the setting is absent.
    """
    _write_yaml(tmp_path, "schemaVersion: gruff-py.config.v0.1\n")

    config, _ = ConfigLoader(tmp_path, _defaults()).load()

    assert config.output_volume_hint_threshold == 50


def test_threshold_yaml_parses_into_analysis_config(tmp_path: Path) -> None:
    """Load an output volume hint threshold of 200 from YAML.

    Args:
        tmp_path: Project root whose config sets the threshold to 200.

    Returns:
        None. Checks that the loaded threshold is the 200 set in YAML.
    """
    _write_yaml(
        tmp_path,
        "schemaVersion: gruff-py.config.v0.1\noutputVolumeHintThreshold: 200\n",
    )

    config, _ = ConfigLoader(tmp_path, _defaults()).load()

    assert config.output_volume_hint_threshold == 200


def test_threshold_pyproject_toml_parses_into_analysis_config(tmp_path: Path) -> None:
    """Load an output volume hint threshold of 0 from pyproject.toml.

    Args:
        tmp_path: Project root whose pyproject.toml sets the threshold to 0.

    Returns:
        None. Checks that the loader preserves the zero threshold set in pyproject.toml.
    """
    (tmp_path / "pyproject.toml").write_text('[tool.gruff-py]\nschemaVersion = "gruff-py.config.v0.1"\noutputVolumeHintThreshold = 0\n')

    config, _ = ConfigLoader(tmp_path, _defaults()).load()

    assert config.output_volume_hint_threshold == 0


def test_threshold_rejects_negative_value(tmp_path: Path) -> None:
    """Refuse a negative output volume hint threshold.

    Args:
        tmp_path: Project root whose config sets the threshold to -1.

    Returns:
        None. Checks that the error for a negative threshold gives zero as the lower bound.
    """
    _write_yaml(
        tmp_path,
        "schemaVersion: gruff-py.config.v0.1\noutputVolumeHintThreshold: -1\n",
    )

    with pytest.raises(ConfigError, match=r"outputVolumeHintThreshold must be >= 0"):
        ConfigLoader(tmp_path, _defaults()).load()


def test_threshold_rejects_non_integer(tmp_path: Path) -> None:
    """Refuse a string output volume hint threshold.

    Args:
        tmp_path: Project root whose config sets the threshold to a quoted word.

    Returns:
        None. Checks that a string threshold raises an error requiring a non-negative integer.
    """
    _write_yaml(
        tmp_path,
        'schemaVersion: gruff-py.config.v0.1\noutputVolumeHintThreshold: "fifty"\n',
    )

    with pytest.raises(ConfigError, match=r"outputVolumeHintThreshold must be a non-negative integer"):
        ConfigLoader(tmp_path, _defaults()).load()


def test_threshold_rejects_boolean(tmp_path: Path) -> None:
    """Refuse a boolean output volume hint threshold.

    Args:
        tmp_path: Project root whose config sets the threshold to true.

    Returns:
        None. Checks that a boolean threshold raises an error requiring a non-negative integer.
    """
    _write_yaml(
        tmp_path,
        "schemaVersion: gruff-py.config.v0.1\noutputVolumeHintThreshold: true\n",
    )

    with pytest.raises(ConfigError, match=r"outputVolumeHintThreshold must be a non-negative integer"):
        ConfigLoader(tmp_path, _defaults()).load()


_CONFIGURED_MAX_LINES = 12
_CONFIGURED_MAX_BYTES = 345


def test_deep_scan_budget_defaults_to_the_family_bounds(tmp_path: Path) -> None:
    """A project that configures nothing still gets the default deep-scan budget.

    Args:
        tmp_path: Empty project root, so the loader falls back to defaults.

    Returns:
        None. Checks the default line and byte limits and verifies that the budget records its source as default.
    """
    default_config, _ = ConfigLoader(tmp_path, _defaults()).load()

    assert default_config.deep_scan_budget.override == "default"
    assert default_config.deep_scan_budget.max_lines == DEEP_SCAN_DEFAULT_MAX_LINES
    assert default_config.deep_scan_budget.max_bytes == DEEP_SCAN_DEFAULT_MAX_BYTES


def test_deep_scan_budget_records_config_as_its_provenance(tmp_path: Path) -> None:
    """A configured budget replaces both bounds and says where the values came from.

    Args:
        tmp_path: Project root the test writes a deepScanBudget block into.

    Returns:
        None. Checks the enabled flag, both configured limits and the config source recorded on the budget.
    """
    _write_yaml(
        tmp_path,
        "schemaVersion: gruff-py.config.v0.1\ndeepScanBudget:\n  enabled: true\n"
        f"  maxLines: {_CONFIGURED_MAX_LINES}\n  maxBytes: {_CONFIGURED_MAX_BYTES}\n",
    )

    configured, _ = ConfigLoader(tmp_path, _defaults()).load()

    assert configured.deep_scan_budget.enabled is True
    assert configured.deep_scan_budget.max_lines == _CONFIGURED_MAX_LINES
    assert configured.deep_scan_budget.max_bytes == _CONFIGURED_MAX_BYTES
    assert configured.deep_scan_budget.override == "config"


@pytest.mark.parametrize(
    "body",
    (
        "deepScanBudget: true\n",
        "deepScanBudget:\n  unknown: 1\n",
        'deepScanBudget:\n  enabled: "yes"\n',
        "deepScanBudget:\n  maxLines: 0\n",
        "deepScanBudget:\n  maxBytes: 1.5\n",
    ),
    ids=("not-a-table", "unknown-key", "enabled-not-bool", "max-lines-zero", "max-bytes-fractional"),
)
def test_deep_scan_budget_rejects_malformed_config(tmp_path: Path, body: str) -> None:
    """Refuse a malformed deepScanBudget section with a ConfigError naming it.

    Args:
        tmp_path: Project root whose config appends the case's budget section.
        body: Budget section text covering a non-table, an unknown key, a non-boolean flag, a zero line limit and a fractional byte limit.

    Returns:
        None. Checks that each malformed budget raises ConfigError naming deepScanBudget.
    """
    _write_yaml(tmp_path, "schemaVersion: gruff-py.config.v0.1\n" + body)

    with pytest.raises(ConfigError, match="deepScanBudget"):
        ConfigLoader(tmp_path, _defaults()).load()
