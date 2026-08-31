from pathlib import Path

import pytest

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.exceptions import ConfigError
from gruffpy.config.loader import ConfigLoader
from gruffpy.rule.registry import RuleRegistry


def _defaults() -> AnalysisConfig:
    return AnalysisConfig.from_registry(RuleRegistry.defaults())


def _write_yaml(tmp_path: Path, body: str) -> Path:
    path = tmp_path / ".gruff-py.yaml"
    path.write_text(body)
    return path


def test_default_threshold_is_50_when_key_absent(tmp_path: Path) -> None:
    _write_yaml(tmp_path, "schemaVersion: gruff-py.config.v0.1\n")

    config, _ = ConfigLoader(tmp_path, _defaults()).load()

    # gruff: disable-next=test-quality.magic-number-assertion -- 50 is the documented default.
    assert config.output_volume_hint_threshold == 50


def test_threshold_yaml_parses_into_analysis_config(tmp_path: Path) -> None:
    _write_yaml(
        tmp_path,
        "schemaVersion: gruff-py.config.v0.1\noutputVolumeHintThreshold: 200\n",
    )

    config, _ = ConfigLoader(tmp_path, _defaults()).load()

    assert config.output_volume_hint_threshold == 200


def test_threshold_pyproject_toml_parses_into_analysis_config(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[tool.gruff-py]\nschemaVersion = "gruff-py.config.v0.1"\noutputVolumeHintThreshold = 0\n')

    config, _ = ConfigLoader(tmp_path, _defaults()).load()

    assert config.output_volume_hint_threshold == 0


def test_threshold_rejects_negative_value(tmp_path: Path) -> None:
    _write_yaml(
        tmp_path,
        "schemaVersion: gruff-py.config.v0.1\noutputVolumeHintThreshold: -1\n",
    )

    with pytest.raises(ConfigError, match=r"outputVolumeHintThreshold must be >= 0"):
        ConfigLoader(tmp_path, _defaults()).load()


def test_threshold_rejects_non_integer(tmp_path: Path) -> None:
    _write_yaml(
        tmp_path,
        'schemaVersion: gruff-py.config.v0.1\noutputVolumeHintThreshold: "fifty"\n',
    )

    with pytest.raises(ConfigError, match=r"outputVolumeHintThreshold must be a non-negative integer"):
        ConfigLoader(tmp_path, _defaults()).load()


def test_threshold_rejects_boolean(tmp_path: Path) -> None:
    _write_yaml(
        tmp_path,
        "schemaVersion: gruff-py.config.v0.1\noutputVolumeHintThreshold: true\n",
    )

    with pytest.raises(ConfigError, match=r"outputVolumeHintThreshold must be a non-negative integer"):
        ConfigLoader(tmp_path, _defaults()).load()


def test_deep_scan_budget_defaults_and_config_provenance(tmp_path: Path) -> None:
    default_config, _ = ConfigLoader(tmp_path, _defaults()).load()
    assert default_config.deep_scan_budget.override == "default"
    assert default_config.deep_scan_budget.max_lines == 20_000
    assert default_config.deep_scan_budget.max_bytes == 2_000_000

    _write_yaml(
        tmp_path,
        "schemaVersion: gruff-py.config.v0.1\ndeepScanBudget:\n  enabled: true\n  maxLines: 12\n  maxBytes: 345\n",
    )
    configured, _ = ConfigLoader(tmp_path, _defaults()).load()
    assert configured.deep_scan_budget.enabled is True
    assert configured.deep_scan_budget.max_lines == 12
    assert configured.deep_scan_budget.max_bytes == 345
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
)
def test_deep_scan_budget_rejects_malformed_config(tmp_path: Path, body: str) -> None:
    _write_yaml(tmp_path, "schemaVersion: gruff-py.config.v0.1\n" + body)

    with pytest.raises(ConfigError, match="deepScanBudget"):
        ConfigLoader(tmp_path, _defaults()).load()
