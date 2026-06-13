"""Warn-by-default vs strict handling of unknown rule-level config keys."""

from pathlib import Path

import pytest

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.exceptions import ConfigError
from gruffpy.config.loader import ConfigLoader
from gruffpy.rule.registry import RuleRegistry

_LEGACY_COGNITIVE_YAML = (
    "schemaVersion: gruff-py.config.v0.1\n"
    "rules:\n"
    "  complexity.cognitive:\n"
    "    enabled: true\n"
    "    thresholds:\n"
    "      warning: 15\n"
    "      error: 30\n"
)


def _defaults() -> AnalysisConfig:
    return AnalysisConfig.from_registry(RuleRegistry.defaults())


def _write_yaml(tmp_path: Path, body: str) -> None:
    (tmp_path / ".gruff-py.yaml").write_text(body)


def test_legacy_tiered_thresholds_warn_and_rule_keeps_defaults(tmp_path: Path):
    _write_yaml(tmp_path, _LEGACY_COGNITIVE_YAML)
    loader = ConfigLoader(tmp_path, _defaults())
    config, source = loader.load()
    assert source == tmp_path / ".gruff-py.yaml"
    assert len(loader.warnings) == 2
    assert config.rules["complexity.cognitive"] == _defaults().rules["complexity.cognitive"]


def test_legacy_threshold_warning_lists_accepted_keys_and_migration_hint(tmp_path: Path):
    _write_yaml(tmp_path, _LEGACY_COGNITIVE_YAML)
    loader = ConfigLoader(tmp_path, _defaults())
    loader.load()
    first = loader.warnings[0]
    assert 'Unknown threshold "rules.complexity.cognitive.thresholds.warning"' in first
    assert 'Accepted keys for "rules.complexity.cognitive": enabled, threshold, severity' in first
    assert "gruff-py migrate-config" in first
    assert "gruff-py init --force" in first


def test_legacy_tiered_thresholds_raise_under_strict(tmp_path: Path):
    _write_yaml(tmp_path, _LEGACY_COGNITIVE_YAML)
    loader = ConfigLoader(tmp_path, _defaults(), strict=True)
    with pytest.raises(ConfigError) as excinfo:
        loader.load()
    message = str(excinfo.value)
    assert 'Unknown threshold "rules.complexity.cognitive.thresholds.warning"' in message
    assert "Accepted keys" in message
    # The lenient consequence must not leak into the abort-path error text.
    assert "ignored" not in message.lower()


def test_unknown_rule_id_warns_and_section_is_skipped(tmp_path: Path):
    _write_yaml(
        tmp_path,
        "schemaVersion: gruff-py.config.v0.1\nrules:\n  complexity.npath:\n    enabled: false\n",
    )
    loader = ConfigLoader(tmp_path, _defaults())
    config, _ = loader.load()
    assert len(loader.warnings) == 1
    assert 'Unknown rule id "complexity.npath"' in loader.warnings[0]
    assert config.rules == _defaults().rules


def test_unknown_rule_section_key_warns_and_rest_applies(tmp_path: Path):
    _write_yaml(
        tmp_path,
        "schemaVersion: gruff-py.config.v0.1\n"
        "rules:\n"
        "  naming.module-name-mismatch:\n"
        "    enabled: false\n"
        "    flavour: spicy\n",
    )
    loader = ConfigLoader(tmp_path, _defaults())
    config, _ = loader.load()
    assert len(loader.warnings) == 1
    assert 'Unknown key "rules.naming.module-name-mismatch.flavour"' in loader.warnings[0]
    assert config.rules["naming.module-name-mismatch"].enabled is False


def test_threshold_on_non_rubric_rule_warns_and_is_dropped(tmp_path: Path):
    _write_yaml(
        tmp_path,
        "schemaVersion: gruff-py.config.v0.1\n"
        "rules:\n"
        "  naming.module-name-mismatch:\n"
        "    threshold: 5\n"
        "    severity: warning\n",
    )
    loader = ConfigLoader(tmp_path, _defaults())
    config, _ = loader.load()
    assert len(loader.warnings) == 1
    assert "only supported for severity-threshold rubrics" in loader.warnings[0]
    assert config.rules["naming.module-name-mismatch"].severity_threshold is None


def test_severity_without_threshold_warns_and_is_dropped(tmp_path: Path):
    _write_yaml(
        tmp_path,
        "schemaVersion: gruff-py.config.v0.1\nrules:\n  size.file-length:\n    severity: error\n",
    )
    loader = ConfigLoader(tmp_path, _defaults())
    config, _ = loader.load()
    assert len(loader.warnings) == 1
    assert 'requires "threshold"' in loader.warnings[0]
    assert config.rules["size.file-length"] == _defaults().rules["size.file-length"]


def test_structural_rule_section_error_still_raises_without_strict(tmp_path: Path):
    _write_yaml(
        tmp_path,
        "schemaVersion: gruff-py.config.v0.1\nrules:\n  size.file-length: 12\n",
    )
    loader = ConfigLoader(tmp_path, _defaults())
    with pytest.raises(ConfigError, match="must be a table"):
        loader.load()


def test_unknown_top_level_key_still_raises_without_strict(tmp_path: Path):
    _write_yaml(
        tmp_path,
        "schemaVersion: gruff-py.config.v0.1\nbananas: true\n",
    )
    loader = ConfigLoader(tmp_path, _defaults())
    with pytest.raises(ConfigError, match="Unknown gruff keys"):
        loader.load()


def test_warnings_reset_between_loads(tmp_path: Path):
    _write_yaml(tmp_path, _LEGACY_COGNITIVE_YAML)
    loader = ConfigLoader(tmp_path, _defaults())
    loader.load()
    assert len(loader.warnings) == 2
    _write_yaml(tmp_path, "schemaVersion: gruff-py.config.v0.1\n")
    loader.load()
    assert loader.warnings == ()
