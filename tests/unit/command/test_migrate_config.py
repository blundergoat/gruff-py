"""Legacy-shape rewrites and preservation guarantees for `migrate-config`."""

from pathlib import Path

import pytest

from gruffpy.analysis.schema import CONFIG_SCHEMA_VERSION
from gruffpy.command.migrate_config import migrate_config_file
from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.exceptions import ConfigError
from gruffpy.config.loader import ConfigLoader
from gruffpy.rule.registry import RuleRegistry

_LEGACY_WARNING_TIER = 15
_LEGACY_ERROR_TIER = 30
_EXPLICIT_THRESHOLD = 25

_LEGACY_CONFIG = (
    "schemaVersion: gruff-py.config.v0.1\n"
    "paths:\n"
    "  ignore:\n"
    '    - "vendor/**"\n'
    "allowlists:\n"
    "  acceptedAbbreviations:\n"
    "    - cfg\n"
    "rules:\n"
    "  complexity.cognitive:\n"
    "    enabled: true\n"
    "    thresholds:\n"
    f"      warning: {_LEGACY_WARNING_TIER}\n"
    f"      error: {_LEGACY_ERROR_TIER}\n"
    "  naming.module-name-mismatch:\n"
    "    enabled: true\n"
    "    options:\n"
    "      conventionalModuleNames:\n"
    "        - constants\n"
    "        - mytypes\n"
)


def _defaults() -> AnalysisConfig:
    return AnalysisConfig.from_registry(RuleRegistry.defaults())


def _write_config(tmp_path: Path, body: str) -> Path:
    target = tmp_path / ".gruff-py.yaml"
    target.write_text(body)
    return target


def test_both_tiers_map_to_error_threshold(tmp_path: Path):
    _write_config(tmp_path, _LEGACY_CONFIG)
    migration = migrate_config_file(tmp_path, None)
    assert migration.has_changes()
    assert any(
        "threshold=30, severity=error" in change and "warning tier 15 dropped" in change
        for change in migration.changes
    )


def test_warning_only_tier_maps_to_warning_threshold(tmp_path: Path):
    _write_config(
        tmp_path,
        "schemaVersion: gruff-py.config.v0.1\n"
        "rules:\n"
        "  complexity.cognitive:\n"
        "    thresholds:\n"
        "      warning: 15\n",
    )
    migration = migrate_config_file(tmp_path, None)
    assert any("threshold=15, severity=warning" in change for change in migration.changes)


def test_migrated_config_round_trips_with_zero_warnings(tmp_path: Path):
    target = _write_config(tmp_path, _LEGACY_CONFIG)
    migration = migrate_config_file(tmp_path, None)
    target.write_text(migration.migrated_text)
    loader = ConfigLoader(tmp_path, _defaults())
    config, source = loader.load()
    assert source == target
    assert loader.warnings == ()
    rubric = config.rules["complexity.cognitive"].severity_threshold
    assert rubric is not None
    assert rubric.threshold == _LEGACY_ERROR_TIER
    assert rubric.severity.value == "error"


def test_migration_preserves_custom_blocks(tmp_path: Path):
    target = _write_config(tmp_path, _LEGACY_CONFIG)
    migration = migrate_config_file(tmp_path, None)
    target.write_text(migration.migrated_text)
    config, _ = ConfigLoader(tmp_path, _defaults()).load()
    assert config.ignored_path_patterns == ("vendor/**",)
    assert config.accepted_abbreviations == ("cfg",)
    options = config.rules["naming.module-name-mismatch"].options
    assert options["conventionalModuleNames"] == ["constants", "mytypes"]
    assert config.rules["naming.module-name-mismatch"].enabled is True


def test_missing_schema_version_is_inserted(tmp_path: Path):
    _write_config(tmp_path, "rules:\n  complexity.cognitive:\n    enabled: true\n")
    migration = migrate_config_file(tmp_path, None)
    assert any("schemaVersion" in change for change in migration.changes)
    assert migration.migrated_text.startswith(f"schemaVersion: {CONFIG_SCHEMA_VERSION}")


def test_non_rubric_legacy_tiers_are_removed_with_note(tmp_path: Path):
    _write_config(
        tmp_path,
        "schemaVersion: gruff-py.config.v0.1\n"
        "rules:\n"
        "  naming.module-name-mismatch:\n"
        "    thresholds:\n"
        "      warning: 3\n",
    )
    migration = migrate_config_file(tmp_path, None)
    assert any("no severity rubric" in change for change in migration.changes)
    assert "thresholds" not in migration.migrated_text


def test_unknown_rule_id_is_left_as_is_with_note(tmp_path: Path):
    _write_config(
        tmp_path,
        "schemaVersion: gruff-py.config.v0.1\n"
        "rules:\n"
        "  complexity.npath:\n"
        "    thresholds:\n"
        "      warning: 200\n",
    )
    migration = migrate_config_file(tmp_path, None)
    assert not migration.has_changes()
    assert any("unknown rule id" in note for note in migration.notes)


def test_current_config_reports_no_changes_and_keeps_text(tmp_path: Path):
    body = (
        "# keep me\n"
        "schemaVersion: gruff-py.config.v0.1\n"
        "rules:\n"
        "  complexity.cognitive:\n"
        "    threshold: 30\n"
        "    severity: error\n"
    )
    _write_config(tmp_path, body)
    migration = migrate_config_file(tmp_path, None)
    assert not migration.has_changes()
    assert migration.migrated_text == body


def test_explicit_toml_path_gets_guidance_error(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text("[tool.gruff-py]\n")
    with pytest.raises(ConfigError, match="YAML configs only"):
        migrate_config_file(tmp_path, tmp_path / "pyproject.toml")


def test_pyproject_only_project_gets_guidance_error(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text("[tool.gruff-py]\n")
    with pytest.raises(ConfigError, match="YAML configs only"):
        migrate_config_file(tmp_path, None)


def test_threshold_without_severity_is_completed_and_loads(tmp_path: Path):
    # A hybrid config with a bare `threshold` plus legacy tiers must gain the
    # missing severity, so migrate-config never writes a config it cannot load.
    target = _write_config(
        tmp_path,
        "schemaVersion: gruff-py.config.v0.1\n"
        "rules:\n"
        "  complexity.cognitive:\n"
        f"    threshold: {_EXPLICIT_THRESHOLD}\n"
        "    thresholds:\n"
        f"      error: {_LEGACY_ERROR_TIER}\n",
    )
    migration = migrate_config_file(tmp_path, None)
    target.write_text(migration.migrated_text)
    config, _ = ConfigLoader(tmp_path, _defaults()).load()
    rubric = config.rules["complexity.cognitive"].severity_threshold
    assert rubric is not None
    assert rubric.threshold == _EXPLICIT_THRESHOLD
    assert rubric.severity.value == "error"


def test_no_config_anywhere_is_an_error(tmp_path: Path):
    with pytest.raises(ConfigError, match="No gruff YAML config found"):
        migrate_config_file(tmp_path, None)


def test_unreadable_config_surfaces_as_config_error(tmp_path: Path):
    # A target that resolves but cannot be read (here a directory with a .yaml
    # suffix, so read_text raises OSError) must surface as ConfigError, not an
    # unhandled traceback - matching the already-protected write path.
    target = tmp_path / "config.yaml"
    target.mkdir()
    with pytest.raises(ConfigError, match="Failed to read config file"):
        migrate_config_file(tmp_path, target)
