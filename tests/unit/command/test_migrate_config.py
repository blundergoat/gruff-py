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
    "  naming.short-variable:\n"
    "    enabled: true\n"
    "    options:\n"
    "      acceptedShortNames:\n"
    "        - constants\n"
    "        - mytypes\n"
)


def _defaults() -> AnalysisConfig:
    """Build the analysis config the registry's defaults produce.

    Returns:
        The default configuration.
    """
    return AnalysisConfig.from_registry(RuleRegistry.defaults())


def _write_config(tmp_path: Path, body: str) -> Path:
    """Write a project's ``.gruff-py.yaml``.

    Args:
        tmp_path: Project root that receives the config, replacing any earlier one.
        body: Config text to write.

    Returns:
        The written config path.
    """
    target = tmp_path / ".gruff-py.yaml"
    target.write_text(body)
    return target


def test_both_tiers_map_to_error_threshold(tmp_path: Path):
    """Report the migration of warning and error tiers to the error tier's threshold at error severity, with the warning tier dropped.

    Args:
        tmp_path: Project root holding the legacy config with both tiers.
    """
    _write_config(tmp_path, _LEGACY_CONFIG)
    migration = migrate_config_file(tmp_path, None)
    assert migration.has_changes()
    assert any("threshold=30, severity=error" in change and "warning tier 15 dropped" in change for change in migration.changes)


def test_warning_only_tier_maps_to_warning_threshold(tmp_path: Path):
    """Report the migration of a lone warning tier to a threshold of 15 at warning severity.

    Args:
        tmp_path: Project root whose config sets only a cognitive warning tier.
    """
    _write_config(
        tmp_path,
        "schemaVersion: gruff-py.config.v0.1\nrules:\n  complexity.cognitive:\n    thresholds:\n      warning: 15\n",
    )
    migration = migrate_config_file(tmp_path, None)
    assert any("threshold=15, severity=warning" in change for change in migration.changes)


def test_migrated_config_round_trips_with_zero_warnings(tmp_path: Path):
    """Load the migrated legacy config with no warnings, and with the error tier as the cognitive rule's threshold and severity.

    Args:
        tmp_path: Project root whose legacy config is replaced by its migrated text.
    """
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
    """Keep the legacy config's ignore paths, accepted abbreviations and one rule's options and enabled flag through migration.

    Args:
        tmp_path: Project root holding the legacy config, rewritten with its migrated text before loading.
    """
    target = _write_config(tmp_path, _LEGACY_CONFIG)
    migration = migrate_config_file(tmp_path, None)
    target.write_text(migration.migrated_text)
    config, _ = ConfigLoader(tmp_path, _defaults()).load()
    assert config.ignored_path_patterns == ("vendor/**",)
    assert config.accepted_abbreviations == ("cfg",)
    options = config.rules["naming.short-variable"].options
    assert options["acceptedShortNames"] == ["constants", "mytypes"]
    assert config.rules["naming.short-variable"].enabled is True


def test_missing_schema_version_is_inserted(tmp_path: Path):
    """Insert the current schema version at the top of a config that lacks one, and record the change.

    Args:
        tmp_path: Project root whose config has rules but no schema version.
    """
    _write_config(tmp_path, "rules:\n  complexity.cognitive:\n    enabled: true\n")
    migration = migrate_config_file(tmp_path, None)
    assert any("schemaVersion" in change for change in migration.changes)
    assert migration.migrated_text.startswith(f"schemaVersion: {CONFIG_SCHEMA_VERSION}")


def test_non_rubric_legacy_tiers_are_removed_with_note(tmp_path: Path):
    """Remove legacy tiers from a rule with no severity rubric, and note why.

    Args:
        tmp_path: Project root whose config sets a warning tier on the short-variable rule.
    """
    _write_config(
        tmp_path,
        "schemaVersion: gruff-py.config.v0.1\nrules:\n  naming.short-variable:\n    thresholds:\n      warning: 3\n",
    )
    migration = migrate_config_file(tmp_path, None)
    assert any("no severity rubric" in change for change in migration.changes)
    assert "thresholds" not in migration.migrated_text


def test_unknown_rule_id_is_left_as_is_with_note(tmp_path: Path):
    """Report no changes for an unknown rule's legacy tiers, and note the unknown rule id.

    Args:
        tmp_path: Project root whose config sets tiers on a rule id the registry lacks.
    """
    _write_config(
        tmp_path,
        "schemaVersion: gruff-py.config.v0.1\nrules:\n  complexity.npath:\n    thresholds:\n      warning: 200\n",
    )
    migration = migrate_config_file(tmp_path, None)
    assert not migration.has_changes()
    assert any("unknown rule id" in note for note in migration.notes)


def test_current_config_reports_no_changes_and_keeps_text(tmp_path: Path):
    """Report no changes for a current config and keep its text, comment included, byte for byte.

    Args:
        tmp_path: Project root whose commented config already uses a single threshold and severity.
    """
    body = "# keep me\nschemaVersion: gruff-py.config.v0.1\nrules:\n  complexity.cognitive:\n    threshold: 30\n    severity: error\n"
    _write_config(tmp_path, body)
    migration = migrate_config_file(tmp_path, None)
    assert not migration.has_changes()
    assert migration.migrated_text == body


def test_explicit_toml_path_gets_guidance_error(tmp_path: Path):
    """Refuse an explicit ``pyproject.toml`` target with a ``ConfigError`` saying migration handles YAML configs only.

    Args:
        tmp_path: Project root holding a ``pyproject.toml`` with a gruff-py table.
    """
    (tmp_path / "pyproject.toml").write_text("[tool.gruff-py]\n")
    with pytest.raises(ConfigError, match="YAML configs only"):
        migrate_config_file(tmp_path, tmp_path / "pyproject.toml")


def test_pyproject_only_project_gets_guidance_error(tmp_path: Path):
    """Refuse a project whose only config is a ``pyproject.toml`` table, with the same YAML-only guidance.

    Args:
        tmp_path: Project root holding a ``pyproject.toml`` with a gruff-py table.
    """
    (tmp_path / "pyproject.toml").write_text("[tool.gruff-py]\n")
    with pytest.raises(ConfigError, match="YAML configs only"):
        migrate_config_file(tmp_path, None)


def test_threshold_without_severity_is_completed_and_loads(tmp_path: Path):
    """Complete a bare threshold with the legacy error tier's severity, so the migrated config loads with that threshold at error severity.

    Args:
        tmp_path: Project root whose config sets a bare threshold beside a legacy error tier, replaced by its migrated text.
    """
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
    """Raise a ``ConfigError`` when the project has no gruff YAML config.

    Args:
        tmp_path: Empty project root.
    """
    with pytest.raises(ConfigError, match="No gruff YAML config found"):
        migrate_config_file(tmp_path, None)


def test_unreadable_config_surfaces_as_config_error(tmp_path: Path):
    """Raise a ``ConfigError`` naming the read failure when the target cannot be read.

    Args:
        tmp_path: Project root holding a directory named ``config.yaml``, passed as the target.
    """
    # A target that resolves but cannot be read (here a directory with a .yaml
    # suffix, so read_text raises OSError) must surface as ConfigError, not an
    # unhandled traceback - matching the already-protected write path.
    target = tmp_path / "config.yaml"
    target.mkdir()
    with pytest.raises(ConfigError, match="Failed to read config file"):
        migrate_config_file(tmp_path, target)
