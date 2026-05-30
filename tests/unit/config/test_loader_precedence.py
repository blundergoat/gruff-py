"""Precedence + format-detection tests for ConfigLoader (ADR-006)."""

from pathlib import Path

import pytest

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.exceptions import ConfigError
from gruffpy.config.loader import ConfigLoader
from gruffpy.rule.registry import RuleRegistry


def _defaults() -> AnalysisConfig:
    return AnalysisConfig.from_registry(RuleRegistry.defaults())


def test_no_config_files_returns_defaults_and_none_source(tmp_path: Path):
    loader = ConfigLoader(tmp_path, _defaults())
    config, source = loader.load()
    assert source is None
    assert config == _defaults()


def test_gruff_py_yaml_wins_over_pyproject_toml(tmp_path: Path):
    # Both files exist. YAML overrides size.file-length warning to 250;
    # pyproject sets it to 400. YAML must win.
    (tmp_path / ".gruff-py.yaml").write_text(
        "schemaVersion: gruff-py.config.v0.1\n"
        "rules:\n  size.file-length:\n    threshold: 250\n    severity: error\n"
    )
    (tmp_path / "pyproject.toml").write_text(
        "[tool.gruff-py]\n"
        'schemaVersion = "gruff-py.config.v0.1"\n'
        '[tool.gruff-py.rules."size.file-length"]\n'
        "enabled = true\n"
        'threshold = 400\nseverity = "error"\n'
    )
    loader = ConfigLoader(tmp_path, _defaults())
    config, source = loader.load()
    assert source == tmp_path / ".gruff-py.yaml"
    assert config.rules["size.file-length"].severity_threshold.threshold == 250


def test_gruff_py_yaml_wins_over_legacy_gruff_yaml(tmp_path: Path):
    (tmp_path / ".gruff-py.yaml").write_text(
        "schemaVersion: gruff-py.config.v0.1\n"
        "rules:\n  size.file-length:\n    threshold: 250\n    severity: error\n"
    )
    (tmp_path / ".gruff.yaml").write_text(
        "schemaVersion: gruff-py.config.v0.1\n"
        "rules:\n  size.file-length:\n    threshold: 400\n    severity: error\n"
    )
    loader = ConfigLoader(tmp_path, _defaults())
    config, source = loader.load()
    assert source == tmp_path / ".gruff-py.yaml"
    assert config.rules["size.file-length"].severity_threshold.threshold == 250


def test_legacy_gruff_yaml_is_discovered(tmp_path: Path):
    (tmp_path / ".gruff.yaml").write_text(
        "schemaVersion: gruff-py.config.v0.1\n"
        "rules:\n  size.file-length:\n    threshold: 321\n    severity: error\n"
    )
    loader = ConfigLoader(tmp_path, _defaults())
    config, source = loader.load()
    assert source == tmp_path / ".gruff.yaml"
    assert config.rules["size.file-length"].severity_threshold.threshold == 321


def test_pyproject_used_when_only_pyproject_exists(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text(
        "[tool.gruff-py]\n"
        'schemaVersion = "gruff-py.config.v0.1"\n'
        '[tool.gruff-py.rules."size.file-length"]\n'
        "enabled = true\n"
        'threshold = 333\nseverity = "error"\n'
    )
    loader = ConfigLoader(tmp_path, _defaults())
    config, source = loader.load()
    assert source == tmp_path / "pyproject.toml"
    assert config.rules["size.file-length"].severity_threshold.threshold == 333


def test_legacy_pyproject_table_is_supported(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text(
        "[tool.gruff]\n"
        'schemaVersion = "gruff-py.config.v0.1"\n'
        '[tool.gruff.rules."size.file-length"]\n'
        "enabled = true\n"
        'threshold = 444\nseverity = "error"\n'
    )
    loader = ConfigLoader(tmp_path, _defaults())
    config, source = loader.load()
    assert source == tmp_path / "pyproject.toml"
    assert config.rules["size.file-length"].severity_threshold.threshold == 444


def test_modern_pyproject_table_wins_over_legacy_table(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text(
        "[tool.gruff-py]\n"
        'schemaVersion = "gruff-py.config.v0.1"\n'
        '[tool.gruff-py.rules."size.file-length"]\n'
        'threshold = 222\nseverity = "error"\n'
        '[tool.gruff.rules."size.file-length"]\n'
        'threshold = 444\nseverity = "error"\n'
    )
    loader = ConfigLoader(tmp_path, _defaults())
    config, source = loader.load()
    assert source == tmp_path / "pyproject.toml"
    assert config.rules["size.file-length"].severity_threshold.threshold == 222


def test_explicit_yaml_path_overrides_discovery(tmp_path: Path):
    (tmp_path / ".gruff-py.yaml").write_text(
        "schemaVersion: gruff-py.config.v0.1\n"
        "rules:\n  size.file-length:\n    threshold: 100\n    severity: error\n"
    )
    explicit = tmp_path / "custom.yaml"
    explicit.write_text(
        "schemaVersion: gruff-py.config.v0.1\n"
        "rules:\n  size.file-length:\n    threshold: 555\n    severity: error\n"
    )
    loader = ConfigLoader(tmp_path, _defaults())
    config, source = loader.load(explicit)
    assert source == explicit
    assert config.rules["size.file-length"].severity_threshold.threshold == 555


def test_explicit_toml_path_supported(tmp_path: Path):
    explicit = tmp_path / "custom.toml"
    explicit.write_text(
        "[tool.gruff-py]\n"
        'schemaVersion = "gruff-py.config.v0.1"\n'
        '[tool.gruff-py.rules."size.file-length"]\nthreshold = 222\nseverity = "error"\n'
    )
    loader = ConfigLoader(tmp_path, _defaults())
    config, source = loader.load(explicit)
    assert source == explicit
    assert config.rules["size.file-length"].severity_threshold.threshold == 222


_HIGH_THRESHOLD_BOUNDARY = 900
_LOW_THRESHOLD_BOUNDARY = 60


def _settings_with_high_threshold_override(tmp_path: Path):
    (tmp_path / ".gruff-py.yaml").write_text(
        "schemaVersion: gruff-py.config.v0.1\n"
        f"rules:\n  size.file-length:\n    threshold: {_HIGH_THRESHOLD_BOUNDARY}\n"
        "    severity: error\n"
    )
    config, _ = ConfigLoader(tmp_path, _defaults()).load()
    return config.rule_settings("size.file-length")


def test_severity_threshold_override_stores_value(tmp_path: Path):
    settings = _settings_with_high_threshold_override(tmp_path)
    assert settings.severity_threshold is not None
    assert settings.severity_threshold.threshold == _HIGH_THRESHOLD_BOUNDARY
    assert settings.severity_threshold.severity.value == "error"


def test_severity_threshold_override_does_not_match_at_boundary(tmp_path: Path):
    settings = _settings_with_high_threshold_override(tmp_path)
    assert settings.high_value_threshold_match(_HIGH_THRESHOLD_BOUNDARY) is None


def test_severity_threshold_override_matches_just_above_boundary(tmp_path: Path):
    settings = _settings_with_high_threshold_override(tmp_path)
    match = settings.high_value_threshold_match(_HIGH_THRESHOLD_BOUNDARY + 1)
    assert match is not None
    assert match.threshold == _HIGH_THRESHOLD_BOUNDARY
    assert match.severity.value == "error"


def test_threshold_and_warning_severity_supported(tmp_path: Path):
    (tmp_path / ".gruff-py.yaml").write_text(
        "schemaVersion: gruff-py.config.v0.1\n"
        "rules:\n  size.file-length:\n    threshold: 500\n    severity: warning\n"
    )
    loader = ConfigLoader(tmp_path, _defaults())

    config, _ = loader.load()
    settings = config.rule_settings("size.file-length")
    match = settings.high_value_threshold_match(501)

    assert match is not None
    assert match.severity.value == "warning"


def _settings_with_low_threshold_override(tmp_path: Path):
    (tmp_path / ".gruff-py.yaml").write_text(
        "schemaVersion: gruff-py.config.v0.1\n"
        f"rules:\n  complexity.maintainability-index:\n    threshold: {_LOW_THRESHOLD_BOUNDARY}\n"
        "    severity: error\n"
    )
    config, _ = ConfigLoader(tmp_path, _defaults()).load()
    return config.rule_settings("complexity.maintainability-index")


def test_low_value_threshold_override_does_not_match_at_boundary(tmp_path: Path):
    settings = _settings_with_low_threshold_override(tmp_path)
    assert settings.low_value_threshold_match(_LOW_THRESHOLD_BOUNDARY) is None


def test_low_value_threshold_override_matches_just_below_boundary(tmp_path: Path):
    settings = _settings_with_low_threshold_override(tmp_path)
    match = settings.low_value_threshold_match(_LOW_THRESHOLD_BOUNDARY - 1)
    assert match is not None
    assert match.threshold == _LOW_THRESHOLD_BOUNDARY
    assert match.severity.value == "error"


def test_threshold_requires_severity(tmp_path: Path):
    (tmp_path / ".gruff-py.yaml").write_text(
        "schemaVersion: gruff-py.config.v0.1\nrules:\n  size.file-length:\n    threshold: 900\n"
    )
    loader = ConfigLoader(tmp_path, _defaults())

    with pytest.raises(ConfigError, match='severity" must be "warning" or "error"'):
        loader.load()


def test_severity_requires_threshold(tmp_path: Path):
    (tmp_path / ".gruff-py.yaml").write_text(
        "schemaVersion: gruff-py.config.v0.1\nrules:\n  size.file-length:\n    severity: error\n"
    )
    loader = ConfigLoader(tmp_path, _defaults())

    with pytest.raises(ConfigError, match='severity" requires "threshold"'):
        loader.load()


def test_threshold_rejects_named_threshold_rule(tmp_path: Path):
    (tmp_path / ".gruff-py.yaml").write_text(
        "schemaVersion: gruff-py.config.v0.1\n"
        "rules:\n  test-quality.eager-test:\n    threshold: 5\n    severity: error\n"
    )
    loader = ConfigLoader(tmp_path, _defaults())

    with pytest.raises(ConfigError, match="only supported for severity-threshold rubrics"):
        loader.load()


def test_threshold_and_thresholds_cannot_be_combined(tmp_path: Path):
    (tmp_path / ".gruff-py.yaml").write_text(
        "schemaVersion: gruff-py.config.v0.1\n"
        "rules:\n"
        "  size.file-length:\n"
        "    threshold: 900\n"
        "    severity: error\n"
        "    thresholds:\n"
        "      warning: 500\n"
    )
    loader = ConfigLoader(tmp_path, _defaults())

    with pytest.raises(ConfigError, match='cannot combine "threshold" and "thresholds"'):
        loader.load()


def test_unknown_named_threshold_rejected(tmp_path: Path):
    (tmp_path / ".gruff-py.yaml").write_text(
        "schemaVersion: gruff-py.config.v0.1\n"
        "rules:\n  test-quality.eager-test:\n    thresholds:\n      warning: 5\n"
    )
    loader = ConfigLoader(tmp_path, _defaults())

    with pytest.raises(ConfigError, match='Unknown threshold "rules.test-quality.eager-test'):
        loader.load()


def test_explicit_config_path_rejects_unknown_extension(tmp_path: Path):
    explicit = tmp_path / "custom.cfg"
    explicit.write_text("rules = {}\n")
    loader = ConfigLoader(tmp_path, _defaults())

    with pytest.raises(ConfigError, match="Unsupported config file extension"):
        loader.load(explicit)


def test_explicit_config_path_rejects_missing_file(tmp_path: Path):
    loader = ConfigLoader(tmp_path, _defaults())

    with pytest.raises(ConfigError, match="Config file does not exist"):
        loader.load(tmp_path / "missing.yaml")


def test_toml_tool_section_must_be_table(tmp_path: Path):
    explicit = tmp_path / "pyproject.toml"
    explicit.write_text('tool = "not-a-table"\n')
    loader = ConfigLoader(tmp_path, _defaults())

    with pytest.raises(ConfigError, match=r"\[tool\] must be a table"):
        loader.load(explicit)


def test_yaml_paths_ignore_applied(tmp_path: Path):
    (tmp_path / ".gruff-py.yaml").write_text(
        "schemaVersion: gruff-py.config.v0.1\npaths:\n  ignore:\n    - build/\n    - .venv/\n"
    )
    loader = ConfigLoader(tmp_path, _defaults())
    config, _ = loader.load()
    assert config.ignored_path_patterns == ("build/", ".venv/")


def test_yaml_selection_applied(tmp_path: Path):
    (tmp_path / ".gruff-py.yaml").write_text(
        "schemaVersion: gruff-py.config.v0.1\n"
        "selection:\n"
        "  pillars:\n"
        "    - size\n"
        "    - complexity\n"
        "  excludeRules:\n"
        "    - size.file-length\n"
    )
    loader = ConfigLoader(tmp_path, _defaults())
    config, _ = loader.load()
    assert config.rule_selection.pillars == ("size", "complexity")
    assert config.rule_selection.exclude_rules == ("size.file-length",)


@pytest.mark.parametrize(
    ("key", "value", "message"),
    [
        ("tiers", "v9.9", "selection].tiers"),
        ("pillars", "made-up", "selection].pillars"),
        ("excludePillars", "made-up", "selection].excludePillars"),
        ("rules", "size.nope", "selection].rules"),
        ("excludeRules", "size.nope", "selection].excludeRules"),
    ],
    ids=["tiers", "pillars", "exclude-pillars", "rules", "exclude-rules"],
)
def test_yaml_selection_rejects_unknown_values(
    tmp_path: Path,
    key: str,
    value: str,
    message: str,
):
    (tmp_path / ".gruff-py.yaml").write_text(
        f"schemaVersion: gruff-py.config.v0.1\nselection:\n  {key}:\n    - {value}\n"
    )
    loader = ConfigLoader(tmp_path, _defaults())

    with pytest.raises(ConfigError, match=message):
        loader.load()


def test_rule_enabled_must_be_boolean(tmp_path: Path):
    (tmp_path / ".gruff-py.yaml").write_text(
        'schemaVersion: gruff-py.config.v0.1\nrules:\n  size.file-length:\n    enabled: "false"\n'
    )
    loader = ConfigLoader(tmp_path, _defaults())

    with pytest.raises(ConfigError, match="enabled"):
        loader.load()


def test_yaml_unknown_top_level_key_raises(tmp_path: Path):
    (tmp_path / ".gruff-py.yaml").write_text("garbage: 1\n")
    loader = ConfigLoader(tmp_path, _defaults())

    with pytest.raises(ConfigError, match="Unknown gruff keys"):
        loader.load()


def test_empty_gruff_py_yaml_falls_through_to_defaults_with_yaml_as_source(tmp_path: Path):
    (tmp_path / ".gruff-py.yaml").write_text("")
    loader = ConfigLoader(tmp_path, _defaults())
    config, source = loader.load()
    assert source == tmp_path / ".gruff-py.yaml"
    assert config == _defaults()
