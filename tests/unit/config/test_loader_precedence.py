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
        "rules:\n  size.file-length:\n    thresholds:\n      warning: 250\n      error: 600\n"
    )
    (tmp_path / "pyproject.toml").write_text(
        '[tool.gruff-py.rules."size.file-length"]\n'
        "enabled = true\n"
        "thresholds = { warning = 400, error = 800 }\n"
    )
    loader = ConfigLoader(tmp_path, _defaults())
    config, source = loader.load()
    assert source == tmp_path / ".gruff-py.yaml"
    assert config.rules["size.file-length"].thresholds["warning"] == 250


def test_pyproject_used_when_only_pyproject_exists(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.gruff-py.rules."size.file-length"]\n'
        "enabled = true\n"
        "thresholds = { warning = 333, error = 999 }\n"
    )
    loader = ConfigLoader(tmp_path, _defaults())
    config, source = loader.load()
    assert source == tmp_path / "pyproject.toml"
    assert config.rules["size.file-length"].thresholds["warning"] == 333


def test_explicit_yaml_path_overrides_discovery(tmp_path: Path):
    (tmp_path / ".gruff-py.yaml").write_text(
        "rules:\n  size.file-length:\n    thresholds:\n      warning: 100\n"
    )
    explicit = tmp_path / "custom.yaml"
    explicit.write_text("rules:\n  size.file-length:\n    thresholds:\n      warning: 555\n")
    loader = ConfigLoader(tmp_path, _defaults())
    config, source = loader.load(explicit)
    assert source == explicit
    assert config.rules["size.file-length"].thresholds["warning"] == 555


def test_explicit_toml_path_supported(tmp_path: Path):
    explicit = tmp_path / "custom.toml"
    explicit.write_text(
        '[tool.gruff-py.rules."size.file-length"]\nthresholds = { warning = 222, error = 444 }\n'
    )
    loader = ConfigLoader(tmp_path, _defaults())
    config, source = loader.load(explicit)
    assert source == explicit
    assert config.rules["size.file-length"].thresholds["warning"] == 222


def test_threshold_and_severity_override_warning_error_rule(tmp_path: Path):
    (tmp_path / ".gruff-py.yaml").write_text(
        "rules:\n  size.file-length:\n    threshold: 900\n    severity: error\n"
    )
    loader = ConfigLoader(tmp_path, _defaults())

    config, _ = loader.load()
    settings = config.rule_settings("size.file-length")

    assert settings.severity_threshold is not None
    assert settings.severity_threshold.threshold == 900
    assert settings.severity_threshold.severity.value == "error"
    assert settings.high_value_threshold_match(900) is None
    match = settings.high_value_threshold_match(901)
    assert match is not None
    assert match.threshold == 900
    assert match.severity.value == "error"


def test_threshold_and_warning_severity_supported(tmp_path: Path):
    (tmp_path / ".gruff-py.yaml").write_text(
        "rules:\n  size.file-length:\n    threshold: 500\n    severity: warning\n"
    )
    loader = ConfigLoader(tmp_path, _defaults())

    config, _ = loader.load()
    settings = config.rule_settings("size.file-length")
    match = settings.high_value_threshold_match(501)

    assert match is not None
    assert match.severity.value == "warning"


def test_threshold_and_severity_override_low_value_rule(tmp_path: Path):
    (tmp_path / ".gruff-py.yaml").write_text(
        "rules:\n  complexity.maintainability-index:\n    threshold: 60\n    severity: error\n"
    )
    loader = ConfigLoader(tmp_path, _defaults())

    config, _ = loader.load()
    settings = config.rule_settings("complexity.maintainability-index")

    assert settings.low_value_threshold_match(60) is None
    match = settings.low_value_threshold_match(59)
    assert match is not None
    assert match.threshold == 60
    assert match.severity.value == "error"


def test_threshold_requires_severity(tmp_path: Path):
    (tmp_path / ".gruff-py.yaml").write_text("rules:\n  size.file-length:\n    threshold: 900\n")
    loader = ConfigLoader(tmp_path, _defaults())

    with pytest.raises(ConfigError, match='severity" must be "warning" or "error"'):
        loader.load()


def test_severity_requires_threshold(tmp_path: Path):
    (tmp_path / ".gruff-py.yaml").write_text("rules:\n  size.file-length:\n    severity: error\n")
    loader = ConfigLoader(tmp_path, _defaults())

    with pytest.raises(ConfigError, match='severity" requires "threshold"'):
        loader.load()


def test_threshold_rejects_named_threshold_rule(tmp_path: Path):
    (tmp_path / ".gruff-py.yaml").write_text(
        "rules:\n  test-quality.eager-test:\n    threshold: 5\n    severity: error\n"
    )
    loader = ConfigLoader(tmp_path, _defaults())

    with pytest.raises(ConfigError, match="only supported for rules with warning/error"):
        loader.load()


def test_threshold_and_thresholds_cannot_be_combined(tmp_path: Path):
    (tmp_path / ".gruff-py.yaml").write_text(
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


def test_yaml_paths_ignore_applied(tmp_path: Path):
    (tmp_path / ".gruff-py.yaml").write_text("paths:\n  ignore:\n    - build/\n    - .venv/\n")
    loader = ConfigLoader(tmp_path, _defaults())
    config, _ = loader.load()
    assert config.ignored_path_patterns == ("build/", ".venv/")


def test_yaml_selection_applied(tmp_path: Path):
    (tmp_path / ".gruff-py.yaml").write_text(
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
