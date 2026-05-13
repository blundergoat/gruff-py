"""Precedence + format-detection tests for ConfigLoader (ADR-006)."""

from pathlib import Path

from gruff.config.analysis_config import AnalysisConfig
from gruff.config.loader import ConfigLoader
from gruff.rule.registry import RuleRegistry


def _defaults() -> AnalysisConfig:
    return AnalysisConfig.from_registry(RuleRegistry.defaults())


def test_no_config_files_returns_defaults_and_none_source(tmp_path: Path):
    loader = ConfigLoader(tmp_path, _defaults())
    config, source = loader.load()
    assert source is None
    assert config == _defaults()


def test_gruff_yaml_wins_over_pyproject_toml(tmp_path: Path):
    # Both files exist. YAML overrides size.file-length warning to 250;
    # pyproject sets it to 400. YAML must win.
    (tmp_path / ".gruff.yaml").write_text(
        "rules:\n  size.file-length:\n    thresholds:\n      warning: 250\n      error: 600\n"
    )
    (tmp_path / "pyproject.toml").write_text(
        '[tool.gruff.rules."size.file-length"]\n'
        "enabled = true\n"
        "thresholds = { warning = 400, error = 800 }\n"
    )
    loader = ConfigLoader(tmp_path, _defaults())
    config, source = loader.load()
    assert source == tmp_path / ".gruff.yaml"
    assert config.rules["size.file-length"].thresholds["warning"] == 250


def test_pyproject_used_when_only_pyproject_exists(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.gruff.rules."size.file-length"]\n'
        "enabled = true\n"
        "thresholds = { warning = 333, error = 999 }\n"
    )
    loader = ConfigLoader(tmp_path, _defaults())
    config, source = loader.load()
    assert source == tmp_path / "pyproject.toml"
    assert config.rules["size.file-length"].thresholds["warning"] == 333


def test_explicit_yaml_path_overrides_discovery(tmp_path: Path):
    (tmp_path / ".gruff.yaml").write_text(
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
        '[tool.gruff.rules."size.file-length"]\nthresholds = { warning = 222, error = 444 }\n'
    )
    loader = ConfigLoader(tmp_path, _defaults())
    config, source = loader.load(explicit)
    assert source == explicit
    assert config.rules["size.file-length"].thresholds["warning"] == 222


def test_yaml_paths_ignore_applied(tmp_path: Path):
    (tmp_path / ".gruff.yaml").write_text("paths:\n  ignore:\n    - build/\n    - .venv/\n")
    loader = ConfigLoader(tmp_path, _defaults())
    config, _ = loader.load()
    assert config.ignored_path_patterns == ("build/", ".venv/")


def test_yaml_selection_applied(tmp_path: Path):
    (tmp_path / ".gruff.yaml").write_text(
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
    (tmp_path / ".gruff.yaml").write_text("garbage: 1\n")
    loader = ConfigLoader(tmp_path, _defaults())
    import pytest

    from gruff.config.exceptions import ConfigError

    with pytest.raises(ConfigError, match="Unknown gruff keys"):
        loader.load()


def test_empty_gruff_yaml_falls_through_to_defaults_with_yaml_as_source(tmp_path: Path):
    (tmp_path / ".gruff.yaml").write_text("")
    loader = ConfigLoader(tmp_path, _defaults())
    config, source = loader.load()
    assert source == tmp_path / ".gruff.yaml"
    assert config == _defaults()
