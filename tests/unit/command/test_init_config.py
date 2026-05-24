import os
import stat
from pathlib import Path

import pytest
import yaml

from gruffpy.command.init_config import (
    DEFAULT_INIT_IGNORED_PATH_PATTERNS,
    existing_config_source,
    existing_ignored_path_patterns,
    render_default_config_yaml,
)
from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.exceptions import ConfigError
from gruffpy.config.loader import ConfigLoader
from gruffpy.rule.registry import RuleRegistry


def test_render_default_config_yaml_starts_with_header() -> None:
    rendered = render_default_config_yaml()
    assert rendered.startswith("# gruff-py configuration - .gruff-py.yaml\n")


def test_render_default_config_yaml_round_trips_through_loader(tmp_path: Path) -> None:
    target = tmp_path / ".gruff-py.yaml"
    target.write_text(render_default_config_yaml())

    defaults = AnalysisConfig.from_registry(RuleRegistry.defaults()).with_ignored_path_patterns(
        DEFAULT_INIT_IGNORED_PATH_PATTERNS
    )
    loader = ConfigLoader(tmp_path, defaults)
    loaded, source = loader.load()

    assert source == target
    assert loaded == defaults


def test_render_default_config_yaml_lists_every_registered_rule() -> None:
    document = yaml.safe_load(render_default_config_yaml())
    registered_ids = {rule.definition().id for rule in RuleRegistry.defaults().all()}
    assert set(document["rules"]) == registered_ids


def test_render_default_config_yaml_prefills_starter_ignore_patterns() -> None:
    document = yaml.safe_load(render_default_config_yaml())
    assert document["paths"]["ignore"] == list(DEFAULT_INIT_IGNORED_PATH_PATTERNS)


def test_render_default_config_yaml_preserves_existing_ignore_patterns() -> None:
    document = yaml.safe_load(render_default_config_yaml(("generated/**", ".codex/")))
    assert document["paths"]["ignore"] == [
        "generated/**",
        ".codex/",
        ".agents/",
        ".antigravitycli/",
        ".claude/",
        ".github/",
        ".goat-flow/",
        "tests/fixtures/**",
    ]


def test_render_default_config_yaml_omits_empty_threshold_and_option_dicts() -> None:
    document = yaml.safe_load(render_default_config_yaml())
    bare_rule = document["rules"]["dead-code.unused-private-attribute"]
    assert bare_rule == {"enabled": True}


def test_render_default_config_yaml_keeps_warning_error_thresholds() -> None:
    document = yaml.safe_load(render_default_config_yaml())
    cyclomatic = document["rules"]["complexity.cyclomatic"]
    assert cyclomatic["thresholds"] == {"warning": 10, "error": 20}


def test_existing_config_source_returns_none_for_empty_directory(tmp_path: Path) -> None:
    assert existing_config_source(tmp_path) is None


def test_existing_config_source_finds_modern_yaml(tmp_path: Path) -> None:
    target = tmp_path / ".gruff-py.yaml"
    target.write_text("rules: {}\n")
    assert existing_config_source(tmp_path) == target


def test_existing_config_source_finds_legacy_yaml(tmp_path: Path) -> None:
    target = tmp_path / ".gruff.yaml"
    target.write_text("rules: {}\n")
    assert existing_config_source(tmp_path) == target


def test_existing_config_source_finds_pyproject_table(tmp_path: Path) -> None:
    target = tmp_path / "pyproject.toml"
    target.write_text("[tool.gruff-py]\nminimumPythonVersion = '3.11'\n")
    assert existing_config_source(tmp_path) == target


def test_existing_config_source_finds_legacy_pyproject_table(tmp_path: Path) -> None:
    target = tmp_path / "pyproject.toml"
    target.write_text("[tool.gruff]\n")
    assert existing_config_source(tmp_path) == target


def test_existing_config_source_ignores_pyproject_without_gruff_table(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'demo'\n")
    assert existing_config_source(tmp_path) is None


def test_existing_config_source_reports_unparseable_pyproject(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("this is = not = valid toml\n[[")
    assert existing_config_source(tmp_path) == pyproject


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0,
    reason="chmod 0 read-denial only enforced on POSIX as a non-root user.",
)
def test_existing_config_source_reports_unreadable_pyproject(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[tool.gruff-py]\n")
    pyproject.chmod(0)
    try:
        assert existing_config_source(tmp_path) == pyproject
    finally:
        pyproject.chmod(stat.S_IRUSR | stat.S_IWUSR)


def test_existing_ignored_path_patterns_reads_yaml_ignore_list(tmp_path: Path) -> None:
    target = tmp_path / ".gruff-py.yaml"
    target.write_text("paths:\n  ignore:\n    - generated/**\n    - .codex/\n")
    assert existing_ignored_path_patterns(target) == ("generated/**", ".codex/")


def test_existing_ignored_path_patterns_rejects_malformed_ignore_list(tmp_path: Path) -> None:
    target = tmp_path / ".gruff-py.yaml"
    target.write_text("paths:\n  ignore: generated/**\n")

    with pytest.raises(ConfigError, match="paths.ignore must be a list of strings"):
        existing_ignored_path_patterns(target)
