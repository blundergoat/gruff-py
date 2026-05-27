"""Loader parses and validates `allowlists.deadCode`. See ADR-015."""

from pathlib import Path

import pytest

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.exceptions import ConfigError
from gruffpy.config.loader import ConfigLoader
from gruffpy.rule.registry import RuleRegistry


def _defaults() -> AnalysisConfig:
    return AnalysisConfig.from_registry(RuleRegistry.defaults())


def _yaml(tmp_path: Path, body: str) -> Path:
    path = tmp_path / ".gruff-py.yaml"
    path.write_text("schemaVersion: gruff-py.config.v0.1\n" + body)
    return path


def test_dead_code_allowlist_parses_all_axes(tmp_path: Path):
    _yaml(
        tmp_path,
        "allowlists:\n"
        "  deadCode:\n"
        "    symbols:\n"
        "      - Service._token\n"
        "    decorators:\n"
        "      - register_event\n"
        "    paths:\n"
        "      - tests/fixtures/**/*.py\n",
    )
    config, _ = ConfigLoader(tmp_path, _defaults()).load()
    allowlist = config.dead_code_allowlist
    assert allowlist.symbols == ("Service._token",)
    assert allowlist.decorators == ("register_event",)
    assert allowlist.paths == ("tests/fixtures/**/*.py",)


def test_dead_code_allowlist_defaults_empty_when_section_absent(tmp_path: Path):
    _yaml(tmp_path, "allowlists:\n  acceptedAbbreviations: ['cfg']\n")
    config, _ = ConfigLoader(tmp_path, _defaults()).load()
    assert config.dead_code_allowlist.symbols == ()
    assert config.dead_code_allowlist.decorators == ()
    assert config.dead_code_allowlist.paths == ()


def test_dead_code_allowlist_rejects_unknown_subkey(tmp_path: Path):
    _yaml(
        tmp_path,
        "allowlists:\n  deadCode:\n    classes:\n      - Foo\n",
    )
    with pytest.raises(ConfigError, match="allowlists.deadCode"):
        ConfigLoader(tmp_path, _defaults()).load()


def test_dead_code_allowlist_rejects_non_list_value(tmp_path: Path):
    _yaml(
        tmp_path,
        "allowlists:\n  deadCode:\n    symbols: not-a-list\n",
    )
    with pytest.raises(ConfigError, match="symbols"):
        ConfigLoader(tmp_path, _defaults()).load()


def test_dead_code_allowlist_rejects_non_string_entry(tmp_path: Path):
    _yaml(
        tmp_path,
        "allowlists:\n  deadCode:\n    symbols:\n      - 42\n",
    )
    with pytest.raises(ConfigError, match="symbols"):
        ConfigLoader(tmp_path, _defaults()).load()


def test_dead_code_allowlist_rejects_non_table(tmp_path: Path):
    _yaml(tmp_path, "allowlists:\n  deadCode: not-a-table\n")
    with pytest.raises(ConfigError, match="allowlists.deadCode"):
        ConfigLoader(tmp_path, _defaults()).load()


def test_dead_code_allowlist_allows_partial_section(tmp_path: Path):
    _yaml(
        tmp_path,
        "allowlists:\n  deadCode:\n    symbols:\n      - Foo._bar\n",
    )
    config, _ = ConfigLoader(tmp_path, _defaults()).load()
    assert config.dead_code_allowlist.symbols == ("Foo._bar",)
    assert config.dead_code_allowlist.decorators == ()
    assert config.dead_code_allowlist.paths == ()
