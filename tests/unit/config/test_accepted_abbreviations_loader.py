"""Verify the allowlist settings users can load from YAML and TOML.

The suite protects naming-seed replacement and the removal of ``secretPreviews``. Section 5 makes category
markers unconditional, so any configuration naming the key is refused before a scan begins.
"""

from pathlib import Path

import pytest

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.exceptions import ConfigError
from gruffpy.config.loader import LEGACY_SECRET_PREVIEWS_ERROR, ConfigLoader
from gruffpy.rule.registry import RuleRegistry


def _defaults() -> AnalysisConfig:
    return AnalysisConfig.from_registry(RuleRegistry.defaults())


def _yaml(tmp_path: Path, body: str) -> Path:
    path = tmp_path / ".gruff-py.yaml"
    path.write_text("schemaVersion: gruff-py.config.v0.1\n" + body)
    return path


def _toml(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "pyproject.toml"
    path.write_text('[tool.gruff-py]\nschemaVersion = "gruff-py.config.v0.1"\n' + body)
    return path


def test_default_accepted_abbreviations_survive_unrelated_allowlists_section(tmp_path: Path):
    _yaml(tmp_path, "allowlists:\n  deadCode:\n    symbols: []\n")

    config, _ = ConfigLoader(tmp_path, _defaults()).load()

    assert config.accepted_abbreviations == _defaults().accepted_abbreviations
    assert "id" in config.accepted_abbreviations


def test_explicit_accepted_abbreviations_replace_defaults(tmp_path: Path):
    _yaml(tmp_path, "allowlists:\n  acceptedAbbreviations: ['ctx', 'cfg']\n")

    config, _ = ConfigLoader(tmp_path, _defaults()).load()

    assert config.accepted_abbreviations == ("ctx", "cfg")


def test_empty_accepted_abbreviations_list_clears_defaults(tmp_path: Path):
    _yaml(tmp_path, "allowlists:\n  acceptedAbbreviations: []\n")

    config, _ = ConfigLoader(tmp_path, _defaults()).load()

    assert config.accepted_abbreviations == ()


def test_default_secret_previews_survive_unrelated_allowlists_section(tmp_path: Path):
    _yaml(tmp_path, "allowlists:\n  acceptedAbbreviations: ['ctx']\n")

    config, _ = ConfigLoader(tmp_path, _defaults()).load()

    assert config.allowed_secret_previews == _defaults().allowed_secret_previews


def test_accepted_abbreviations_rejects_non_list_value(tmp_path: Path):
    _yaml(tmp_path, "allowlists:\n  acceptedAbbreviations: not-a-list\n")

    with pytest.raises(ConfigError, match="acceptedAbbreviations"):
        ConfigLoader(tmp_path, _defaults()).load()


def test_accepted_abbreviations_rejects_non_string_entry(tmp_path: Path):
    _yaml(tmp_path, "allowlists:\n  acceptedAbbreviations:\n      - ctx\n      - 7\n")

    with pytest.raises(ConfigError, match="acceptedAbbreviations"):
        ConfigLoader(tmp_path, _defaults()).load()


@pytest.mark.parametrize(
    "configured_value",
    ("['known-fixture']", "not-a-list", "{}", "null", "['']", "[known, 42]"),
    ids=("nonempty-list", "scalar", "empty-object", "null", "blank-entry", "mixed-list"),
)
def test_secret_previews_rejects_every_value_except_an_empty_list(tmp_path: Path, configured_value: str):
    _yaml(tmp_path, f"allowlists:\n  secretPreviews: {configured_value}\n")

    with pytest.raises(ConfigError) as error:
        ConfigLoader(tmp_path, _defaults()).load()

    assert str(error.value) == LEGACY_SECRET_PREVIEWS_ERROR
    assert "known-fixture" not in str(error.value)


def test_toml_secret_previews_is_refused_even_when_empty(tmp_path: Path):
    """An empty list reads as configured redaction just as a populated one does, so presence is what is refused.

    Args:
        tmp_path: Temporary project the configuration is written into.
    """
    _toml(tmp_path, "\n[tool.gruff-py.allowlists]\nsecretPreviews = []\n")

    with pytest.raises(ConfigError) as error:
        ConfigLoader(tmp_path, _defaults()).load()

    assert str(error.value) == LEGACY_SECRET_PREVIEWS_ERROR


def test_toml_secret_previews_rejects_a_configured_preview(tmp_path: Path):
    _toml(tmp_path, '\n[tool.gruff-py.allowlists]\nsecretPreviews = ["known-fixture"]\n')

    with pytest.raises(ConfigError) as error:
        ConfigLoader(tmp_path, _defaults()).load()

    assert str(error.value) == LEGACY_SECRET_PREVIEWS_ERROR
    assert "known-fixture" not in str(error.value)
