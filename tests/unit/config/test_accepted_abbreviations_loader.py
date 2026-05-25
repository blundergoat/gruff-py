"""Loader preserves seeded ``accepted_abbreviations`` defaults when the key is absent."""

from pathlib import Path

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.loader import ConfigLoader
from gruffpy.rule.registry import RuleRegistry


def _defaults() -> AnalysisConfig:
    return AnalysisConfig.from_registry(RuleRegistry.defaults())


def _yaml(tmp_path: Path, body: str) -> Path:
    path = tmp_path / ".gruff-py.yaml"
    path.write_text(body)
    return path


def test_default_accepted_abbreviations_survive_unrelated_allowlists_section(tmp_path: Path):
    _yaml(tmp_path, "allowlists:\n  secretPreviews: ['known-fixture']\n")

    config, _ = ConfigLoader(tmp_path, _defaults()).load()

    assert config.accepted_abbreviations == _defaults().accepted_abbreviations
    assert "id" in config.accepted_abbreviations
    assert config.allowed_secret_previews == ("known-fixture",)


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
