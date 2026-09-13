"""User config generation, preservation, and fail-closed command tests.

Users reach this path through ``gruff-py init`` when creating or canonically
regenerating project settings. The suite pins full semantic round-trips,
alternate-source refusal, atomic failure behavior, and the family seed.
"""

import os
import stat
from pathlib import Path

import pytest
import yaml

from gruffpy.command import init_config
from gruffpy.command.init_config import (
    DEFAULT_INIT_IGNORED_PATH_PATTERNS,
    existing_config_source,
    render_default_config_yaml,
)
from gruffpy.config.analysis_config import (
    MINIMUM_SEVERITY_BINARY_DEFAULTS,
    AnalysisConfig,
    DeepScanBudget,
)
from gruffpy.config.exceptions import ConfigError
from gruffpy.config.loader import ConfigLoader
from gruffpy.rule.registry import RuleRegistry

_FAMILY_ACCEPTED_ABBREVIATIONS = (
    "age",
    "app",
    "db",
    "fs",
    "id",
    "io",
    "key",
    "log",
    "max",
    "min",
    "now",
    "raw",
    "rx",
    "tx",
    "ui",
    "url",
)

# Mode `open()` requests for a new file before the process umask narrows it.
_NEW_FILE_BASE_MODE = 0o666
# A deliberate non-default mode a user would set on their own config.
_USER_CHOSEN_TARGET_MODE = 0o640

_FULLY_CUSTOMISED_YAML = (
    "schemaVersion: gruff-py.config.v0.1\n"
    "minimumPythonVersion: '3.12'\n"
    "failOn:\n  analyse: error\n  report: warning\n  dashboard: advisory\n"
    "outputVolumeHintThreshold: 7\n"
    "paths:\n  ignore:\n    - custom/**\n"
    "allowlists:\n"
    "  acceptedAbbreviations:\n    - biz\n"
    "  deadCode:\n"
    "    symbols:\n    - retained_symbol\n"
    "    decorators:\n    - retained_decorator\n"
    "    paths:\n    - retained/**\n"
    "selection:\n"
    "  tiers:\n    - v0.1\n"
    "  pillars:\n    - security\n"
    "  rules:\n    - security.weak-crypto\n"
    "  excludePillars:\n    - naming\n"
    "  excludeRules:\n    - security.ssrf\n"
    "rules:\n"
    "  size.file-length:\n"
    "    enabled: false\n"
    "    threshold: 777\n"
    "    severity: warning\n"
    "  test-quality.eager-test:\n"
    "    enabled: false\n"
    "    thresholds:\n"
    "      maxAssertions: 9\n"
    "  naming.boolean-prefix:\n"
    "    enabled: true\n"
    "    options:\n"
    "      acceptedBooleanNames:\n"
    "      - ready\n"
)

_DIFFERENT_CONFIG_SOURCES = (
    (
        ".gruff.yaml",
        "schemaVersion: gruff-py.config.v0.1\n",
        "migrate-config",
    ),
    (
        "pyproject.toml",
        '[tool.gruff-py]\nschemaVersion = "gruff-py.config.v0.1"\n',
        "TOML",
    ),
    (
        "pyproject.toml",
        '[tool.gruff]\nschemaVersion = "gruff-py.config.v0.1"\n',
        "TOML",
    ),
)


def _strict_loaded_config(project_root: Path) -> AnalysisConfig:
    """Load the user's active config with every warning promoted to failure.

    Args:
        project_root: Temporary project whose discovered config should be loaded.

    Returns:
        Fully resolved config; no empty/default fallback is accepted silently.
    """
    defaults = AnalysisConfig.from_registry(RuleRegistry.defaults())
    loaded, _ = ConfigLoader(project_root, defaults, strict=True).load()
    return loaded


def test_render_default_config_yaml_starts_with_header() -> None:
    rendered = render_default_config_yaml()
    assert rendered.startswith("# gruff-py configuration - .gruff-py.yaml\n")


def test_render_default_config_yaml_round_trips_through_loader(tmp_path: Path) -> None:
    target = tmp_path / ".gruff-py.yaml"
    target.write_text(render_default_config_yaml())

    defaults = (
        AnalysisConfig.from_registry(RuleRegistry.defaults())
        .with_ignored_path_patterns(DEFAULT_INIT_IGNORED_PATH_PATTERNS)
        .with_minimum_severity(MINIMUM_SEVERITY_BINARY_DEFAULTS)
        .with_deep_scan_budget(DeepScanBudget(override="config"))
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


def test_render_default_config_yaml_omits_the_removed_secret_previews_key() -> None:
    """Section 5 removed the key, so a generated file offering it would fail to load on the port that wrote it."""
    document = yaml.safe_load(render_default_config_yaml())

    assert "secretPreviews" not in document["allowlists"]


def test_render_default_config_yaml_omits_empty_threshold_and_option_dicts() -> None:
    document = yaml.safe_load(render_default_config_yaml())
    bare_rule = document["rules"]["dead-code.unused-private-attribute"]
    assert bare_rule == {"enabled": True}


def test_render_default_config_yaml_shows_markdown_sanitizer_defaults() -> None:
    """Show strict labels and vetted URL encoders in a user's generated config."""
    document = yaml.safe_load(render_default_config_yaml())
    markdown_rule = document["rules"]["security.unsanitized-markdown-interpolation"]

    assert markdown_rule["options"] == {
        "labelSanitizers": [],
        "urlSanitizers": ["urllib.parse.quote", "urllib.parse.quote_plus"],
    }


def test_render_default_config_yaml_uses_single_threshold_and_severity() -> None:
    document = yaml.safe_load(render_default_config_yaml())
    cyclomatic = document["rules"]["complexity.cyclomatic"]
    assert cyclomatic["threshold"] == 20
    assert cyclomatic["severity"] == "error"
    assert "thresholds" not in cyclomatic


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


def test_init_default_render_emits_canonical_three_key_block_when_no_user_input() -> None:
    """Without a prior config, the renderer writes all three binary defaults."""
    document = yaml.safe_load(render_default_config_yaml())
    assert document["failOn"] == {
        "analyse": "advisory",
        "report": "none",
        "dashboard": "none",
    }


def test_rendered_accepted_abbreviation_seed_matches_family_contract() -> None:
    """Keep the universal naming seed visible with replace-not-merge guidance."""
    rendered = render_default_config_yaml()
    document = yaml.safe_load(rendered)
    accepted_key = "  acceptedAbbreviations:"
    accepted_key_index = rendered.splitlines().index(accepted_key)
    lines = rendered.splitlines()

    assert document["allowlists"]["acceptedAbbreviations"] == list(_FAMILY_ACCEPTED_ABBREVIATIONS)
    assert lines[accepted_key_index - 2] == ("  # acceptedAbbreviations lets naming rules accept project vocabulary.")
    assert lines[accepted_key_index - 1] == ("  # Configured values replace this seed; they do not merge with it.")


def test_init_force_preserves_all_supported_semantics(tmp_path: Path) -> None:
    """Keep every loaded user setting equal after canonical regeneration.

    Args:
        tmp_path: Project containing a valid target with every supported surface.
    """
    target = tmp_path / ".gruff-py.yaml"
    target.write_text(_FULLY_CUSTOMISED_YAML)
    before = _strict_loaded_config(tmp_path)

    written_target = init_config.initialise_project_config(tmp_path, force=True)
    after = _strict_loaded_config(tmp_path)

    assert written_target == target
    assert after == before


@pytest.mark.skipif(os.name != "posix", reason="umask-derived modes only apply on POSIX.")
@pytest.mark.parametrize("active_umask", (0o022, 0o077), ids=("umask-022", "umask-077"))
def test_init_generates_the_same_mode_as_every_other_config_writer(
    tmp_path: Path,
    active_umask: int,
) -> None:
    """Match the mode a plain write produces, rather than mkstemp's private 0600.

    Args:
        tmp_path: Empty project so init takes the first-time branch.
        active_umask: Process umask under which both writers create their file.
    """
    previous_umask = os.umask(active_umask)
    try:
        written_target = init_config.initialise_project_config(tmp_path, force=False)
        plain_write = tmp_path / "written-the-ordinary-way.yaml"
        plain_write.write_text("compare: mode\n")

        init_mode = stat.S_IMODE(written_target.stat().st_mode)
        assert init_mode == stat.S_IMODE(plain_write.stat().st_mode)
        assert init_mode == _NEW_FILE_BASE_MODE & ~active_umask
    finally:
        os.umask(previous_umask)


@pytest.mark.skipif(os.name != "posix", reason="umask-derived modes only apply on POSIX.")
def test_init_force_preserves_an_existing_target_mode(tmp_path: Path) -> None:
    """Keep a user's deliberate config permissions across canonical regeneration.

    Args:
        tmp_path: Project whose existing target carries a non-default mode.
    """
    target = tmp_path / ".gruff-py.yaml"
    target.write_text(_FULLY_CUSTOMISED_YAML)
    target.chmod(_USER_CHOSEN_TARGET_MODE)

    written_target = init_config.initialise_project_config(tmp_path, force=True)

    assert stat.S_IMODE(written_target.stat().st_mode) == _USER_CHOSEN_TARGET_MODE


@pytest.mark.parametrize(
    ("source_name", "source_text", "expected_guidance"),
    _DIFFERENT_CONFIG_SOURCES,
    ids=("legacy-yaml", "modern-toml", "legacy-toml"),
)
def test_init_force_rejects_different_source(
    tmp_path: Path,
    source_name: str,
    source_text: str,
    expected_guidance: str,
) -> None:
    """Leave an authoritative non-target source untouched and create no YAML.

    Args:
        tmp_path: Project containing the alternate source.
        source_name: Legacy YAML or pyproject filename discovered by the loader.
        source_text: Original bytes that must remain unchanged after refusal.
        expected_guidance: Format-correct recovery word shown to the user.
    """
    source = tmp_path / source_name
    source.write_text(source_text)

    with pytest.raises(ConfigError, match=expected_guidance):
        init_config.initialise_project_config(tmp_path, force=True)

    assert source.read_text() == source_text
    assert not (tmp_path / ".gruff-py.yaml").exists()


def test_init_force_rejects_invalid_target_without_changing_bytes(tmp_path: Path) -> None:
    """Keep malformed target bytes when the user asks for force regeneration.

    Args:
        tmp_path: Project containing a target with an unknown config surface.
    """
    target = tmp_path / ".gruff-py.yaml"
    original = "schemaVersion: gruff-py.config.v0.1\nunknownSurface: keep-me\n"
    target.write_text(original)

    with pytest.raises(ConfigError, match="left unchanged"):
        init_config.initialise_project_config(tmp_path, force=True)

    assert target.read_text() == original


def test_init_force_rejects_rendered_semantic_change_before_replace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep the original target when rendered YAML reloads differently.

    Args:
        tmp_path: Project containing a valid fully customised target.
        monkeypatch: Fixture that substitutes a valid but semantically different render.
    """
    target = tmp_path / ".gruff-py.yaml"
    target.write_text(_FULLY_CUSTOMISED_YAML)
    original = target.read_text()
    different_rendered_config = render_default_config_yaml()

    def render_different_config(resolved_config: AnalysisConfig) -> str:
        """Model a renderer that silently discards the user's settings.

        Args:
            resolved_config: Loaded settings deliberately ignored by the broken render.

        Returns:
            Valid starter YAML with different user-visible semantics.
        """
        del resolved_config
        return different_rendered_config

    monkeypatch.setattr(
        init_config,
        "render_resolved_config_yaml",
        render_different_config,
        raising=False,
    )

    with pytest.raises(ConfigError, match="semantic validation"):
        init_config.initialise_project_config(tmp_path, force=True)

    assert target.read_text() == original
    assert list(tmp_path.glob(".gruff-py.yaml.*.yaml")) == []


def test_init_force_atomic_replace_failure_keeps_original_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep the user file intact when the final filesystem replace fails.

    Args:
        tmp_path: Project containing a valid target before replacement.
        monkeypatch: Fixture that models a filesystem replace error.
    """
    target = tmp_path / ".gruff-py.yaml"
    target.write_text(_FULLY_CUSTOMISED_YAML)
    original = target.read_text()

    def deny_user_config_replacement(staged_config_path: Path, user_config_path: Path) -> None:
        """Model a user filesystem that refuses the final atomic rename.

        Args:
            staged_config_path: Valid temporary config awaiting the rename.
            user_config_path: Existing user file that must remain byte-identical.

        Raises:
            OSError: Always, as if filesystem permissions denied the replacement.
        """
        del staged_config_path, user_config_path
        raise OSError("replace denied")

    monkeypatch.setattr(
        init_config.os,
        "replace",
        deny_user_config_replacement,
        raising=False,
    )

    with pytest.raises(ConfigError, match="Unable to replace"):
        init_config.initialise_project_config(tmp_path, force=True)

    assert target.read_text() == original
    assert list(tmp_path.glob(".gruff-py.yaml.*.yaml")) == []
