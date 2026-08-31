"""User-facing warning and strict-error contracts for rule configuration.

Normal scans continue with unsupported rule keys removed and explain what was
ignored. Strict scans stop on the same exact key without claiming it was
ignored, so CI users never mistake a rejected config for an applied one.
"""

import re
from pathlib import Path

import pytest

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.exceptions import ConfigError
from gruffpy.config.loader import ConfigLoader
from gruffpy.rule.registry import RuleRegistry

_LEGACY_COGNITIVE_YAML = (
    "schemaVersion: gruff-py.config.v0.1\nrules:\n  complexity.cognitive:\n    enabled: true\n    thresholds:\n      warning: 15\n      error: 30\n"
)

_CUSTOM_MIN_FIELDS = 6
_UNKNOWN_OPTION_WITH_VALID_SIBLING_YAML = (
    "schemaVersion: gruff-py.config.v0.1\n"
    "rules:\n"
    "  docs.dataclass-attributes:\n"
    "    options:\n"
    f"      min_fields: {_CUSTOM_MIN_FIELDS}\n"
    "      allowBullet: false\n"
)

_MARKDOWN_RULE_ID = "security.unsanitized-markdown-interpolation"


def _markdown_options_yaml(option_lines: str) -> str:
    """Place sanitizer option YAML under the public Markdown rule.

    Args:
        option_lines: Already-indented option entries; empty means no overrides.

    Returns:
        Complete config text a user could place in ``.gruff-py.yaml``.
    """
    return f"schemaVersion: gruff-py.config.v0.1\nrules:\n  {_MARKDOWN_RULE_ID}:\n    options:\n{option_lines}"


def _defaults() -> AnalysisConfig:
    return AnalysisConfig.from_registry(RuleRegistry.defaults())


def _write_yaml(tmp_path: Path, body: str) -> None:
    (tmp_path / ".gruff-py.yaml").write_text(body)


def test_legacy_tiered_thresholds_warn_and_rule_keeps_defaults(tmp_path: Path):
    _write_yaml(tmp_path, _LEGACY_COGNITIVE_YAML)
    loader = ConfigLoader(tmp_path, _defaults())
    config, source = loader.load()
    assert source == tmp_path / ".gruff-py.yaml"
    assert len(loader.warnings) == 2
    assert config.rules["complexity.cognitive"] == _defaults().rules["complexity.cognitive"]


def test_legacy_threshold_warning_lists_accepted_keys_and_migration_hint(tmp_path: Path):
    _write_yaml(tmp_path, _LEGACY_COGNITIVE_YAML)
    loader = ConfigLoader(tmp_path, _defaults())
    loader.load()
    first = loader.warnings[0]
    assert 'Unknown threshold "rules.complexity.cognitive.thresholds.warning"' in first
    assert 'Accepted keys for "rules.complexity.cognitive": enabled, threshold, severity' in first
    assert "gruff-py migrate-config" in first
    assert "TOML" in first
    assert "init --force" not in first


def test_legacy_tiered_thresholds_raise_under_strict(tmp_path: Path):
    _write_yaml(tmp_path, _LEGACY_COGNITIVE_YAML)
    loader = ConfigLoader(tmp_path, _defaults(), strict=True)
    with pytest.raises(ConfigError) as excinfo:
        loader.load()
    message = str(excinfo.value)
    assert 'Unknown threshold "rules.complexity.cognitive.thresholds.warning"' in message
    assert "Accepted keys" in message
    # The lenient consequence must not leak into the abort-path error text.
    assert "ignored" not in message.lower()


def _unknown_option_warning(project_root: Path) -> str:
    """Load one option typo and return its sole user-facing warning.

    Args:
        project_root: Project containing one valid option and one misspelled option.

    Returns:
        Non-empty warning text; an absent warning fails the one-item unpack.
    """
    _write_yaml(project_root, _UNKNOWN_OPTION_WITH_VALID_SIBLING_YAML)
    loader = ConfigLoader(project_root, _defaults())
    loader.load()
    (warning,) = loader.warnings
    return warning


def _strict_unknown_option_error(project_root: Path) -> str:
    """Load one option typo in strict mode and return the blocking message.

    Args:
        project_root: Project containing one valid option and one misspelled option.

    Returns:
        Non-empty error text explaining why the user's config was rejected.
    """
    _write_yaml(project_root, _UNKNOWN_OPTION_WITH_VALID_SIBLING_YAML)

    with pytest.raises(ConfigError) as error:
        ConfigLoader(project_root, _defaults(), strict=True).load()

    return str(error.value)


def test_unknown_option_warning_names_key_and_lenient_consequence(tmp_path: Path) -> None:
    """Show the exact ignored key and what a normal scan still applies.

    Args:
        tmp_path: Project containing one valid option and one misspelled option.
    """
    warning = _unknown_option_warning(tmp_path)

    assert 'Unknown option "rules.docs.dataclass-attributes.options.allowBullet".' in warning
    assert "Option ignored; registered defaults and valid sibling options still apply." in warning


def test_unknown_option_warning_lists_registered_alternatives(tmp_path: Path) -> None:
    """List every registered option name that can replace the user's typo.

    Args:
        tmp_path: Project containing one valid option and one misspelled option.
    """
    warning = _unknown_option_warning(tmp_path)

    assert "options.allow_bullets" in warning
    assert "options.min_fields" in warning
    assert "options.require_all_fields" in warning


def test_unknown_option_keeps_valid_sibling_and_registered_default(tmp_path: Path) -> None:
    """Apply a valid sibling while the misspelling leaves its default intact.

    Args:
        tmp_path: Project containing one valid option and one misspelled option.
    """
    _write_yaml(tmp_path, _UNKNOWN_OPTION_WITH_VALID_SIBLING_YAML)
    defaults = _defaults()
    loader = ConfigLoader(tmp_path, defaults)

    config, _ = loader.load()
    options = config.rules["docs.dataclass-attributes"].options

    assert options["min_fields"] == _CUSTOM_MIN_FIELDS
    assert options["allow_bullets"] is defaults.rules["docs.dataclass-attributes"].options["allow_bullets"]
    assert "allowBullet" not in options


def test_unknown_option_strict_error_names_key_without_lenient_consequence(
    tmp_path: Path,
) -> None:
    """Stop strict users on the typo without saying an ignored key was applied.

    Args:
        tmp_path: Project containing one valid option and one misspelled option.
    """
    message = _strict_unknown_option_error(tmp_path)

    assert 'Unknown option "rules.docs.dataclass-attributes.options.allowBullet".' in message
    assert "ignored" not in message.lower()


def test_unknown_option_strict_error_lists_registered_alternatives(tmp_path: Path) -> None:
    """Give strict users every registered option name that can replace the typo.

    Args:
        tmp_path: Project containing one valid option and one misspelled option.
    """
    message = _strict_unknown_option_error(tmp_path)

    assert "options.allow_bullets" in message
    assert "options.min_fields" in message
    assert "options.require_all_fields" in message


@pytest.mark.parametrize(
    ("option_lines", "expected_message"),
    [
        (
            "      labelSanitizers: markdown_label\n",
            "must be a list of exact Python call targets",
        ),
        (
            "      labelSanitizers:\n        - ''\n",
            "contains invalid call target ''",
        ),
        (
            "      urlSanitizers:\n        - helpers.*\n",
            "contains invalid call target 'helpers.*'",
        ),
        (
            "      urlSanitizers:\n        - helpers.markdown_url\n        - 7\n",
            "contains invalid call target 7",
        ),
    ],
    ids=["scalar", "empty", "wildcard", "non-text"],
)
def test_markdown_sanitizer_options_reject_ambiguous_targets(
    tmp_path: Path,
    option_lines: str,
    expected_message: str,
) -> None:
    """Stop before scanning when a user helper cannot map to one exact call.

    Args:
        tmp_path: Project receiving the invalid sanitizer configuration.
        option_lines: User option value exercising one invalid public shape.
        expected_message: Stable explanation fragment shown for that shape.
    """
    _write_yaml(tmp_path, _markdown_options_yaml(option_lines))

    with pytest.raises(ConfigError, match=re.escape(expected_message)):
        ConfigLoader(tmp_path, _defaults()).load()


def test_markdown_sanitizer_options_accept_exact_targets_and_empty_strict_mode(
    tmp_path: Path,
) -> None:
    """Keep exact label helpers while an empty URL list trusts no call.

    Args:
        tmp_path: Project receiving a valid slot-asymmetric configuration.
    """
    _write_yaml(
        tmp_path,
        _markdown_options_yaml("      labelSanitizers:\n        - markdown_label\n        - helpers.markdown_label\n      urlSanitizers: []\n"),
    )

    config, _ = ConfigLoader(tmp_path, _defaults(), strict=True).load()

    assert config.rules[_MARKDOWN_RULE_ID].options == {
        "labelSanitizers": ["markdown_label", "helpers.markdown_label"],
        "urlSanitizers": [],
    }


def test_markdown_sanitizer_toml_rejects_wildcard_target(tmp_path: Path) -> None:
    """Apply the same exact-target error to users configuring pyproject TOML.

    Args:
        tmp_path: Project receiving a TOML wildcard sanitizer target.
    """
    (tmp_path / "pyproject.toml").write_text(
        "[tool.gruff-py]\n"
        'schemaVersion = "gruff-py.config.v0.1"\n'
        f'[tool.gruff-py.rules."{_MARKDOWN_RULE_ID}".options]\n'
        'urlSanitizers = ["helpers.*"]\n'
    )

    with pytest.raises(ConfigError, match=r"contains invalid call target 'helpers\.\*'"):
        ConfigLoader(tmp_path, _defaults()).load()


def test_unknown_rule_id_warns_and_section_is_skipped(tmp_path: Path):
    _write_yaml(
        tmp_path,
        "schemaVersion: gruff-py.config.v0.1\nrules:\n  complexity.npath:\n    enabled: false\n",
    )
    loader = ConfigLoader(tmp_path, _defaults())
    config, _ = loader.load()
    assert len(loader.warnings) == 1
    assert 'Unknown rule id "complexity.npath"' in loader.warnings[0]
    assert config.rules == _defaults().rules


def test_unknown_rule_section_key_warns_and_rest_applies(tmp_path: Path):
    _write_yaml(
        tmp_path,
        "schemaVersion: gruff-py.config.v0.1\nrules:\n  naming.module-name-mismatch:\n    enabled: false\n    flavour: spicy\n",
    )
    loader = ConfigLoader(tmp_path, _defaults())
    config, _ = loader.load()
    assert len(loader.warnings) == 1
    assert 'Unknown key "rules.naming.module-name-mismatch.flavour"' in loader.warnings[0]
    assert config.rules["naming.module-name-mismatch"].enabled is False


def test_threshold_on_non_rubric_rule_warns_and_is_dropped(tmp_path: Path):
    _write_yaml(
        tmp_path,
        "schemaVersion: gruff-py.config.v0.1\nrules:\n  naming.module-name-mismatch:\n    threshold: 5\n    severity: warning\n",
    )
    loader = ConfigLoader(tmp_path, _defaults())
    config, _ = loader.load()
    assert len(loader.warnings) == 1
    assert "only supported for severity-threshold rubrics" in loader.warnings[0]
    assert config.rules["naming.module-name-mismatch"].severity_threshold is None


def test_severity_without_threshold_warns_and_is_dropped(tmp_path: Path):
    _write_yaml(
        tmp_path,
        "schemaVersion: gruff-py.config.v0.1\nrules:\n  size.file-length:\n    severity: error\n",
    )
    loader = ConfigLoader(tmp_path, _defaults())
    config, _ = loader.load()
    assert len(loader.warnings) == 1
    assert 'requires "threshold"' in loader.warnings[0]
    assert config.rules["size.file-length"] == _defaults().rules["size.file-length"]


def test_structural_rule_section_error_still_raises_without_strict(tmp_path: Path):
    _write_yaml(
        tmp_path,
        "schemaVersion: gruff-py.config.v0.1\nrules:\n  size.file-length: 12\n",
    )
    loader = ConfigLoader(tmp_path, _defaults())
    with pytest.raises(ConfigError, match="must be a table"):
        loader.load()


def test_unknown_top_level_key_still_raises_without_strict(tmp_path: Path):
    _write_yaml(
        tmp_path,
        "schemaVersion: gruff-py.config.v0.1\nbananas: true\n",
    )
    loader = ConfigLoader(tmp_path, _defaults())
    with pytest.raises(ConfigError, match="Unknown gruff keys"):
        loader.load()


def test_warnings_reset_between_loads(tmp_path: Path):
    _write_yaml(tmp_path, _LEGACY_COGNITIVE_YAML)
    loader = ConfigLoader(tmp_path, _defaults())
    loader.load()
    assert len(loader.warnings) == 2
    _write_yaml(tmp_path, "schemaVersion: gruff-py.config.v0.1\n")
    loader.load()
    assert loader.warnings == ()
