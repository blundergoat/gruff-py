"""Config precedence and shared YAML/TOML validation journeys.

Users reach this loader through every command that reads project settings.
These tests keep source discovery, rule overrides, lenient warnings, and strict
failures identical across both supported configuration formats (ADR-006).
"""

from pathlib import Path

import pytest

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.exceptions import ConfigError
from gruffpy.config.loader import ConfigLoader
from gruffpy.rule.registry import RuleRegistry


def _defaults() -> AnalysisConfig:
    """Build the analysis config the registry's defaults produce.

    Returns:
        The default configuration.
    """
    return AnalysisConfig.from_registry(RuleRegistry.defaults())


_YAML_WINNING_THRESHOLD = 250
_PYPROJECT_LOSING_THRESHOLD = 400
_LEGACY_YAML_THRESHOLD = 321
_PYPROJECT_ONLY_THRESHOLD = 333
_LEGACY_PYPROJECT_THRESHOLD = 444
_MODERN_PYPROJECT_THRESHOLD = 222
_EXPLICIT_YAML_THRESHOLD = 555
_EXPLICIT_TOML_THRESHOLD = 222
_CUSTOM_MIN_FIELDS = 6

_VALID_OPTION_CONFIGS = (
    pytest.param(
        ".gruff-py.yaml",
        f"""schemaVersion: gruff-py.config.v0.1
rules:
  docs.dataclass-attributes:
    options:
      min_fields: {_CUSTOM_MIN_FIELDS}
""",
        id="yaml",
    ),
    pytest.param(
        "pyproject.toml",
        f"""[tool.gruff-py]
schemaVersion = "gruff-py.config.v0.1"
[tool.gruff-py.rules."docs.dataclass-attributes".options]
min_fields = {_CUSTOM_MIN_FIELDS}
""",
        id="toml",
    ),
)

_UNKNOWN_OPTION_CONFIGS = (
    pytest.param(
        ".gruff-py.yaml",
        f"""schemaVersion: gruff-py.config.v0.1
rules:
  docs.dataclass-attributes:
    options:
      min_fields: {_CUSTOM_MIN_FIELDS}
      allowBullet: false
""",
        "rules.docs.dataclass-attributes.options.allowBullet",
        id="yaml-with-defaults",
    ),
    pytest.param(
        "pyproject.toml",
        f"""[tool.gruff-py]
schemaVersion = "gruff-py.config.v0.1"
[tool.gruff-py.rules."docs.dataclass-attributes".options]
min_fields = {_CUSTOM_MIN_FIELDS}
allowBullet = false
""",
        "rules.docs.dataclass-attributes.options.allowBullet",
        id="toml-with-defaults",
    ),
)

_NO_DEFAULT_OPTION_CONFIGS = (
    pytest.param(
        ".gruff-py.yaml",
        """schemaVersion: gruff-py.config.v0.1
rules:
  size.file-length:
    options:
      unexpected: true
""",
        "rules.size.file-length.options.unexpected",
        id="yaml-without-defaults",
    ),
    pytest.param(
        "pyproject.toml",
        """[tool.gruff-py]
schemaVersion = "gruff-py.config.v0.1"
[tool.gruff-py.rules."size.file-length".options]
unexpected = true
""",
        "rules.size.file-length.options.unexpected",
        id="toml-without-defaults",
    ),
)


def _write_option_config(project_root: Path, config_name: str, config_text: str) -> None:
    """Place one YAML or TOML option fixture where a user would configure it.

    Args:
        project_root: Temporary project that receives the config source.
        config_name: Discovery filename for the selected format; never empty.
        config_text: Full fixture text to write as supplied. Empty text leaves a zero-byte file.

    Returns:
        None. Writes the fixture text to the selected config file, replacing any existing contents.
    """
    (project_root / config_name).write_text(config_text)


@pytest.mark.parametrize(("config_name", "config_text"), _VALID_OPTION_CONFIGS)
def test_valid_option_override_loads_identically_from_yaml_and_toml(
    tmp_path: Path,
    config_name: str,
    config_text: str,
) -> None:
    """Apply a registered option override without warning in either format.

    Args:
        tmp_path: Project receiving the YAML or TOML source.
        config_name: Discovery filename selected by the parameterized format.
        config_text: Valid option override expressed in that format.

    Returns:
        None. Checks that each format loads the min_fields override without warnings.
    """
    _write_option_config(tmp_path, config_name, config_text)
    loader = ConfigLoader(tmp_path, _defaults())

    config, _ = loader.load()

    assert loader.warnings == ()
    assert config.rules["docs.dataclass-attributes"].options["min_fields"] == _CUSTOM_MIN_FIELDS


@pytest.mark.parametrize(
    ("config_name", "config_text", "unknown_option_key"),
    _UNKNOWN_OPTION_CONFIGS,
)
def test_unknown_option_yaml_or_toml_warns_and_keeps_valid_sibling(
    tmp_path: Path,
    config_name: str,
    config_text: str,
    unknown_option_key: str,
) -> None:
    """Ignore a typo while preserving a valid sibling and the registered allow_bullets default.

    Args:
        tmp_path: Project receiving the YAML or TOML source.
        config_name: Discovery filename selected by the parameterized format.
        config_text: Config containing one valid option and one typo.
        unknown_option_key: Full dotted typo users must see in the warning.

    Returns:
        None. Checks that one warning names the discarded typo and that the valid override and registered default remain.
    """
    _write_option_config(tmp_path, config_name, config_text)
    defaults = _defaults()
    loader = ConfigLoader(tmp_path, defaults)

    config, _ = loader.load()
    options = config.rules["docs.dataclass-attributes"].options

    assert len(loader.warnings) == 1
    assert unknown_option_key in loader.warnings[0]
    assert options["min_fields"] == _CUSTOM_MIN_FIELDS
    assert options["allow_bullets"] is defaults.rules["docs.dataclass-attributes"].options["allow_bullets"]
    assert "allowBullet" not in options


@pytest.mark.parametrize(
    ("config_name", "config_text", "unknown_option_key"),
    _NO_DEFAULT_OPTION_CONFIGS,
)
def test_unknown_option_yaml_or_toml_is_rejected_when_rule_has_no_options(
    tmp_path: Path,
    config_name: str,
    config_text: str,
    unknown_option_key: str,
) -> None:
    """Warn about an option on a rule that supports none and leave the rule's options empty.

    Args:
        tmp_path: Project receiving the YAML or TOML source.
        config_name: Discovery filename selected by the parameterized format.
        config_text: Config containing an option where none are supported.
        unknown_option_key: Full dotted key users must see in the warning.

    Returns:
        None. Checks that one warning names the unsupported key and that the loaded rule has no options.
    """
    _write_option_config(tmp_path, config_name, config_text)
    loader = ConfigLoader(tmp_path, _defaults())

    config, _ = loader.load()

    assert len(loader.warnings) == 1
    assert unknown_option_key in loader.warnings[0]
    assert config.rules["size.file-length"].options == {}


@pytest.mark.parametrize(
    ("config_name", "config_text", "unknown_option_key"),
    (*_UNKNOWN_OPTION_CONFIGS, *_NO_DEFAULT_OPTION_CONFIGS),
)
def test_unknown_option_yaml_or_toml_raises_with_accepted_names_under_strict(
    tmp_path: Path,
    config_name: str,
    config_text: str,
    unknown_option_key: str,
) -> None:
    """Require strict loading to report the unsupported key and an Accepted keys hint without calling it ignored.

    Args:
        tmp_path: Project receiving the YAML or TOML source.
        config_name: Discovery filename selected by the parameterized format.
        config_text: Config containing an unsupported option key.
        unknown_option_key: Full dotted key users must see in the error.

    Returns:
        None. Checks that the strict error names the unsupported key, includes an Accepted keys hint, and omits the word ignored.
    """
    _write_option_config(tmp_path, config_name, config_text)

    with pytest.raises(ConfigError) as error:
        ConfigLoader(tmp_path, _defaults(), strict=True).load()

    message = str(error.value)
    assert unknown_option_key in message
    assert "Accepted keys" in message
    assert "ignored" not in message.lower()


def test_no_config_files_returns_defaults_and_none_source(tmp_path: Path):
    """Return the registry defaults and no source when the project has no config file.

    Args:
        tmp_path: Empty project root.

    Returns:
        None. Checks that loading a project without a config file yields the registry defaults and no source path.
    """
    loader = ConfigLoader(tmp_path, _defaults())
    config, source = loader.load()
    assert source is None
    assert config == _defaults()


def test_gruff_py_yaml_wins_over_pyproject_toml(tmp_path: Path):
    """Prefer .gruff-py.yaml over pyproject.toml when both set the file-length threshold.

    Args:
        tmp_path: Project root holding both files with different file-length thresholds.

    Returns:
        None. Checks that discovery selects .gruff-py.yaml and applies its file-length threshold when pyproject.toml is also present.
    """
    (tmp_path / ".gruff-py.yaml").write_text(
        f"schemaVersion: gruff-py.config.v0.1\nrules:\n  size.file-length:\n    threshold: {_YAML_WINNING_THRESHOLD}\n    severity: error\n"
    )
    (tmp_path / "pyproject.toml").write_text(
        "[tool.gruff-py]\n"
        'schemaVersion = "gruff-py.config.v0.1"\n'
        '[tool.gruff-py.rules."size.file-length"]\n'
        "enabled = true\n"
        f'threshold = {_PYPROJECT_LOSING_THRESHOLD}\nseverity = "error"\n'
    )
    loader = ConfigLoader(tmp_path, _defaults())
    config, source = loader.load()
    assert source == tmp_path / ".gruff-py.yaml"
    assert config.rules["size.file-length"].severity_threshold.threshold == _YAML_WINNING_THRESHOLD


def test_gruff_py_yaml_wins_over_legacy_gruff_yaml(tmp_path: Path):
    """Prefer .gruff-py.yaml over a legacy .gruff.yaml when both set the file-length threshold.

    Args:
        tmp_path: Project root holding both YAML files with different thresholds.

    Returns:
        None. Checks that discovery selects .gruff-py.yaml and applies its threshold when both YAML names are present.
    """
    (tmp_path / ".gruff-py.yaml").write_text(
        f"schemaVersion: gruff-py.config.v0.1\nrules:\n  size.file-length:\n    threshold: {_YAML_WINNING_THRESHOLD}\n    severity: error\n"
    )
    (tmp_path / ".gruff.yaml").write_text(
        f"schemaVersion: gruff-py.config.v0.1\nrules:\n  size.file-length:\n    threshold: {_PYPROJECT_LOSING_THRESHOLD}\n    severity: error\n"
    )
    loader = ConfigLoader(tmp_path, _defaults())
    config, source = loader.load()
    assert source == tmp_path / ".gruff-py.yaml"
    assert config.rules["size.file-length"].severity_threshold.threshold == _YAML_WINNING_THRESHOLD


def test_legacy_gruff_yaml_is_discovered(tmp_path: Path):
    """Discover and apply a legacy .gruff.yaml when it is the only config.

    Args:
        tmp_path: Project root holding only a legacy .gruff.yaml.

    Returns:
        None. Checks that discovery selects the sole legacy .gruff.yaml and applies its file-length threshold.
    """
    (tmp_path / ".gruff.yaml").write_text(
        f"schemaVersion: gruff-py.config.v0.1\nrules:\n  size.file-length:\n    threshold: {_LEGACY_YAML_THRESHOLD}\n    severity: error\n"
    )
    loader = ConfigLoader(tmp_path, _defaults())
    config, source = loader.load()
    assert source == tmp_path / ".gruff.yaml"
    assert config.rules["size.file-length"].severity_threshold.threshold == _LEGACY_YAML_THRESHOLD


def test_pyproject_used_when_only_pyproject_exists(tmp_path: Path):
    """Load pyproject.toml when it is the only config.

    Args:
        tmp_path: Project root holding only a pyproject.toml with a gruff-py table.

    Returns:
        None. Checks that discovery reports pyproject.toml as the source and applies its file-length threshold.
    """
    (tmp_path / "pyproject.toml").write_text(
        "[tool.gruff-py]\n"
        'schemaVersion = "gruff-py.config.v0.1"\n'
        '[tool.gruff-py.rules."size.file-length"]\n'
        "enabled = true\n"
        f'threshold = {_PYPROJECT_ONLY_THRESHOLD}\nseverity = "error"\n'
    )
    loader = ConfigLoader(tmp_path, _defaults())
    config, source = loader.load()
    assert source == tmp_path / "pyproject.toml"
    assert config.rules["size.file-length"].severity_threshold.threshold == _PYPROJECT_ONLY_THRESHOLD


def test_legacy_pyproject_table_is_supported(tmp_path: Path):
    """Load a legacy tool.gruff table from pyproject.toml.

    Args:
        tmp_path: Project root whose pyproject.toml holds only the legacy table.

    Returns:
        None. Checks that the legacy tool.gruff table supplies the threshold and pyproject.toml is reported as the source.
    """
    (tmp_path / "pyproject.toml").write_text(
        "[tool.gruff]\n"
        'schemaVersion = "gruff-py.config.v0.1"\n'
        '[tool.gruff.rules."size.file-length"]\n'
        "enabled = true\n"
        f'threshold = {_LEGACY_PYPROJECT_THRESHOLD}\nseverity = "error"\n'
    )
    loader = ConfigLoader(tmp_path, _defaults())
    config, source = loader.load()
    assert source == tmp_path / "pyproject.toml"
    assert config.rules["size.file-length"].severity_threshold.threshold == _LEGACY_PYPROJECT_THRESHOLD


def test_modern_pyproject_table_wins_over_legacy_table(tmp_path: Path):
    """Prefer the tool.gruff-py table over a legacy tool.gruff table in the same pyproject.toml.

    Args:
        tmp_path: Project root whose pyproject.toml holds both tables with different thresholds.

    Returns:
        None. Checks that pyproject.toml supplies the modern table's threshold when both tables are present.
    """
    (tmp_path / "pyproject.toml").write_text(
        "[tool.gruff-py]\n"
        'schemaVersion = "gruff-py.config.v0.1"\n'
        '[tool.gruff-py.rules."size.file-length"]\n'
        f'threshold = {_MODERN_PYPROJECT_THRESHOLD}\nseverity = "error"\n'
        '[tool.gruff.rules."size.file-length"]\n'
        f'threshold = {_LEGACY_PYPROJECT_THRESHOLD}\nseverity = "error"\n'
    )
    loader = ConfigLoader(tmp_path, _defaults())
    config, source = loader.load()
    assert source == tmp_path / "pyproject.toml"
    assert config.rules["size.file-length"].severity_threshold.threshold == _MODERN_PYPROJECT_THRESHOLD


def test_explicit_yaml_path_overrides_discovery(tmp_path: Path):
    """Load an explicit YAML path instead of the discovered .gruff-py.yaml.

    Args:
        tmp_path: Project root holding a discovered config and a custom.yaml with another threshold.

    Returns:
        None. Checks that the loader reports the explicit YAML path and uses its threshold even when a discoverable config exists.
    """
    (tmp_path / ".gruff-py.yaml").write_text(
        "schemaVersion: gruff-py.config.v0.1\nrules:\n  size.file-length:\n    threshold: 100\n    severity: error\n"
    )
    explicit = tmp_path / "custom.yaml"
    explicit.write_text(
        f"schemaVersion: gruff-py.config.v0.1\nrules:\n  size.file-length:\n    threshold: {_EXPLICIT_YAML_THRESHOLD}\n    severity: error\n"
    )
    loader = ConfigLoader(tmp_path, _defaults())
    config, source = loader.load(explicit)
    assert source == explicit
    assert config.rules["size.file-length"].severity_threshold.threshold == _EXPLICIT_YAML_THRESHOLD


def test_explicit_toml_path_supported(tmp_path: Path):
    """Load an explicit TOML path that holds a gruff-py table.

    Args:
        tmp_path: Project root holding custom.toml.

    Returns:
        None. Checks that the loader reports the explicit TOML path and applies the file-length threshold from its gruff-py table.
    """
    explicit = tmp_path / "custom.toml"
    explicit.write_text(
        "[tool.gruff-py]\n"
        'schemaVersion = "gruff-py.config.v0.1"\n'
        '[tool.gruff-py.rules."size.file-length"]\n'
        f'threshold = {_EXPLICIT_TOML_THRESHOLD}\nseverity = "error"\n'
    )
    loader = ConfigLoader(tmp_path, _defaults())
    config, source = loader.load(explicit)
    assert source == explicit
    assert config.rules["size.file-length"].severity_threshold.threshold == _EXPLICIT_TOML_THRESHOLD


_HIGH_THRESHOLD_BOUNDARY = 900
_LOW_THRESHOLD_BOUNDARY = 60


def _settings_with_high_threshold_override(tmp_path: Path):
    """Load a config that sets the file-length rule to a threshold of 900 at error severity.

    Args:
        tmp_path: Project root that receives the config.

    Returns:
        The loaded file-length rule settings.
    """
    (tmp_path / ".gruff-py.yaml").write_text(
        f"schemaVersion: gruff-py.config.v0.1\nrules:\n  size.file-length:\n    threshold: {_HIGH_THRESHOLD_BOUNDARY}\n    severity: error\n"
    )
    config, _ = ConfigLoader(tmp_path, _defaults()).load()
    return config.rule_settings("size.file-length")


def test_severity_threshold_override_stores_value(tmp_path: Path):
    """Store a configured threshold of 900 and error severity on the file-length settings.

    Args:
        tmp_path: Project root for the 900-line file-length override.

    Returns:
        None. Checks that the file-length settings store the configured threshold and error severity.
    """
    settings = _settings_with_high_threshold_override(tmp_path)
    assert settings.severity_threshold is not None
    assert settings.severity_threshold.threshold == _HIGH_THRESHOLD_BOUNDARY
    assert settings.severity_threshold.severity.value == "error"


def test_severity_threshold_override_does_not_match_at_boundary(tmp_path: Path):
    """Report no match for a value exactly at a high-value threshold.

    Args:
        tmp_path: Project root for the 900-line file-length override.

    Returns:
        None. Checks that a value equal to the configured high-value threshold produces no match.
    """
    settings = _settings_with_high_threshold_override(tmp_path)
    assert settings.high_value_threshold_match(_HIGH_THRESHOLD_BOUNDARY) is None


def test_severity_threshold_override_matches_just_above_boundary(tmp_path: Path):
    """Match a value one above a high-value threshold with that threshold and error severity.

    Args:
        tmp_path: Project root for the 900-line file-length override.

    Returns:
        None. Checks that one above the boundary yields a match carrying the configured threshold and error severity.
    """
    settings = _settings_with_high_threshold_override(tmp_path)
    match = settings.high_value_threshold_match(_HIGH_THRESHOLD_BOUNDARY + 1)
    assert match is not None
    assert match.threshold == _HIGH_THRESHOLD_BOUNDARY
    assert match.severity.value == "error"


def test_threshold_and_warning_severity_supported(tmp_path: Path):
    """Match a value above a configured threshold at warning severity when the config sets warning.

    Args:
        tmp_path: Project root whose config sets file length to 500 at warning severity.

    Returns:
        None. Checks that a value above the configured threshold matches at warning severity.
    """
    (tmp_path / ".gruff-py.yaml").write_text(
        "schemaVersion: gruff-py.config.v0.1\nrules:\n  size.file-length:\n    threshold: 500\n    severity: warning\n"
    )
    loader = ConfigLoader(tmp_path, _defaults())

    config, _ = loader.load()
    settings = config.rule_settings("size.file-length")
    match = settings.high_value_threshold_match(501)

    assert match is not None
    assert match.severity.value == "warning"


def _settings_with_low_threshold_override(tmp_path: Path):
    """Load a config that sets the function-length rule to a threshold of 60 at error severity.

    Args:
        tmp_path: Project root that receives the config.

    Returns:
        The loaded function-length rule settings.
    """
    (tmp_path / ".gruff-py.yaml").write_text(
        f"schemaVersion: gruff-py.config.v0.1\nrules:\n  size.function-length:\n    threshold: {_LOW_THRESHOLD_BOUNDARY}\n    severity: error\n"
    )
    config, _ = ConfigLoader(tmp_path, _defaults()).load()
    return config.rule_settings("size.function-length")


def test_low_value_threshold_override_does_not_match_at_boundary(tmp_path: Path):
    """Report no match for a value exactly at a low-value threshold.

    Args:
        tmp_path: Project root for the 60-line function-length override.

    Returns:
        None. Checks that a value equal to the configured low-value threshold produces no match.
    """
    settings = _settings_with_low_threshold_override(tmp_path)
    assert settings.low_value_threshold_match(_LOW_THRESHOLD_BOUNDARY) is None


def test_low_value_threshold_override_matches_just_below_boundary(tmp_path: Path):
    """Match a value one below a low-value threshold with that threshold and error severity.

    Args:
        tmp_path: Project root for the 60-line function-length override.

    Returns:
        None. Checks that one below the boundary yields a match carrying the configured threshold and error severity.
    """
    settings = _settings_with_low_threshold_override(tmp_path)
    match = settings.low_value_threshold_match(_LOW_THRESHOLD_BOUNDARY - 1)
    assert match is not None
    assert match.threshold == _LOW_THRESHOLD_BOUNDARY
    assert match.severity.value == "error"


def test_threshold_requires_severity(tmp_path: Path):
    """Refuse a threshold without a severity, with a ConfigError naming the allowed severities.

    Args:
        tmp_path: Project root whose config gives file length a threshold alone.

    Returns:
        None. Checks that a threshold without a severity raises ConfigError naming warning and error as the allowed values.
    """
    (tmp_path / ".gruff-py.yaml").write_text("schemaVersion: gruff-py.config.v0.1\nrules:\n  size.file-length:\n    threshold: 900\n")
    loader = ConfigLoader(tmp_path, _defaults())

    with pytest.raises(ConfigError, match='severity" must be "warning" or "error"'):
        loader.load()


def test_severity_requires_threshold_warns_by_default_and_raises_under_strict(tmp_path: Path):
    """Warn about a severity set without a threshold and keep the rule's defaults, but raise under strict loading.

    Args:
        tmp_path: Project root whose config gives file length a severity alone.

    Returns:
        None. Checks that a severity alone warns and leaves the rule at its defaults in lenient mode and raises ConfigError in strict mode.
    """
    (tmp_path / ".gruff-py.yaml").write_text("schemaVersion: gruff-py.config.v0.1\nrules:\n  size.file-length:\n    severity: error\n")
    loader = ConfigLoader(tmp_path, _defaults())
    config, _ = loader.load()
    assert any('severity" requires "threshold"' in warning for warning in loader.warnings)
    assert config.rules["size.file-length"] == _defaults().rules["size.file-length"]

    with pytest.raises(ConfigError, match='severity" requires "threshold"'):
        ConfigLoader(tmp_path, _defaults(), strict=True).load()


def test_threshold_on_named_threshold_rule_warns_by_default_and_raises_under_strict(
    tmp_path: Path,
):
    """Warn about a single threshold on a rule that uses named thresholds and keep its defaults, but raise under strict loading.

    Args:
        tmp_path: Project root whose config gives the excessive-mocking rule a threshold and severity.

    Returns:
        None. Checks that the unsupported threshold warns and preserves defaults in lenient mode and raises ConfigError in strict mode.
    """
    (tmp_path / ".gruff-py.yaml").write_text(
        "schemaVersion: gruff-py.config.v0.1\nrules:\n  test-quality.excessive-mocking:\n    threshold: 5\n    severity: error\n"
    )
    loader = ConfigLoader(tmp_path, _defaults())
    config, _ = loader.load()
    assert any("only supported for severity-threshold rubrics" in warning for warning in loader.warnings)
    assert config.rules["test-quality.excessive-mocking"] == _defaults().rules["test-quality.excessive-mocking"]

    with pytest.raises(ConfigError, match="only supported for severity-threshold rubrics"):
        ConfigLoader(tmp_path, _defaults(), strict=True).load()


def test_threshold_with_legacy_tier_block_warns_and_keeps_explicit_threshold(tmp_path: Path):
    """Keep an explicit threshold beside a leftover legacy tier, warning about the tier, but raise under strict loading.

    Args:
        tmp_path: Project root whose file-length section holds a threshold, a severity and a legacy warning tier.

    Returns:
        None. Checks that lenient loading warns and keeps the explicit threshold and that strict loading raises ConfigError.
    """
    # Discarding the obsolete warning entry prevents the two threshold formats from conflicting in lenient loading.
    # The CLI exposes the loader's strict mode through --strict-config.
    (tmp_path / ".gruff-py.yaml").write_text(
        "schemaVersion: gruff-py.config.v0.1\n"
        "rules:\n"
        "  size.file-length:\n"
        f"    threshold: {_HIGH_THRESHOLD_BOUNDARY}\n"
        "    severity: error\n"
        "    thresholds:\n"
        "      warning: 500\n"
    )
    loader = ConfigLoader(tmp_path, _defaults())
    config, _ = loader.load()
    assert any('thresholds.warning"' in warning for warning in loader.warnings)
    rubric = config.rules["size.file-length"].severity_threshold
    assert rubric is not None
    assert rubric.threshold == _HIGH_THRESHOLD_BOUNDARY

    with pytest.raises(ConfigError, match='Unknown threshold "rules.size.file-length'):
        ConfigLoader(tmp_path, _defaults(), strict=True).load()


def test_unknown_named_threshold_warns_by_default_and_raises_under_strict(tmp_path: Path):
    """Warn about an unknown named threshold and keep the rule's defaults, but raise under strict loading.

    Args:
        tmp_path: Project root whose excessive-mocking section sets an unknown warning threshold.

    Returns:
        None. Checks that the unknown threshold warns and preserves defaults in lenient mode and raises ConfigError in strict mode.
    """
    (tmp_path / ".gruff-py.yaml").write_text(
        "schemaVersion: gruff-py.config.v0.1\nrules:\n  test-quality.excessive-mocking:\n    thresholds:\n      warning: 5\n"
    )
    loader = ConfigLoader(tmp_path, _defaults())
    config, _ = loader.load()
    assert any('Unknown threshold "rules.test-quality.excessive-mocking' in warning for warning in loader.warnings)
    assert config.rules["test-quality.excessive-mocking"] == _defaults().rules["test-quality.excessive-mocking"]

    with pytest.raises(ConfigError, match='Unknown threshold "rules.test-quality.excessive-mocking'):
        ConfigLoader(tmp_path, _defaults(), strict=True).load()


def test_explicit_config_path_rejects_unknown_extension(tmp_path: Path):
    """Refuse an explicit config path with an unsupported extension.

    Args:
        tmp_path: Project root holding a custom.cfg file.

    Returns:
        None. Checks that loading an explicit file with an unsupported extension raises ConfigError.
    """
    explicit = tmp_path / "custom.cfg"
    explicit.write_text("rules = {}\n")
    loader = ConfigLoader(tmp_path, _defaults())

    with pytest.raises(ConfigError, match="Unsupported config file extension"):
        loader.load(explicit)


def test_explicit_config_path_rejects_missing_file(tmp_path: Path):
    """Refuse an explicit config path that does not exist.

    Args:
        tmp_path: Project root where the named config is never written.

    Returns:
        None. Checks that an explicit path to a missing config raises ConfigError identifying the file as absent.
    """
    loader = ConfigLoader(tmp_path, _defaults())

    with pytest.raises(ConfigError, match="Config file does not exist"):
        loader.load(tmp_path / "missing.yaml")


def test_toml_tool_section_must_be_table(tmp_path: Path):
    """Refuse a TOML file whose tool key is not a table.

    Args:
        tmp_path: Project root whose pyproject.toml sets tool to a string.

    Returns:
        None. Checks that loading a TOML file with a string-valued tool key raises ConfigError requiring a table.
    """
    explicit = tmp_path / "pyproject.toml"
    explicit.write_text('tool = "not-a-table"\n')
    loader = ConfigLoader(tmp_path, _defaults())

    with pytest.raises(ConfigError, match=r"\[tool\] must be a table"):
        loader.load(explicit)


def test_yaml_paths_ignore_applied(tmp_path: Path):
    """Load the YAML paths.ignore list in order.

    Args:
        tmp_path: Project root whose config ignores two folders.

    Returns:
        None. Checks that the loaded ignore patterns match the YAML list in the same order.
    """
    (tmp_path / ".gruff-py.yaml").write_text("schemaVersion: gruff-py.config.v0.1\npaths:\n  ignore:\n    - build/\n    - .venv/\n")
    loader = ConfigLoader(tmp_path, _defaults())
    config, _ = loader.load()
    assert config.ignored_path_patterns == ("build/", ".venv/")


def test_yaml_selection_applied(tmp_path: Path):
    """Load the YAML pillar selection and rule exclusions.

    Args:
        tmp_path: Project root whose config selects two pillars and excludes one rule.

    Returns:
        None. Checks that the loaded selection contains the configured pillars and excluded rule.
    """
    (tmp_path / ".gruff-py.yaml").write_text(
        "schemaVersion: gruff-py.config.v0.1\nselection:\n  pillars:\n    - size\n    - complexity\n  excludeRules:\n    - size.file-length\n"
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
    """Refuse an unknown value in a YAML selection list with a ConfigError naming that list.

    Args:
        tmp_path: Project root whose config lists one unknown value.
        key: Selection list under test; the cases cover tiers, pillars, rules and both exclusion lists.
        value: Unknown value placed in that list.
        message: Regex used to check that the error names the selection list.

    Returns:
        None. Checks that loading an unknown selection value raises ConfigError identifying the affected list.
    """
    (tmp_path / ".gruff-py.yaml").write_text(f"schemaVersion: gruff-py.config.v0.1\nselection:\n  {key}:\n    - {value}\n")
    loader = ConfigLoader(tmp_path, _defaults())

    with pytest.raises(ConfigError, match=message):
        loader.load()


def test_removed_npath_rule_pin_warns_by_default_and_raises_under_strict(tmp_path: Path):
    """Warn about the removed complexity.npath rule id and keep every rule's default, but raise under strict loading.

    Args:
        tmp_path: Project root whose config enables the removed rule.

    Returns:
        None. Checks that the removed rule ID warns and leaves defaults intact in lenient mode and raises ConfigError in strict mode.
    """
    (tmp_path / ".gruff-py.yaml").write_text("schemaVersion: gruff-py.config.v0.1\nrules:\n  complexity.npath:\n    enabled: true\n")
    loader = ConfigLoader(tmp_path, _defaults())
    config, _ = loader.load()
    assert any('Unknown rule id "complexity.npath"' in warning for warning in loader.warnings)
    assert config.rules == _defaults().rules

    with pytest.raises(ConfigError, match='Unknown rule id "complexity.npath"'):
        ConfigLoader(tmp_path, _defaults(), strict=True).load()


def test_rule_enabled_must_be_boolean(tmp_path: Path):
    """Refuse a quoted enabled value with a ConfigError naming the key.

    Args:
        tmp_path: Project root whose config sets file length's enabled flag to a string.

    Returns:
        None. Checks that a quoted enabled value raises ConfigError naming the enabled key.
    """
    (tmp_path / ".gruff-py.yaml").write_text('schemaVersion: gruff-py.config.v0.1\nrules:\n  size.file-length:\n    enabled: "false"\n')
    loader = ConfigLoader(tmp_path, _defaults())

    with pytest.raises(ConfigError, match="enabled"):
        loader.load()


def test_yaml_unknown_top_level_key_raises(tmp_path: Path):
    """Refuse an unknown top-level YAML key.

    Args:
        tmp_path: Project root whose config holds only an unknown key.

    Returns:
        None. Checks that loading YAML with an unknown top-level key raises ConfigError.
    """
    (tmp_path / ".gruff-py.yaml").write_text("garbage: 1\n")
    loader = ConfigLoader(tmp_path, _defaults())

    with pytest.raises(ConfigError, match="Unknown gruff keys"):
        loader.load()


def test_empty_gruff_py_yaml_falls_through_to_defaults_with_yaml_as_source(tmp_path: Path):
    """Load registry defaults from an empty .gruff-py.yaml, reporting that file as the source.

    Args:
        tmp_path: Project root holding an empty config file.

    Returns:
        None. Checks that loading an empty .gruff-py.yaml yields the registry defaults and still reports the file as the source.
    """
    (tmp_path / ".gruff-py.yaml").write_text("")
    loader = ConfigLoader(tmp_path, _defaults())
    config, source = loader.load()
    assert source == tmp_path / ".gruff-py.yaml"
    assert config == _defaults()
