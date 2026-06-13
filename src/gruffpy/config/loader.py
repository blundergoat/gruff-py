"""Loads YAML and ``pyproject.toml`` config into an ``AnalysisConfig``."""

import tomllib
from pathlib import Path
from typing import Any

from gruffpy.analysis.schema import CONFIG_SCHEMA_VERSION
from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.dead_code_allowlist import DeadCodeAllowlist
from gruffpy.config.exceptions import ConfigError
from gruffpy.config.rule_selection import RuleSelection
from gruffpy.config.rule_settings import RuleSettings, SeverityThreshold
from gruffpy.config.yaml_loader import load_gruff_py_yaml
from gruffpy.finding.fail_threshold import FailThreshold
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity

VALID_TOP_LEVEL_KEYS = frozenset(
    {
        "schemaVersion",
        "minimumPythonVersion",
        "minimumSeverity",
        "outputVolumeHintThreshold",
        "paths",
        "allowlists",
        "selection",
        "rules",
    }
)
GATEABLE_COMMANDS = frozenset({"analyse", "report", "dashboard"})
NON_GATING_COMMANDS = frozenset(
    {
        "summary",
        "list-rules",
        "metric-calibration",
        "migrate-config",
        "init",
        "list",
        "help",
        "completion",
    }
)
VALID_MINIMUM_SEVERITY_VALUES = frozenset(f.value for f in FailThreshold)
VALID_PATHS_KEYS = frozenset({"ignore"})
VALID_ALLOWLISTS_KEYS = frozenset({"acceptedAbbreviations", "secretPreviews", "deadCode"})
VALID_DEAD_CODE_ALLOWLIST_KEYS = frozenset({"symbols", "decorators", "paths"})
VALID_SELECTION_KEYS = frozenset(
    {
        "tiers",
        "pillars",
        "rules",
        "excludePillars",
        "excludeRules",
    }
)
VALID_RULE_KEYS = frozenset({"enabled", "threshold", "severity", "thresholds", "options"})
MIGRATION_HINT = (
    'Run "gruff-py migrate-config" to rewrite legacy keys, '
    'or "gruff-py init --force" to regenerate the config.'
)
TOML_TOOL_KEY = "gruff-py"
LEGACY_TOML_TOOL_KEY = "gruff"
TOML_TABLE = f"[tool.{TOML_TOOL_KEY}]"
LEGACY_TOML_TABLE = f"[tool.{LEGACY_TOML_TOOL_KEY}]"
DEFAULT_YAML_CONFIG_NAME = ".gruff-py.yaml"
LEGACY_YAML_CONFIG_NAME = ".gruff.yaml"


class ConfigLoader:
    """Resolves the active ``AnalysisConfig`` from YAML / `pyproject.toml` / defaults.

    Unknown rule-level keys (unknown rule ids, unknown rule-section keys,
    unknown ``thresholds.<name>`` knobs, ``threshold`` on non-rubric rules,
    and ``severity`` without ``threshold``) downgrade to warnings by default:
    the offending key is ignored, the rule keeps its defaults, and the warning
    is collected on :attr:`warnings`. With ``strict=True`` the same shapes
    raise :class:`ConfigError`. Structural errors (non-table sections, bad
    value types, unknown top-level keys, schema-version mismatches) always
    raise regardless of strictness.
    """

    def __init__(
        self,
        project_root: str | Path,
        analysis_config: AnalysisConfig,
        *,
        strict: bool = False,
    ) -> None:
        self._project_root = Path(project_root)
        self._defaults = analysis_config
        self._strict = strict
        self._warnings: list[str] = []

    @property
    def warnings(self) -> tuple[str, ...]:
        """Return the non-fatal config warnings collected by the last ``load()``.

        Returns:
            Warning messages in encounter order; empty when the config was
            fully understood or ``load()`` has not run yet.
        """
        return tuple(self._warnings)

    def _warn_or_raise(self, problem: str, lenient_consequence: str, hint: str) -> None:
        """Raise *problem* under strict mode; otherwise record it as a warning.

        The lenient consequence ("ignored; defaults apply") is only true on
        the warning path, so it never appears in the strict-mode error.
        """
        if self._strict:
            raise ConfigError(f"{problem} {hint}")
        self._warnings.append(f"{problem} {lenient_consequence} {hint}")

    def load(self, config_path: Path | None = None) -> tuple[AnalysisConfig, Path | None]:
        """Load config, honouring YAML / `pyproject.toml` precedence.

        Precedence:

        1. Explicit *config_path* (format auto-detected by extension).
        2. ``.gruff-py.yaml`` or legacy ``.gruff.yaml`` in the project root.
        3. ``pyproject.toml`` ``[tool.gruff-py]`` or legacy ``[tool.gruff]``.
        4. Built-in defaults.

        Args:
            config_path: Optional explicit config path; when set, skips the
                project-root discovery and loads that file directly.

        Returns:
            Tuple ``(config, source_path)`` where ``source_path`` is the file
            the config was loaded from, or ``None`` if defaults were used.
        """
        self._warnings = []
        if config_path is not None:
            return self._load_explicit(config_path)

        for yaml_path in (
            self._project_root / DEFAULT_YAML_CONFIG_NAME,
            self._project_root / LEGACY_YAML_CONFIG_NAME,
        ):
            if not yaml_path.exists():
                continue
            section = load_gruff_py_yaml(yaml_path)
            if not section:
                return self._defaults, yaml_path
            self._validate_top_level(section, source=str(yaml_path))
            return self._apply_config_section(section), yaml_path

        toml_path = self._project_root / "pyproject.toml"
        if toml_path.exists():
            toml_section = self._load_toml_section(toml_path)
            if toml_section is None:
                return self._defaults, None
            return self._apply_config_section(toml_section), toml_path

        return self._defaults, None

    def _load_explicit(self, path: Path) -> tuple[AnalysisConfig, Path | None]:
        if not path.exists():
            raise ConfigError(f"Config file does not exist: {path}")
        if path.suffix in {".yaml", ".yml"}:
            section = load_gruff_py_yaml(path)
            if not section:
                return self._defaults, path
            self._validate_top_level(section, source=str(path))
            return self._apply_config_section(section), path
        if path.suffix != ".toml":
            raise ConfigError(
                f"Unsupported config file extension for {path}; use .yaml, .yml, or .toml."
            )
        toml_section = self._load_toml_section(path)
        if toml_section is None:
            raise ConfigError(
                f"Config file {path} has no {TOML_TABLE} or {LEGACY_TOML_TABLE} table."
            )
        return self._apply_config_section(toml_section), path

    def _load_toml_section(self, path: Path) -> dict[str, Any] | None:
        try:
            with open(path, "rb") as f:
                data = tomllib.load(f)
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ConfigError(f"Failed to read config file {path}: {exc}") from exc
        tool_section = data.get("tool", {})
        if not isinstance(tool_section, dict):
            raise ConfigError("[tool] must be a table.")
        section = tool_section.get(TOML_TOOL_KEY)
        table = TOML_TABLE
        if section is None:
            section = tool_section.get(LEGACY_TOML_TOOL_KEY)
            table = LEGACY_TOML_TABLE
        if section is None:
            return None
        if not isinstance(section, dict):
            raise ConfigError(f"{table} must be a table.")
        self._validate_top_level(section, source=f"{table} in {path}")
        return section

    @staticmethod
    def _validate_top_level(section: dict[str, Any], source: str) -> None:
        unknown = set(section.keys()) - VALID_TOP_LEVEL_KEYS
        if unknown:
            raise ConfigError(f"Unknown gruff keys in {source}: {sorted(unknown)}")
        ConfigLoader._validate_schema_version(section, source)
        if "minimumSeverity" in section:
            ConfigLoader._validate_minimum_severity(section["minimumSeverity"], source)
        if "outputVolumeHintThreshold" in section:
            ConfigLoader._validate_output_volume_hint_threshold(
                section["outputVolumeHintThreshold"], source
            )

    @staticmethod
    def _validate_schema_version(section: dict[str, Any], source: str) -> None:
        if "schemaVersion" not in section:
            raise ConfigError(
                f"{source} is missing required 'schemaVersion'. "
                f"Expected {CONFIG_SCHEMA_VERSION!r}; "
                f"run `gruff-py init --force` to regenerate."
            )
        value = section["schemaVersion"]
        if value != CONFIG_SCHEMA_VERSION:
            raise ConfigError(
                f"{source} has schemaVersion {value!r}; "
                f"expected {CONFIG_SCHEMA_VERSION!r}. "
                f"Run `gruff-py init --force` to regenerate."
            )

    @staticmethod
    def _validate_minimum_severity(block: Any, source: str) -> None:
        if not isinstance(block, dict):
            raise ConfigError(
                f"{source} minimumSeverity must be a mapping of command name to severity."
            )
        errors: list[str] = []
        for key, value in block.items():
            if key in NON_GATING_COMMANDS:
                errors.append(
                    f"minimumSeverity.{key!r} is a non-gating subcommand; "
                    f"only {sorted(GATEABLE_COMMANDS)} accept a per-command default."
                )
            elif key not in GATEABLE_COMMANDS:
                errors.append(
                    f"Unknown minimumSeverity key {key!r}; allowed: {sorted(GATEABLE_COMMANDS)}."
                )
            elif not isinstance(value, str):
                errors.append(
                    f"minimumSeverity.{key} must be a string; got {type(value).__name__}."
                )
            elif value not in VALID_MINIMUM_SEVERITY_VALUES:
                errors.append(
                    f"minimumSeverity.{key} has invalid value {value!r}; "
                    f"allowed: {sorted(VALID_MINIMUM_SEVERITY_VALUES)}."
                )
        if errors:
            raise ConfigError(f"{source} has minimumSeverity errors: {'; '.join(errors)}")

    @staticmethod
    def _validate_output_volume_hint_threshold(value: Any, source: str) -> None:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ConfigError(
                f"{source} outputVolumeHintThreshold must be a non-negative integer; "
                f"got {type(value).__name__}."
            )
        if value < 0:
            raise ConfigError(
                f"{source} outputVolumeHintThreshold must be >= 0; got {value} "
                f"(set to 0 to disable the hint)."
            )

    def _apply_config_section(self, section: dict[str, Any]) -> AnalysisConfig:
        config = self._defaults

        if "minimumPythonVersion" in section:
            config = config.with_minimum_python_version(
                _parse_python_version(section["minimumPythonVersion"])
            )

        if "minimumSeverity" in section:
            config = config.with_minimum_severity(
                {key: FailThreshold(value) for key, value in section["minimumSeverity"].items()}
            )

        if "outputVolumeHintThreshold" in section:
            config = config.with_output_volume_hint_threshold(section["outputVolumeHintThreshold"])

        applicators = (
            ("paths", self._apply_paths),
            ("allowlists", self._apply_allowlists),
            ("selection", self._apply_selection),
            ("rules", self._apply_rules),
        )
        for key, applicator in applicators:
            if key in section:
                config = applicator(config, section[key])

        return config

    @staticmethod
    def _apply_paths(config: AnalysisConfig, paths: Any) -> AnalysisConfig:
        if not isinstance(paths, dict):
            raise ConfigError("[tool.gruff-py.paths] must be a table.")
        unknown = set(paths.keys()) - VALID_PATHS_KEYS
        if unknown:
            raise ConfigError(f"Unknown [tool.gruff-py.paths] keys: {sorted(unknown)}")
        ignore = paths.get("ignore", [])
        if not isinstance(ignore, list) or not all(isinstance(p, str) for p in ignore):
            raise ConfigError("[tool.gruff-py.paths].ignore must be a list of strings.")
        return config.with_ignored_path_patterns(tuple(ignore))

    @staticmethod
    def _apply_allowlists(config: AnalysisConfig, allowlists: Any) -> AnalysisConfig:
        if not isinstance(allowlists, dict):
            raise ConfigError("[tool.gruff-py.allowlists] must be a table.")
        unknown = set(allowlists.keys()) - VALID_ALLOWLISTS_KEYS
        if unknown:
            raise ConfigError(f"Unknown [tool.gruff-py.allowlists] keys: {sorted(unknown)}")
        ConfigLoader._validate_string_list_allowlists(allowlists)
        return ConfigLoader._apply_present_allowlists(config, allowlists)

    @staticmethod
    def _validate_string_list_allowlists(allowlists: dict[str, Any]) -> None:
        for key in ("acceptedAbbreviations", "secretPreviews"):
            value = allowlists.get(key, [])
            if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
                raise ConfigError(f"[tool.gruff-py.allowlists].{key} must be a list of strings.")

    @staticmethod
    def _apply_present_allowlists(
        config: AnalysisConfig, allowlists: dict[str, Any]
    ) -> AnalysisConfig:
        if "acceptedAbbreviations" in allowlists:
            config = config.with_accepted_abbreviations(tuple(allowlists["acceptedAbbreviations"]))
        if "secretPreviews" in allowlists:
            config = config.with_allowed_secret_previews(tuple(allowlists["secretPreviews"]))
        if "deadCode" in allowlists:
            config = config.with_dead_code_allowlist(
                _parse_dead_code_allowlist(allowlists["deadCode"])
            )
        return config

    @staticmethod
    def _apply_selection(config: AnalysisConfig, selection: Any) -> AnalysisConfig:
        if not isinstance(selection, dict):
            raise ConfigError("[tool.gruff-py.selection] must be a table.")
        unknown = set(selection.keys()) - VALID_SELECTION_KEYS
        if unknown:
            raise ConfigError(f"Unknown [tool.gruff-py.selection] keys: {sorted(unknown)}")
        for key in VALID_SELECTION_KEYS:
            value = selection.get(key, [])
            if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
                raise ConfigError(f"[tool.gruff-py.selection].{key} must be a list of strings.")
        _validate_selection_values(config, selection)
        return config.with_rule_selection(
            RuleSelection(
                tiers=tuple(selection.get("tiers", [])),
                pillars=tuple(selection.get("pillars", [])),
                rules=tuple(selection.get("rules", [])),
                exclude_pillars=tuple(selection.get("excludePillars", [])),
                exclude_rules=tuple(selection.get("excludeRules", [])),
            )
        )

    def _apply_rules(self, config: AnalysisConfig, rules: Any) -> AnalysisConfig:
        if not isinstance(rules, dict):
            raise ConfigError("[tool.gruff-py.rules] must be a table.")
        for rule_id, rule_section in rules.items():
            if not isinstance(rule_section, dict):
                raise ConfigError(f'[tool.gruff-py.rules."{rule_id}"] must be a table.')
            if rule_id not in config.rules:
                self._warn_or_raise(
                    f'Unknown rule id "{rule_id}" in rules config.',
                    "Section ignored.",
                    MIGRATION_HINT,
                )
                continue
            rule_settings = config.rules[rule_id]
            section = self._sanitised_rule_section(rule_id, rule_section, rule_settings)
            override = _severity_threshold(rule_id, rule_settings, section)
            severity_threshold = (
                override if override is not None else rule_settings.severity_threshold
            )
            config = config.with_rule_settings(
                rule_id,
                RuleSettings(
                    enabled=_is_rule_enabled(rule_settings, section),
                    thresholds=(
                        dict(rule_settings.thresholds)
                        if override is not None
                        else _merged_thresholds(rule_id, rule_settings, section)
                    ),
                    options=_merged_options(rule_id, rule_settings, section),
                    severity_threshold=severity_threshold,
                ),
            )
        return config

    def _sanitised_rule_section(
        self,
        rule_id: str,
        rule_section: dict[str, Any],
        defaults: RuleSettings,
    ) -> dict[str, Any]:
        """Strip legacy/unknown rule keys, warning (or raising under strict) per key.

        The returned section only contains shapes the strict merge logic
        accepts, so every remaining raise in ``_merged_thresholds`` /
        ``_severity_threshold`` is a structural or type error that stays fatal.
        """
        section: dict[str, Any] = {}
        for key, value in rule_section.items():
            if key not in VALID_RULE_KEYS:
                self._warn_or_raise(
                    f'Unknown key "rules.{rule_id}.{key}".',
                    "Key ignored.",
                    f"{_accepted_keys_sentence(rule_id, defaults)} {MIGRATION_HINT}",
                )
                continue
            section[key] = value
        thresholds = section.get("thresholds")
        if isinstance(thresholds, dict):
            kept = self._sanitised_thresholds(rule_id, thresholds, defaults)
            if kept or not thresholds:
                section["thresholds"] = kept
            else:
                # Every entry was a legacy/unknown knob: drop the emptied table
                # so it cannot trip the threshold/thresholds combination error.
                del section["thresholds"]
        if "threshold" in section and defaults.severity_threshold is None:
            self._warn_or_raise(
                f'Config key "rules.{rule_id}.threshold" is only supported for '
                "severity-threshold rubrics.",
                f'Ignored; "{rule_id}" keeps its defaults.',
                f"{_accepted_keys_sentence(rule_id, defaults)} {MIGRATION_HINT}",
            )
            section.pop("threshold", None)
            section.pop("severity", None)
        if "severity" in section and "threshold" not in section:
            self._warn_or_raise(
                f'Config key "rules.{rule_id}.severity" requires "threshold".',
                "Ignored.",
                f"{_accepted_keys_sentence(rule_id, defaults)} {MIGRATION_HINT}",
            )
            section.pop("severity", None)
        return section

    def _sanitised_thresholds(
        self,
        rule_id: str,
        overrides: dict[str, Any],
        defaults: RuleSettings,
    ) -> dict[str, Any]:
        kept: dict[str, Any] = {}
        for key, value in overrides.items():
            if key not in defaults.thresholds:
                self._warn_or_raise(
                    f'Unknown threshold "rules.{rule_id}.thresholds.{key}".',
                    f'Ignored; "{rule_id}" keeps its default for that knob.',
                    f"{_accepted_keys_sentence(rule_id, defaults)} {MIGRATION_HINT}",
                )
                continue
            kept[key] = value
        return kept


def _accepted_keys_sentence(rule_id: str, defaults: RuleSettings) -> str:
    """Render the accepted config keys for one rule, derived from its defaults."""
    keys = ["enabled"]
    if defaults.severity_threshold is not None:
        keys.extend(("threshold", "severity"))
    keys.extend(f"thresholds.{name}" for name in sorted(defaults.thresholds))
    keys.extend(f"options.{name}" for name in sorted(defaults.options))
    return f'Accepted keys for "rules.{rule_id}": {", ".join(keys)}.'


def _is_rule_enabled(rule_settings: RuleSettings, rule_section: dict[str, Any]) -> bool:
    if "enabled" not in rule_section:
        return rule_settings.enabled
    enabled = rule_section["enabled"]
    if not isinstance(enabled, bool):
        raise ConfigError('Config key "rules.*.enabled" must be a boolean.')
    return enabled


def _validate_selection_values(config: AnalysisConfig, selection: dict[str, Any]) -> None:
    valid_tiers = {tier.value for tier in RuleTier}
    valid_pillars = {pillar.value for pillar in Pillar}
    valid_rules = set(config.rules)

    _reject_unknown_selection_values("tiers", selection.get("tiers", []), valid_tiers)
    _reject_unknown_selection_values("pillars", selection.get("pillars", []), valid_pillars)
    _reject_unknown_selection_values(
        "excludePillars", selection.get("excludePillars", []), valid_pillars
    )
    _reject_unknown_selection_values("rules", selection.get("rules", []), valid_rules)
    _reject_unknown_selection_values("excludeRules", selection.get("excludeRules", []), valid_rules)


def _reject_unknown_selection_values(
    key: str,
    values: list[str],
    valid_values: set[str],
) -> None:
    unknown = sorted(set(values) - valid_values)
    if unknown:
        raise ConfigError(f"Unknown [tool.gruff-py.selection].{key} values: {unknown}")


def _merged_thresholds(
    rule_id: str,
    rule_settings: RuleSettings,
    rule_section: dict[str, Any],
) -> dict[str, int | float]:
    if "severity" in rule_section:
        raise ConfigError(f'Config key "rules.{rule_id}.severity" requires "threshold".')
    thresholds = dict(rule_settings.thresholds)
    if "thresholds" not in rule_section:
        return thresholds
    overrides = rule_section["thresholds"]
    if not isinstance(overrides, dict):
        raise ConfigError(f'thresholds in rule "{rule_id}" must be a table.')
    for key, value in overrides.items():
        if key not in rule_settings.thresholds:
            raise ConfigError(f'Unknown threshold "rules.{rule_id}.thresholds.{key}".')
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise ConfigError(f'threshold "{key}" in rule "{rule_id}" must be a number.')
        thresholds[key] = value
    return thresholds


def _severity_threshold(
    rule_id: str,
    rule_settings: RuleSettings,
    rule_section: dict[str, Any],
) -> SeverityThreshold | None:
    if "threshold" not in rule_section:
        return None
    if "thresholds" in rule_section:
        raise ConfigError(
            f'Config key "rules.{rule_id}" cannot combine "threshold" and "thresholds".'
        )
    if rule_settings.severity_threshold is None:
        raise ConfigError(
            f'Config key "rules.{rule_id}.threshold" is only supported for '
            "severity-threshold rubrics."
        )

    threshold = rule_section["threshold"]
    if not isinstance(threshold, (int, float)) or isinstance(threshold, bool):
        raise ConfigError(f'Config key "rules.{rule_id}.threshold" must be numeric.')

    severity = rule_section.get("severity")
    allowed_severities = {Severity.WARNING.value, Severity.ERROR.value}
    if not isinstance(severity, str) or severity not in allowed_severities:
        raise ConfigError(f'Config key "rules.{rule_id}.severity" must be "warning" or "error".')

    return SeverityThreshold(threshold=threshold, severity=Severity(severity))


def _merged_options(
    rule_id: str,
    rule_settings: RuleSettings,
    rule_section: dict[str, Any],
) -> dict[str, Any]:
    options = dict(rule_settings.options)
    if "options" not in rule_section:
        return options
    overrides = rule_section["options"]
    if not isinstance(overrides, dict):
        raise ConfigError(f'options in rule "{rule_id}" must be a table.')
    options.update(overrides)
    return options


def _parse_dead_code_allowlist(section: Any) -> DeadCodeAllowlist:
    if not isinstance(section, dict):
        raise ConfigError("[tool.gruff-py.allowlists.deadCode] must be a table.")
    unknown = set(section.keys()) - VALID_DEAD_CODE_ALLOWLIST_KEYS
    if unknown:
        raise ConfigError(f"Unknown [tool.gruff-py.allowlists.deadCode] keys: {sorted(unknown)}")
    for key in VALID_DEAD_CODE_ALLOWLIST_KEYS:
        value = section.get(key, [])
        if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
            raise ConfigError(
                f"[tool.gruff-py.allowlists.deadCode].{key} must be a list of strings."
            )
    return DeadCodeAllowlist(
        symbols=tuple(section.get("symbols", [])),
        decorators=tuple(section.get("decorators", [])),
        paths=tuple(section.get("paths", [])),
    )


def _parse_python_version(value: Any) -> tuple[int, int]:
    if isinstance(value, str):
        parts = value.split(".")
        if len(parts) >= 2:
            try:
                return (int(parts[0]), int(parts[1]))
            except ValueError:
                pass
    raise ConfigError(f"minimumPythonVersion must be a string like '3.11', got {value!r}")
