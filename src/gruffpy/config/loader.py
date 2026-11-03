"""Resolve user YAML or TOML into the settings used by every scan command.

The loader applies source precedence, validates shared config shapes, and
merges registered rule defaults with supported overrides. Normal scans expose
recoverable rule-key mistakes as warnings; strict scans stop on the same key.
"""

import tomllib
from pathlib import Path
from typing import Any

from gruffpy.analysis.schema import CONFIG_SCHEMA_VERSION
from gruffpy.config.analysis_config import AnalysisConfig, DeepScanBudget
from gruffpy.config.dead_code_allowlist import DeadCodeAllowlist
from gruffpy.config.exceptions import ConfigError
from gruffpy.config.rule_selection import RuleSelection
from gruffpy.config.rule_settings import RuleSettings, SeverityThreshold
from gruffpy.config.sensitive_exclusions import (
    SENSITIVE_EXCLUSIONS_KEY,
    parse_sensitive_exclusions,
)
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
        "failOn",
        "outputVolumeHintThreshold",
        "deepScanBudget",
        "paths",
        "allowlists",
        "selection",
        SENSITIVE_EXCLUSIONS_KEY,
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
# secretPreviews stays recognised so the loader can refuse it by name with the section 5 explanation, rather
# than reporting it as an unknown key the user might think was a typo.
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
MIGRATION_HINT = 'Run "gruff-py migrate-config" to rewrite legacy YAML keys. For TOML, edit [tool.gruff-py] in pyproject.toml by hand.'
TOML_TOOL_KEY = "gruff-py"
LEGACY_TOML_TOOL_KEY = "gruff"
TOML_TABLE = f"[tool.{TOML_TOOL_KEY}]"
LEGACY_TOML_TABLE = f"[tool.{LEGACY_TOML_TOOL_KEY}]"
DEFAULT_YAML_CONFIG_NAME = ".gruff-py.yaml"
LEGACY_YAML_CONFIG_NAME = ".gruff.yaml"
LEGACY_SECRET_PREVIEWS_ERROR = (
    'Config key "allowlists.secretPreviews" is removed in 0.6.0: FAMILY-CONTRACT.md section 5 makes category '
    "markers unconditional, so the key authorises nothing; delete it from the configuration."
)

DISPLAY_FLOOR_VALUES = frozenset(severity.value for severity in Severity)

LEGACY_MINIMUM_SEVERITY_ERROR = (
    'Config key "minimumSeverity" is the display floor in 0.6.0 and takes one severity, not a per-command map; '
    'move the per-command exit gate to "failOn", which is the key that gates the exit code.'
)


class ConfigLoader:
    """Resolve the settings every user command needs before analysis begins.

    Discovery chooses YAML, TOML, or registered defaults in documented order.
    Normal scans warn and remove unsupported rule, threshold, and option keys;
    strict scans stop on the same exact key. Structural, type, and schema errors
    always stop because continuing would misrepresent the user's configuration.
    """

    def __init__(
        self,
        project_root: str | Path,
        analysis_config: AnalysisConfig,
        *,
        strict: bool = False,
    ) -> None:
        """Prepare config discovery for one project and the command's strictness choice."""
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

        Args:
            problem: Invalid setting described in both strict errors and lenient warnings.
            lenient_consequence: Effect of continuing, included only in the recorded warning.
            hint: Corrective instruction appended to either form of feedback.

        Raises:
            ConfigError: When this loader is strict; otherwise the warning is retained for the caller.
        """
        if self._strict:
            raise ConfigError(f"{problem} {hint}")
        self._warnings.append(f"{problem} {lenient_consequence} {hint}")

    def load(self, config_path: Path | None = None) -> tuple[AnalysisConfig, Path | None]:
        """Load config, honouring YAML / `pyproject.toml` precedence.

        An explicit path wins, followed by modern or legacy YAML, modern or legacy TOML, and
        finally built-in defaults when the project has no Gruff settings.

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
        """Load the exact YAML or TOML path supplied by the user, without project discovery.

        Args:
            path: User-selected configuration file whose suffix chooses the YAML or TOML reader.

        Returns:
            Resolved settings and the selected path; empty YAML uses registered defaults.

        Raises:
            ConfigError: When the file is missing, its format or settings are invalid, or TOML has no Gruff table.
            ValueError: When the parsed minimum Python version is below 3.11.
        """
        if not path.exists():
            raise ConfigError(f"Config file does not exist: {path}")
        if path.suffix in {".yaml", ".yml"}:
            section = load_gruff_py_yaml(path)
            if not section:
                return self._defaults, path
            self._validate_top_level(section, source=str(path))
            return self._apply_config_section(section), path
        if path.suffix != ".toml":
            raise ConfigError(f"Unsupported config file extension for {path}; use .yaml, .yml, or .toml.")
        toml_section = self._load_toml_section(path)
        if toml_section is None:
            raise ConfigError(f"Config file {path} has no {TOML_TABLE} or {LEGACY_TOML_TABLE} table.")
        return self._apply_config_section(toml_section), path

    def _load_toml_section(self, path: Path) -> dict[str, Any] | None:
        """Read the supported Gruff table from TOML, or return no table for normal discovery.

        Args:
            path: TOML file to read, using the modern Gruff table before the legacy table.

        Returns:
            Validated Gruff settings, or None when neither supported table is present.

        Raises:
            ConfigError: When reading or parsing fails, a selected table has the wrong shape, or settings are invalid.
        """
        try:
            with open(path, "rb") as f:
                data = tomllib.load(f)
        # For example, malformed TOML or a permissions error should tell the user which file failed.
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
        """Validate shared top-level keys before any user setting can affect analysis.

        Args:
            section: Parsed settings to check for supported keys, schema and shared value shapes.
            source: File or table label included in feedback so the user can locate the setting.

        Raises:
            ConfigError: When a key, schema version or present shared setting is unsupported or malformed.
        """
        unknown = set(section.keys()) - VALID_TOP_LEVEL_KEYS
        if unknown:
            raise ConfigError(f"Unknown gruff keys in {source}: {sorted(unknown)}")
        ConfigLoader._validate_schema_version(section, source)
        if "minimumSeverity" in section:
            ConfigLoader._validate_display_floor(section["minimumSeverity"], source)
        if "failOn" in section:
            ConfigLoader._validate_minimum_severity(section["failOn"], source)
        if "outputVolumeHintThreshold" in section:
            ConfigLoader._validate_output_volume_hint_threshold(section["outputVolumeHintThreshold"], source)
        if "deepScanBudget" in section:
            ConfigLoader._validate_deep_scan_budget(section["deepScanBudget"], source)

    @staticmethod
    def _validate_schema_version(section: dict[str, Any], source: str) -> None:
        """Require the schema version that this binary can interpret for the user.

        Args:
            section: Parsed settings whose required schemaVersion must match this binary.
            source: File or table label included in migration feedback.

        Raises:
            ConfigError: When schemaVersion is absent or differs from the supported version.
        """
        if "schemaVersion" not in section:
            raise ConfigError(
                f"{source} is missing required 'schemaVersion'. "
                f"Expected {CONFIG_SCHEMA_VERSION!r}; "
                "run `gruff-py migrate-config` for YAML, or edit "
                "[tool.gruff-py] in TOML by hand."
            )
        value = section["schemaVersion"]
        if value != CONFIG_SCHEMA_VERSION:
            raise ConfigError(
                f"{source} has schemaVersion {value!r}; "
                f"expected {CONFIG_SCHEMA_VERSION!r}. "
                "Run `gruff-py migrate-config` for YAML, or edit "
                "[tool.gruff-py] in TOML by hand."
            )

    @staticmethod
    def _validate_display_floor(value: Any, source: str) -> None:
        """Validate the display floor, refusing the per-command map that used to mean the exit gate.

        The map form is the whole reason this check exists: it is valid YAML that
        used to gate a build, and reading it as a display floor would change what
        a committed file does without changing what it says.

        Args:
            value: Raw minimumSeverity setting; must name one supported display severity.
            source: File or table label used to identify an invalid setting.

        Raises:
            ConfigError: When the value is a legacy per-command map or is not a supported severity string.
        """
        if isinstance(value, dict):
            raise ConfigError(f"{source}: {LEGACY_MINIMUM_SEVERITY_ERROR}")
        if not isinstance(value, str) or value not in DISPLAY_FLOOR_VALUES:
            raise ConfigError(f"{source} minimumSeverity {value!r} is not a severity: want {sorted(DISPLAY_FLOOR_VALUES)}.")

    @staticmethod
    def _validate_minimum_severity(block: Any, source: str) -> None:
        """Validate per-command failure thresholds before a scan can report the wrong exit code.

        Args:
            block: Raw failOn table mapping supported gating commands to threshold strings; an empty table is valid.
            source: File or table label attached to the collected setting errors.

        Raises:
            ConfigError: When the table shape, command names or threshold strings are invalid.
        """
        if not isinstance(block, dict):
            raise ConfigError(f"{source} failOn must be a mapping of command name to severity.")
        errors: list[str] = []
        for key, value in block.items():
            if key in NON_GATING_COMMANDS:
                errors.append(f"failOn.{key!r} is a non-gating subcommand; only {sorted(GATEABLE_COMMANDS)} accept a per-command default.")
            elif key not in GATEABLE_COMMANDS:
                errors.append(f"Unknown failOn key {key!r}; allowed: {sorted(GATEABLE_COMMANDS)}.")
            elif not isinstance(value, str):
                errors.append(f"failOn.{key} must be a string; got {type(value).__name__}.")
            elif value not in VALID_MINIMUM_SEVERITY_VALUES:
                errors.append(f"failOn.{key} has invalid value {value!r}; allowed: {sorted(VALID_MINIMUM_SEVERITY_VALUES)}.")
        if errors:
            raise ConfigError(f"{source} has failOn errors: {'; '.join(errors)}")

    @staticmethod
    def _validate_output_volume_hint_threshold(value: Any, source: str) -> None:
        """Validate when text users should see the high-volume findings hint.

        Args:
            value: Raw hint threshold; zero disables the hint and positive integers set its trigger.
            source: File or table label used in invalid-threshold feedback.

        Raises:
            ConfigError: When the threshold is a boolean, a non-integer or negative.
        """
        if isinstance(value, bool) or not isinstance(value, int):
            raise ConfigError(f"{source} outputVolumeHintThreshold must be a non-negative integer; got {type(value).__name__}.")
        if value < 0:
            raise ConfigError(f"{source} outputVolumeHintThreshold must be >= 0; got {value} (set to 0 to disable the hint).")

    @staticmethod
    def _validate_deep_scan_budget(value: Any, source: str) -> None:
        """Validate the supplied deep-scan budget fields before merging their defaults.

        Args:
            value: Raw budget table; omitted fields retain their configured defaults.
            source: File or table label used in invalid-budget feedback.

        Raises:
            ConfigError: When the value is not a table, keys are unknown, enabled is not boolean, or a supplied limit is not a positive integer.
        """
        if not isinstance(value, dict):
            raise ConfigError(f"{source} deepScanBudget must be a mapping.")
        unknown = set(value) - {"enabled", "maxLines", "maxBytes"}
        if unknown:
            raise ConfigError(f"Unknown deepScanBudget keys in {source}: {sorted(unknown)}; allowed: ['enabled', 'maxBytes', 'maxLines'].")
        enabled = value.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ConfigError(f"{source} deepScanBudget.enabled must be true or false.")
        for key in ("maxLines", "maxBytes"):
            if key not in value:
                continue
            limit = value[key]
            if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
                raise ConfigError(f"{source} deepScanBudget.{key} must be a positive integer.")

    def _apply_config_section(self, section: dict[str, Any]) -> AnalysisConfig:
        """Layer every present user section over registered defaults in documented order.

        Args:
            section: Top-level settings already shape-checked by the loader; absent sections keep their defaults.

        Returns:
            Settings with each present section applied; an empty section returns the registered defaults.

        Raises:
            ConfigError: When a section applicator rejects an invalid setting or a strict-mode override.
            ValueError: When the requested minimum Python version is below the supported minimum.
        """
        config = self._defaults

        if "minimumPythonVersion" in section:
            config = config.with_minimum_python_version(_parse_python_version(section["minimumPythonVersion"]))

        if "failOn" in section:
            config = config.with_minimum_severity({key: FailThreshold(value) for key, value in section["failOn"].items()})

        if "minimumSeverity" in section:
            config = config.with_display_floor(Severity(section["minimumSeverity"]))

        if "outputVolumeHintThreshold" in section:
            config = config.with_output_volume_hint_threshold(section["outputVolumeHintThreshold"])

        if "deepScanBudget" in section:
            value = section["deepScanBudget"]
            current = config.deep_scan_budget
            config = config.with_deep_scan_budget(
                DeepScanBudget(
                    enabled=value.get("enabled", current.enabled),
                    max_lines=value.get("maxLines", current.max_lines),
                    max_bytes=value.get("maxBytes", current.max_bytes),
                    override="config",
                )
            )

        applicators = (
            ("paths", self._apply_paths),
            ("allowlists", self._apply_allowlists),
            ("selection", self._apply_selection),
            (SENSITIVE_EXCLUSIONS_KEY, self._apply_sensitive_exclusions),
            ("rules", self._apply_rules),
        )
        for key, applicator in applicators:
            if key in section:
                config = applicator(config, section[key])

        return config

    @staticmethod
    def _apply_paths(config: AnalysisConfig, paths: Any) -> AnalysisConfig:
        """Apply path ignores that control which files the user's scan discovers.

        Args:
            config: Settings whose ignored paths will be replaced.
            paths: Raw paths table; omitting ignore replaces the patterns with an empty tuple.

        Returns:
            A new configuration carrying exactly the supplied ignore patterns.

        Raises:
            ConfigError: When the table has unknown keys or ignore is not a list of strings.
        """
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
        """Apply supported user exceptions after validating every allowlist shape.

        Args:
            config: Settings retaining any allowlist that the user does not supply.
            allowlists: Raw allowlist table to validate before applying its present sections.

        Returns:
            Settings with supplied allowlists replaced; an empty table leaves the configuration unchanged.

        Raises:
            ConfigError: When the table, its keys or entries are invalid, including the removed preview setting.
        """
        if not isinstance(allowlists, dict):
            raise ConfigError("[tool.gruff-py.allowlists] must be a table.")
        unknown = set(allowlists.keys()) - VALID_ALLOWLISTS_KEYS
        if unknown:
            raise ConfigError(f"Unknown [tool.gruff-py.allowlists] keys: {sorted(unknown)}")
        ConfigLoader._validate_string_list_allowlists(allowlists)
        return ConfigLoader._apply_present_allowlists(config, allowlists)

    @staticmethod
    def _validate_string_list_allowlists(allowlists: dict[str, Any]) -> None:
        """Validate naming entries and reject any use of the retired preview setting.

        Args:
            allowlists: Supported allowlist keys; absent acceptedAbbreviations is treated as an empty list for validation.

        Raises:
            ConfigError: When abbreviations are not a list of strings or secretPreviews is present, even if empty.
        """
        accepted_abbreviations = allowlists.get("acceptedAbbreviations", [])
        # Invalid naming entries stop the command so the user never sees results based on a
        # partly applied allowlist.
        if not isinstance(accepted_abbreviations, list) or not all(isinstance(abbreviation, str) for abbreviation in accepted_abbreviations):
            raise ConfigError("[tool.gruff-py.allowlists].acceptedAbbreviations must be a list of strings.")

        # Presence is the test, not content: an empty list reads as configured redaction just as a populated one does.
        if "secretPreviews" in allowlists:
            raise ConfigError(LEGACY_SECRET_PREVIEWS_ERROR)

    @staticmethod
    def _apply_present_allowlists(config: AnalysisConfig, allowlists: dict[str, Any]) -> AnalysisConfig:
        """Copy validated allowlists into the immutable config used by the user's scan.

        Args:
            config: Settings supplying values for allowlists the user leaves absent.
            allowlists: Present acceptedAbbreviations and deadCode sections to apply after outer validation.

        Returns:
            Settings with present allowlists replaced; returns config itself when neither section is present.

        Raises:
            ConfigError: When a supplied deadCode section cannot be parsed.
        """
        if "acceptedAbbreviations" in allowlists:
            config = config.with_accepted_abbreviations(tuple(allowlists["acceptedAbbreviations"]))
        if "deadCode" in allowlists:
            config = config.with_dead_code_allowlist(_parse_dead_code_allowlist(allowlists["deadCode"]))
        return config

    @staticmethod
    def _apply_sensitive_exclusions(config: AnalysisConfig, section: Any) -> AnalysisConfig:
        """Apply the reviewed scopes in which one sensitive-data rule may stay quiet.

        Every problem in this section is fatal, so a user never gets results from a partly
        understood suppression list.

        Args:
            config: Config carrying the registered rule ids and their sensitive-data membership.
            section: Raw ``sensitiveExclusions`` value from the user's YAML or TOML.

        Returns:
            New config carrying the validated entries.
        """
        return config.with_sensitive_exclusions(
            parse_sensitive_exclusions(
                section,
                known_rule_ids=frozenset(config.rules),
                sensitive_rule_ids=config.sensitive_data_rule_ids,
            )
        )

    @staticmethod
    def _apply_selection(config: AnalysisConfig, selection: Any) -> AnalysisConfig:
        """Apply the user's include and exclude selectors after rejecting unknown values.

        Args:
            config: Settings defining known rules and receiving the new selector set.
            selection: Raw selector table; absent lists become empty, clearing their previous selections.

        Returns:
            A new configuration containing the validated include and exclude lists.

        Raises:
            ConfigError: When the table, keys, list shapes or referenced selector values are invalid.
        """
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
        """Merge per-rule user overrides while retaining defaults for unsupported keys.

        Args:
            config: Settings providing registered rule ids and the defaults each override builds on.
            rules: Raw per-rule tables; an empty mapping leaves the configuration unchanged.

        Returns:
            Settings with supported rule overrides applied in input order.

        Raises:
            ConfigError: When a table or supported override is malformed, or strict mode rejects an unsupported key.
        """
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
            severity_threshold = override if override is not None else rule_settings.severity_threshold
            config = config.with_rule_settings(
                rule_id,
                RuleSettings(
                    enabled=_is_rule_enabled(rule_settings, section),
                    thresholds=(dict(rule_settings.thresholds) if override is not None else _merged_thresholds(rule_id, rule_settings, section)),
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
        """Keep only registered rule keys before applying the user's overrides.

        Args:
            rule_id: Public rule id whose dotted config keys appear in feedback.
            rule_section: User table; an empty table keeps every registered default.
            defaults: Registered settings that define accepted threshold and option names.

        Returns:
            Sanitised table; empty means no supported override remains to apply.
        """
        section: dict[str, Any] = {}
        # Each top-level rule key is checked before users see any override applied.
        for key, value in rule_section.items():
            # Unsupported keys warn in normal scans and stop strict scans.
            if key not in VALID_RULE_KEYS:
                self._warn_or_raise(
                    f'Unknown key "rules.{rule_id}.{key}".',
                    "Key ignored.",
                    f"{_accepted_keys_sentence(rule_id, defaults)} {MIGRATION_HINT}",
                )
                continue
            section[key] = value
        thresholds = section.get("thresholds")
        # A table of named thresholds keeps only knobs registered by this rule.
        if isinstance(thresholds, dict):
            kept = self._sanitised_thresholds(rule_id, thresholds, defaults)
            # An explicitly empty table remains harmless and visible to the merge.
            if kept or not thresholds:
                section["thresholds"] = kept
            else:
                # Unknown-only input disappears so the user's registered defaults survive.
                del section["thresholds"]
        options = section.get("options")
        # A user option table keeps only names declared by the registered rule.
        if isinstance(options, dict):
            kept_options = self._sanitised_options(rule_id, options, defaults)
            # An explicitly empty table still means the user supplied no overrides.
            if kept_options or not options:
                section["options"] = kept_options
            else:
                # Unknown-only input disappears so it cannot enter rule execution.
                del section["options"]
        # Single thresholds are only meaningful for rules with a registered rubric.
        if "threshold" in section and defaults.severity_threshold is None:
            self._warn_or_raise(
                f'Config key "rules.{rule_id}.threshold" is only supported for severity-threshold rubrics.',
                f'Ignored; "{rule_id}" keeps its defaults.',
                f"{_accepted_keys_sentence(rule_id, defaults)} {MIGRATION_HINT}",
            )
            section.pop("threshold", None)
            section.pop("severity", None)
        # A severity alone cannot tell the user where the rule should begin firing.
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
        """Keep registered threshold overrides and explain unsupported knobs to the user.

        Args:
            rule_id: Rule whose dotted threshold key identifies feedback.
            overrides: User threshold table inspected in input order; empty means no overrides.
            defaults: Registered settings defining the only accepted threshold names.

        Returns:
            Supported threshold entries without changing their values; empty when no names are retained.

        Raises:
            ConfigError: When strict mode encounters an unregistered threshold name.
        """
        kept: dict[str, Any] = {}
        # Each named threshold is checked in the order the user wrote it.
        for key, value in overrides.items():
            # Unknown knobs leave the corresponding registered default unchanged.
            if key not in defaults.thresholds:
                self._warn_or_raise(
                    f'Unknown threshold "rules.{rule_id}.thresholds.{key}".',
                    f'Ignored; "{rule_id}" keeps its default for that knob.',
                    f"{_accepted_keys_sentence(rule_id, defaults)} {MIGRATION_HINT}",
                )
                continue
            kept[key] = value
        return kept

    def _sanitised_options(
        self,
        rule_id: str,
        overrides: dict[str, Any],
        defaults: RuleSettings,
    ) -> dict[str, Any]:
        """Keep option overrides whose names the registered rule exposes.

        Args:
            rule_id: Public rule id whose exact dotted typo appears in feedback.
            overrides: User option table; empty means no options were requested.
            defaults: Registered options serving as the sole accepted-name source.

        Returns:
            Supported sibling overrides in the user's original order; empty when none remain.
        """
        kept: dict[str, Any] = {}
        # Each option is checked in user order so multiple warnings stay predictable.
        for key, value in overrides.items():
            # A missing registered default means this option is not public for the rule.
            if key not in defaults.options:
                self._warn_or_raise(
                    f'Unknown option "rules.{rule_id}.options.{key}".',
                    "Option ignored; registered defaults and valid sibling options still apply.",
                    f"{_accepted_keys_sentence(rule_id, defaults)} {MIGRATION_HINT}",
                )
                continue
            kept[key] = value
        return kept


def _accepted_keys_sentence(rule_id: str, defaults: RuleSettings) -> str:
    """Render the accepted config keys for one rule, derived from its defaults.

    Args:
        rule_id: Rule named in the corrective message.
        defaults: Registered settings supplying named thresholds, options and support for a single-severity rubric.

    Returns:
        One feedback sentence listing supported dotted keys in deterministic order.
    """
    keys = ["enabled"]
    if defaults.severity_threshold is not None:
        keys.extend(("threshold", "severity"))
    keys.extend(f"thresholds.{name}" for name in sorted(defaults.thresholds))
    keys.extend(f"options.{name}" for name in sorted(defaults.options))
    return f'Accepted keys for "rules.{rule_id}": {", ".join(keys)}.'


def _is_rule_enabled(rule_settings: RuleSettings, rule_section: dict[str, Any]) -> bool:
    """Return the user's enabled override, or the registered default when it is absent.

    Args:
        rule_settings: Registered settings supplying the fallback enabled state.
        rule_section: User override table; absence of enabled retains the fallback.

    Returns:
        The supplied boolean override, or the registered enabled state.

    Raises:
        ConfigError: When a present enabled value is not a boolean.
    """
    if "enabled" not in rule_section:
        return rule_settings.enabled
    enabled = rule_section["enabled"]
    if not isinstance(enabled, bool):
        raise ConfigError('Config key "rules.*.enabled" must be a boolean.')
    return enabled


def _validate_selection_values(config: AnalysisConfig, selection: dict[str, Any]) -> None:
    """Reject selectors that cannot match a known tier, pillar, or rule for the user.

    Args:
        config: Settings whose registered rule ids define valid rule selectors.
        selection: String-list selectors to check; absent lists select no values for validation.

    Raises:
        ConfigError: When any include or exclude selector names an unknown tier, pillar or rule.
    """
    valid_tiers = {tier.value for tier in RuleTier}
    valid_pillars = {pillar.value for pillar in Pillar}
    valid_rules = set(config.rules)

    _reject_unknown_selection_values("tiers", selection.get("tiers", []), valid_tiers)
    _reject_unknown_selection_values("pillars", selection.get("pillars", []), valid_pillars)
    _reject_unknown_selection_values("excludePillars", selection.get("excludePillars", []), valid_pillars)
    _reject_unknown_selection_values("rules", selection.get("rules", []), valid_rules)
    _reject_unknown_selection_values("excludeRules", selection.get("excludeRules", []), valid_rules)


def _reject_unknown_selection_values(
    key: str,
    values: list[str],
    valid_values: set[str],
) -> None:
    """Report unknown values under the exact selection key the user needs to edit.

    Args:
        key: Selector list name included in the error path.
        values: Requested selector values; an empty list is valid.
        valid_values: Complete accepted set used to find unsupported requests.

    Raises:
        ConfigError: When at least one requested value is absent from the accepted set.
    """
    unknown = sorted(set(values) - valid_values)
    if unknown:
        raise ConfigError(f"Unknown [tool.gruff-py.selection].{key} values: {unknown}")


def _merged_thresholds(
    rule_id: str,
    rule_settings: RuleSettings,
    rule_section: dict[str, Any],
) -> dict[str, int | float]:
    """Merge supported named thresholds into the settings used by rule findings.

    Args:
        rule_id: Rule identified in invalid-override feedback.
        rule_settings: Registered named thresholds copied before applying overrides.
        rule_section: Supported override table; absent thresholds retains a copy of all registered values.

    Returns:
        A new threshold mapping with valid numeric overrides applied.

    Raises:
        ConfigError: When severity is unpaired, thresholds is not a table, a name is unknown, or a value is non-numeric.
    """
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
    """Build a single severity rubric from the user's paired threshold and severity.

    Args:
        rule_id: Rule identified in invalid-rubric feedback.
        rule_settings: Registered settings indicating whether a single-severity rubric is supported.
        rule_section: Override table; absence of threshold returns no replacement rubric.

    Returns:
        The requested numeric threshold paired with warning or error, or None when no threshold was supplied.

    Raises:
        ConfigError: When the rubric is unsupported, conflicts with named thresholds, or lacks valid numeric/severity values.
    """
    if "threshold" not in rule_section:
        return None
    if "thresholds" in rule_section:
        raise ConfigError(f'Config key "rules.{rule_id}" cannot combine "threshold" and "thresholds".')
    if rule_settings.severity_threshold is None:
        raise ConfigError(f'Config key "rules.{rule_id}.threshold" is only supported for severity-threshold rubrics.')

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
    """Merge validated rule options so the user's scan receives each explicit override.

    Args:
        rule_id: Rule identified when an options value has the wrong shape.
        rule_settings: Registered options copied before applying the supplied values.
        rule_section: Supported override table; absent options retains a copy of all registered options.

    Returns:
        A new options mapping containing registered defaults and explicit overrides.

    Raises:
        ConfigError: When a present options value is not a table.
    """
    options = dict(rule_settings.options)
    if "options" not in rule_section:
        return options
    overrides = rule_section["options"]
    if not isinstance(overrides, dict):
        raise ConfigError(f'options in rule "{rule_id}" must be a table.')
    options.update(overrides)
    return options


def _parse_dead_code_allowlist(section: Any) -> DeadCodeAllowlist:
    """Parse dead-code exceptions that keep intentional entry points out of user findings.

    Args:
        section: Raw deadCode table of symbol, decorator and path string lists; omitted lists become empty tuples.

    Returns:
        An allowlist retaining the supplied strings and their order.

    Raises:
        ConfigError: When the table contains unknown keys or a supplied value is not a list of strings.
    """
    if not isinstance(section, dict):
        raise ConfigError("[tool.gruff-py.allowlists.deadCode] must be a table.")
    unknown = set(section.keys()) - VALID_DEAD_CODE_ALLOWLIST_KEYS
    if unknown:
        raise ConfigError(f"Unknown [tool.gruff-py.allowlists.deadCode] keys: {sorted(unknown)}")
    for key in VALID_DEAD_CODE_ALLOWLIST_KEYS:
        value = section.get(key, [])
        if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
            raise ConfigError(f"[tool.gruff-py.allowlists.deadCode].{key} must be a list of strings.")
    return DeadCodeAllowlist(
        symbols=tuple(section.get("symbols", [])),
        decorators=tuple(section.get("decorators", [])),
        paths=tuple(section.get("paths", [])),
    )


def _parse_python_version(value: Any) -> tuple[int, int]:
    """Parse the minimum Python version used to tailor modernisation findings.

    Args:
        value: Raw version string with at least two integer components separated by dots; later components are ignored.

    Returns:
        The major and minor components as integers.

    Raises:
        ConfigError: When the value is not a string with two components that can be parsed as integers.
    """
    if isinstance(value, str):
        parts = value.split(".")
        if len(parts) >= 2:
            try:
                return (int(parts[0]), int(parts[1]))
            # For example, ``3.next`` reaches this path and becomes a concise config error below.
            except ValueError:
                pass
    raise ConfigError(f"minimumPythonVersion must be a string like '3.11', got {value!r}")
