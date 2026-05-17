"""Loads ``.gruff.yaml`` and ``pyproject.toml`` config into an ``AnalysisConfig``."""

import tomllib
from pathlib import Path
from typing import Any

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.exceptions import ConfigError
from gruffpy.config.rule_selection import RuleSelection
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.config.yaml_loader import load_gruff_yaml

VALID_TOP_LEVEL_KEYS = frozenset(
    {
        "minimumPythonVersion",
        "paths",
        "allowlists",
        "selection",
        "rules",
    }
)
VALID_PATHS_KEYS = frozenset({"ignore"})
VALID_ALLOWLISTS_KEYS = frozenset({"acceptedAbbreviations", "secretPreviews"})
VALID_SELECTION_KEYS = frozenset(
    {
        "tiers",
        "pillars",
        "rules",
        "excludePillars",
        "excludeRules",
    }
)
VALID_RULE_KEYS = frozenset({"enabled", "thresholds", "options"})
TOML_TOOL_KEY = "gruff-py"
LEGACY_TOML_TOOL_KEY = "gruff"
TOML_TABLE = f"[tool.{TOML_TOOL_KEY}]"


class ConfigLoader:
    def __init__(self, project_root: str | Path, analysis_config: AnalysisConfig) -> None:
        self._project_root = Path(project_root)
        self._defaults = analysis_config

    def load(self, config_path: Path | None = None) -> tuple[AnalysisConfig, Path | None]:
        """Load config, honouring `.gruff.yaml` / `pyproject.toml` precedence.

        Returns ``(config, source_path)`` where ``source_path`` is the file the
        config was loaded from, or ``None`` if no config file was found and
        defaults are used.

        Precedence:

        1. Explicit *config_path* (format auto-detected by extension).
        2. ``.gruff.yaml`` in the project root.
        3. ``pyproject.toml`` ``[tool.gruff-py]`` in the project root.
        4. Built-in defaults.
        """
        if config_path is not None:
            return self._load_explicit(config_path)

        yaml_path = self._project_root / ".gruff.yaml"
        if yaml_path.exists():
            section = load_gruff_yaml(yaml_path)
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
            return self._defaults, None
        if path.suffix in {".yaml", ".yml"}:
            section = load_gruff_yaml(path)
            if not section:
                return self._defaults, path
            self._validate_top_level(section, source=str(path))
            return self._apply_config_section(section), path
        toml_section = self._load_toml_section(path)
        if toml_section is None:
            return self._defaults, path
        return self._apply_config_section(toml_section), path

    def _load_toml_section(self, path: Path) -> dict[str, Any] | None:
        try:
            with open(path, "rb") as f:
                data = tomllib.load(f)
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ConfigError(f"Failed to read config file {path}: {exc}") from exc
        tool_section = data.get("tool", {})
        section = tool_section.get(TOML_TOOL_KEY)
        if section is None:
            if LEGACY_TOML_TOOL_KEY in tool_section:
                raise ConfigError(f"Use {TOML_TABLE} in {path}; [tool.gruff] is not supported.")
            return None
        if not isinstance(section, dict):
            raise ConfigError(f"{TOML_TABLE} must be a table.")
        self._validate_top_level(section, source=f"{TOML_TABLE} in {path}")
        return section

    @staticmethod
    def _validate_top_level(section: dict[str, Any], source: str) -> None:
        unknown = set(section.keys()) - VALID_TOP_LEVEL_KEYS
        if unknown:
            raise ConfigError(f"Unknown gruff keys in {source}: {sorted(unknown)}")

    def _apply_config_section(self, section: dict[str, Any]) -> AnalysisConfig:
        config = self._defaults

        if "minimumPythonVersion" in section:
            config = config.with_minimum_python_version(
                _parse_python_version(section["minimumPythonVersion"])
            )

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
        for key in ("acceptedAbbreviations", "secretPreviews"):
            value = allowlists.get(key, [])
            if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
                raise ConfigError(f"[tool.gruff-py.allowlists].{key} must be a list of strings.")
        config = config.with_accepted_abbreviations(
            tuple(allowlists.get("acceptedAbbreviations", []))
        )
        return config.with_allowed_secret_previews(tuple(allowlists.get("secretPreviews", [])))

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
        return config.with_rule_selection(
            RuleSelection(
                tiers=tuple(selection.get("tiers", [])),
                pillars=tuple(selection.get("pillars", [])),
                rules=tuple(selection.get("rules", [])),
                exclude_pillars=tuple(selection.get("excludePillars", [])),
                exclude_rules=tuple(selection.get("excludeRules", [])),
            )
        )

    @staticmethod
    def _apply_rules(config: AnalysisConfig, rules: Any) -> AnalysisConfig:
        if not isinstance(rules, dict):
            raise ConfigError("[tool.gruff-py.rules] must be a table.")
        for rule_id, rule_section in rules.items():
            _validate_rule_section(config, rule_id, rule_section)
            rule_settings = config.rules[rule_id]
            config = config.with_rule_settings(
                rule_id,
                RuleSettings(
                    enabled=_is_rule_enabled(rule_settings, rule_section),
                    thresholds=_merged_thresholds(rule_id, rule_settings, rule_section),
                    options=_merged_options(rule_id, rule_settings, rule_section),
                ),
            )
        return config


def _validate_rule_section(
    config: AnalysisConfig,
    rule_id: str,
    rule_section: dict[str, Any],
) -> None:
    if not isinstance(rule_section, dict):
        raise ConfigError(f'[tool.gruff-py.rules."{rule_id}"] must be a table.')
    unknown = set(rule_section.keys()) - VALID_RULE_KEYS
    if unknown:
        raise ConfigError(f'Unknown keys in [tool.gruff-py.rules."{rule_id}"]: {sorted(unknown)}')
    if rule_id not in config.rules:
        raise ConfigError(f'Unknown rule id "{rule_id}".')


def _is_rule_enabled(rule_settings: RuleSettings, rule_section: dict[str, Any]) -> bool:
    return bool(rule_section.get("enabled", rule_settings.enabled))


def _merged_thresholds(
    rule_id: str,
    rule_settings: RuleSettings,
    rule_section: dict[str, Any],
) -> dict[str, int | float]:
    thresholds = dict(rule_settings.thresholds)
    if "thresholds" not in rule_section:
        return thresholds
    overrides = rule_section["thresholds"]
    if not isinstance(overrides, dict):
        raise ConfigError(f'thresholds in rule "{rule_id}" must be a table.')
    for key, value in overrides.items():
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise ConfigError(f'threshold "{key}" in rule "{rule_id}" must be a number.')
        thresholds[key] = value
    return thresholds


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


def _parse_python_version(value: Any) -> tuple[int, int]:
    if isinstance(value, str):
        parts = value.split(".")
        if len(parts) >= 2:
            try:
                return (int(parts[0]), int(parts[1]))
            except ValueError:
                pass
    raise ConfigError(f"minimumPythonVersion must be a string like '3.11', got {value!r}")
