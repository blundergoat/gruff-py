"""Rewrite legacy gruff config key shapes to the current schema (``migrate-config``)."""

import copy
import difflib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from gruffpy.analysis.schema import CONFIG_SCHEMA_VERSION
from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.exceptions import ConfigError
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.config.yaml_loader import load_gruff_py_yaml
from gruffpy.rule.registry import RuleRegistry

_TOML_GUIDANCE = (
    "migrate-config rewrites YAML configs only. For pyproject.toml "
    "[tool.gruff-py], apply the same edits by hand: set "
    f'schemaVersion = "{CONFIG_SCHEMA_VERSION}" and replace each '
    'rules."<id>".thresholds {warning, error} pair with a single '
    '"threshold" plus "severity".'
)


@dataclass(frozen=True, slots=True)
class ConfigMigration:
    """Outcome of migrating one YAML config file.

    Attributes:
        path: The config file the migration targets.
        original_text: File content before migration.
        migrated_text: Rendered YAML after migration.
        changes: One human-readable line per applied rewrite; empty when the
            config is already current.
    """

    path: Path
    original_text: str
    migrated_text: str
    changes: tuple[str, ...]
    notes: tuple[str, ...] = ()

    def has_changes(self) -> bool:
        """Return whether the migration rewrote anything.

        Returns:
            True when at least one rewrite applies; informational notes alone
            do not count.
        """
        return bool(self.changes)

    def diff(self) -> str:
        """Return a unified diff between the original and migrated YAML text.

        Returns:
            ``difflib.unified_diff`` text; empty when nothing changed.
        """
        return "".join(
            difflib.unified_diff(
                self.original_text.splitlines(keepends=True),
                self.migrated_text.splitlines(keepends=True),
                fromfile=str(self.path),
                tofile=f"{self.path} (migrated)",
            )
        )

    def will_lose_comments(self) -> bool:
        """Return whether applying the migration would drop YAML comments.

        Returns:
            True when a rewrite applies and the original text carries comment
            lines (the data-level re-render cannot preserve them).
        """
        return self.has_changes() and any(
            line.lstrip().startswith("#") for line in self.original_text.splitlines()
        )


def migrate_config_file(project_root: Path, config_path: Path | None) -> ConfigMigration:
    """Compute the migrated form of the project's YAML config.

    Rewrites the legacy two-tier ``thresholds: {warning, error}`` shape to the
    single ``threshold`` + ``severity`` rubric (the error tier wins when both
    are present) and pins ``schemaVersion`` to the current value. Allowlists,
    ``paths.ignore``, ``selection``, ``minimumSeverity``, per-rule ``enabled``
    and ``options`` (including ``conventionalModuleNames``), and valid
    ``thresholds`` knobs pass through unchanged. Nothing is written to disk;
    the caller decides whether to apply :attr:`ConfigMigration.migrated_text`.

    Args:
        project_root: Directory used for config discovery when *config_path*
            is ``None``.
        config_path: Explicit YAML config path, or ``None`` to discover
            ``.gruff-py.yaml`` / ``.gruff.yaml`` in *project_root*.

    Returns:
        The migration result with the rendered YAML and per-change notes.

    Raises:
        ConfigError: When no YAML config exists to migrate, the path is not a
            YAML file, or the file cannot be parsed.
    """
    target = _resolve_target(project_root, config_path)
    try:
        original_text = target.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Failed to read config file {target}: {exc}") from exc
    document = load_gruff_py_yaml(target)
    defaults = AnalysisConfig.from_registry(RuleRegistry.defaults())
    migrated, changes, notes = _migrate_document(document, defaults)
    migrated_text = yaml.safe_dump(migrated, sort_keys=False, default_flow_style=False)
    if not changes:
        migrated_text = original_text
    return ConfigMigration(
        path=target,
        original_text=original_text,
        migrated_text=migrated_text,
        changes=tuple(changes),
        notes=tuple(notes),
    )


def _resolve_target(project_root: Path, config_path: Path | None) -> Path:
    if config_path is not None:
        if config_path.suffix == ".toml":
            raise ConfigError(_TOML_GUIDANCE)
        if config_path.suffix not in {".yaml", ".yml"}:
            raise ConfigError(
                f"Unsupported config file extension for {config_path}; use .yaml or .yml."
            )
        if not config_path.exists():
            raise ConfigError(f"Config file does not exist: {config_path}")
        return config_path
    for name in (".gruff-py.yaml", ".gruff.yaml"):
        candidate = project_root / name
        if candidate.exists():
            return candidate
    if (project_root / "pyproject.toml").exists():
        raise ConfigError(_TOML_GUIDANCE)
    raise ConfigError("No gruff YAML config found to migrate; run `gruff-py init` first.")


def _migrate_document(
    document: dict[str, Any],
    defaults: AnalysisConfig,
) -> tuple[dict[str, Any], list[str], list[str]]:
    changes: list[str] = []
    notes: list[str] = []
    working = copy.deepcopy(document)

    if working.get("schemaVersion") != CONFIG_SCHEMA_VERSION:
        previous = working.get("schemaVersion")
        label = repr(previous) if previous is not None else "absent"
        changes.append(f"schemaVersion: {label} -> {CONFIG_SCHEMA_VERSION!r}")
    migrated: dict[str, Any] = {"schemaVersion": CONFIG_SCHEMA_VERSION}
    for key, value in working.items():
        if key != "schemaVersion":
            migrated[key] = value

    rules = migrated.get("rules")
    if isinstance(rules, dict):
        for rule_id, section in rules.items():
            if not isinstance(section, dict):
                continue
            if rule_id not in defaults.rules:
                notes.append(
                    f"rules.{rule_id}: unknown rule id, left as-is (analysis warns about it)"
                )
                continue
            changes.extend(_migrate_rule_section(rule_id, section, defaults.rules[rule_id]))
    return migrated, changes, notes


def _migrate_rule_section(
    rule_id: str,
    section: dict[str, Any],
    default_settings: RuleSettings,
) -> list[str]:
    thresholds = section.get("thresholds")
    if not isinstance(thresholds, dict):
        return []
    legacy = {
        tier: thresholds[tier]
        for tier in ("warning", "error")
        if tier in thresholds and tier not in default_settings.thresholds
    }
    if not legacy:
        return []
    for tier in legacy:
        del thresholds[tier]
    if not thresholds:
        del section["thresholds"]
    dropped = ", ".join(f"thresholds.{tier}={value}" for tier, value in sorted(legacy.items()))
    if not _is_rubric(default_settings):
        return [
            f"rules.{rule_id}: removed legacy {dropped}; the rule has no severity rubric "
            "and runs at its defaults"
        ]
    if "threshold" in section:
        return [
            f"rules.{rule_id}: removed legacy {dropped}; an explicit threshold/severity "
            "pair is already present"
        ]
    tier = "error" if "error" in legacy else "warning"
    section["threshold"] = legacy[tier]
    section["severity"] = tier
    note = f"rules.{rule_id}: thresholds.{tier} -> threshold={legacy[tier]}, severity={tier}"
    if len(legacy) == 2:
        note += f" (warning tier {legacy['warning']} dropped; single-threshold contract)"
    return [note]


def _is_rubric(settings: RuleSettings) -> bool:
    return settings.severity_threshold is not None
