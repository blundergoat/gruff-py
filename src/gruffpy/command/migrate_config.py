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
        return self.has_changes() and any(line.lstrip().startswith("#") for line in self.original_text.splitlines())


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
    """Choose the YAML config file to migrate.

    The explicit path wins when one is given; otherwise the first of .gruff-py.yaml and .gruff.yaml found in the project root is used.

    Args:
        project_root: Directory searched for .gruff-py.yaml, then .gruff.yaml, when config_path is None; it is also checked for pyproject.toml when
            neither YAML file exists.
        config_path: Explicit config path supplied by the user, or None to discover one in project_root; an explicit path is validated and never falls
            back to discovery.

    Returns:
        The explicit config_path unchanged when given, otherwise the first YAML config found directly in project_root.

    Raises:
        ConfigError: When the explicit path has a .toml suffix, or discovery finds no YAML config but pyproject.toml exists (both carry the hand-edit
            guidance for TOML configs); when the explicit path's suffix is not .yaml or .yml; when the explicit path does not exist; or when discovery
            finds neither a YAML config nor pyproject.toml, in which case the message points to gruff-py init.
    """
    if config_path is not None:
        if config_path.suffix == ".toml":
            raise ConfigError(_TOML_GUIDANCE)
        if config_path.suffix not in {".yaml", ".yml"}:
            raise ConfigError(f"Unsupported config file extension for {config_path}; use .yaml or .yml.")
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
    """Build the migrated form of a parsed config document, with schemaVersion pinned as its first key.

    It also collects the change lines for each rewrite and the notes for unknown rule ids left as-is. The input document is deep-copied and never
    mutated. A schemaVersion change line is recorded only when the existing value is absent or differs from the current schema version. The 0.6.0 key
    moves are applied next (a per-command minimumSeverity mapping is renamed to failOn and allowlists.secretPreviews is removed), then each rule
    section under rules whose id is a known rule gets the legacy threshold rewrite. A rule section that is not a mapping is skipped without a note,
    while an unknown rule id is passed through unchanged and reported as a note rather than a change line.

    Args:
        document: The config mapping parsed from the YAML file; it is deep-copied before any rewrite.
        defaults: Registry-default analysis config whose rules map decides which rule ids are known and supplies each known rule's default settings
            for the legacy threshold rewrite.

    Returns:
        A tuple of the migrated document, the change lines for every rewrite applied (empty when the config is already current), and the notes for
        unknown rule ids left as-is.
    """
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

    changes.extend(_migrate_zero_six_keys(migrated))

    rules = migrated.get("rules")
    if isinstance(rules, dict):
        for rule_id, section in rules.items():
            if not isinstance(section, dict):
                continue
            if rule_id not in defaults.rules:
                notes.append(f"rules.{rule_id}: unknown rule id, left as-is (analysis warns about it)")
                continue
            changes.extend(_migrate_rule_section(rule_id, section, defaults.rules[rule_id]))
    return migrated, changes, notes


def _migrate_zero_six_keys(migrated: dict[str, Any]) -> list[str]:
    """Apply the two key moves 0.6.0 made, both of which the loader now refuses outright.

    The per-command exit gate left ``minimumSeverity`` for ``failOn``; the same
    key as a single severity is the 0.6 display floor and stays where it is.
    ``allowlists.secretPreviews`` was removed because FAMILY-CONTRACT.md
    section 5 makes category markers unconditional, and the key authorises
    nothing.

    Args:
        migrated: The working document, edited in place.

    Returns:
        One readable line per rewrite; empty when the document was already
        current.
    """
    changes: list[str] = []

    gate = migrated.get("minimumSeverity")
    # Only the per-command mapping is the old gate; a bare severity is the 0.6 display floor and keeps its name.
    if isinstance(gate, dict):
        migrated["failOn"] = migrated.pop("minimumSeverity")
        changes.append("minimumSeverity: renamed to failOn, the key that gates the exit code in 0.6")

    allowlists = migrated.get("allowlists")
    # Presence is the test, not content: an empty list reads as configured redaction just as a populated one does.
    if isinstance(allowlists, dict) and "secretPreviews" in allowlists:
        allowlists.pop("secretPreviews")
        changes.append("allowlists.secretPreviews: removed; section 5 makes category markers unconditional")

        # A block whose last key just went is a mapping with nothing in it, which the loader reads as neither shape.
        if not allowlists:
            migrated.pop("allowlists")

    return changes


def _migrate_rule_section(
    rule_id: str,
    section: dict[str, Any],
    default_settings: RuleSettings,
) -> list[str]:
    """Replace a rule section's legacy warning and error threshold tiers with a single threshold and severity, in place.

    Only warning and error keys that are not threshold names in the rule's default settings count as legacy tiers; other thresholds keys are kept, and
    the thresholds mapping is deleted when nothing remains in it. The error tier wins when both legacy tiers are present. For a rule without a
    severity rubric the legacy tiers are only removed. When the section already has a threshold, that threshold and any existing severity are kept and
    a missing severity is filled from the winning tier name. Otherwise the winning tier's value becomes threshold and its tier name becomes severity,
    replacing any severity already set.

    Args:
        rule_id: Rule id used only to label the returned change line.
        section: The rule's config mapping, mutated in place: legacy tiers are deleted, and threshold and severity may be set.
        default_settings: Registry-default settings for the rule; its threshold names decide whether a warning or error key is a real knob rather than
            a legacy tier, and its severity rubric decides whether the legacy value is converted or only removed.

    Returns:
        A one-item list holding the change line that describes the removal or conversion, or an empty list when the section has no thresholds mapping
        or no legacy tiers.
    """
    thresholds = section.get("thresholds")
    if not isinstance(thresholds, dict):
        return []
    legacy = {tier: thresholds[tier] for tier in ("warning", "error") if tier in thresholds and tier not in default_settings.thresholds}
    if not legacy:
        return []
    for tier in legacy:
        del thresholds[tier]
    if not thresholds:
        del section["thresholds"]
    dropped = ", ".join(f"thresholds.{tier}={value}" for tier, value in sorted(legacy.items()))
    if not _is_rubric(default_settings):
        return [f"rules.{rule_id}: removed legacy {dropped}; the rule has no severity rubric and runs at its defaults"]
    tier = "error" if "error" in legacy else "warning"
    if "threshold" in section:
        if "severity" in section:
            return [f"rules.{rule_id}: removed legacy {dropped}; an explicit threshold/severity pair is already present"]
        # threshold without severity is fatal even in non-strict mode, so fill
        # the missing half from the legacy tier rather than write a config that
        # cannot load.
        section["severity"] = tier
        return [f"rules.{rule_id}: removed legacy {dropped}; kept the existing threshold and added the missing severity={tier}"]
    section["threshold"] = legacy[tier]
    section["severity"] = tier
    note = f"rules.{rule_id}: thresholds.{tier} -> threshold={legacy[tier]}, severity={tier}"
    if len(legacy) == 2:
        note += f" (warning tier {legacy['warning']} dropped; single-threshold contract)"
    return [note]


def _is_rubric(settings: RuleSettings) -> bool:
    """Report whether a rule's default settings carry a severity rubric that a legacy threshold tier can be converted into.

    Args:
        settings: Registry-default settings for one rule.

    Returns:
        True when the settings define a single threshold and severity pair; False when the rule has no severity rubric, so legacy tiers are dropped
        rather than converted.
    """
    return settings.severity_threshold is not None
