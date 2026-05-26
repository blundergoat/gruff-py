"""Frozen value object holding the resolved analyser configuration for one run."""

from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING

from gruffpy.config.dead_code_allowlist import DeadCodeAllowlist
from gruffpy.config.rule_selection import RuleSelection
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.finding.fail_threshold import FailThreshold

if TYPE_CHECKING:
    from gruffpy.rule.registry import RuleRegistry

MINIMUM_SEVERITY_BINARY_DEFAULTS: dict[str, FailThreshold] = {
    "analyse": FailThreshold.ADVISORY,
    "report": FailThreshold.NONE,
    "dashboard": FailThreshold.NONE,
}
"""Binary defaults for the per-command ``--fail-on`` threshold (ADR-019).

These are the values ``gruff-py init`` writes into the ``minimumSeverity:`` block
and the values the CLI consumers fall back to when neither a ``--fail-on`` flag
nor a configured override is set."""


@dataclass(frozen=True, slots=True)
class AnalysisConfig:
    """Resolved analyser configuration for one run: rules, ignore globs, allowlists, Python pin.

    Immutable. ``from_registry`` seeds per-rule defaults; the
    ``with_*`` methods produce updated copies as the config loader
    layers user overrides on top.

    Attributes:
        rules: Per-rule settings keyed by rule id.
        minimum_python_version: Minimum Python version assumed by modernisation rules.
        minimum_severity: Per-command ``--fail-on`` defaults sourced from the
            ``minimumSeverity:`` config block. Keys are gateable subcommand names
            (``analyse``, ``report``, ``dashboard``); the validator rejects any
            other key.
        rule_selection: Include and exclude selectors applied before analysis.
        ignored_path_patterns: Configured path globs excluded during discovery.
        accepted_abbreviations: Project-approved abbreviations for naming rules.
        allowed_secret_previews: Redacted secret previews allowed by config.
        dead_code_allowlist: Symbols, decorators, and paths allowed for dead-code rules.
    """

    rules: dict[str, RuleSettings] = field(default_factory=dict)
    minimum_python_version: tuple[int, int] = (3, 11)
    minimum_severity: dict[str, FailThreshold] = field(default_factory=dict)
    rule_selection: RuleSelection = field(default_factory=RuleSelection)
    ignored_path_patterns: tuple[str, ...] = ()
    # Seed value matches the gruff-rs/gruff-ts runtime defaults and the
    # gruff-py init template; project-specific vocabulary should be appended
    # in the user's config rather than added here.
    accepted_abbreviations: tuple[str, ...] = (
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
    allowed_secret_previews: tuple[str, ...] = ()
    dead_code_allowlist: DeadCodeAllowlist = field(default_factory=DeadCodeAllowlist)

    def __post_init__(self) -> None:
        if self.minimum_python_version < (3, 11):
            raise ValueError("Minimum Python version must be at least 3.11.")

    @classmethod
    def from_registry(cls, registry: "RuleRegistry") -> "AnalysisConfig":
        """Build a baseline config from each rule's declared defaults.

        Initialises the ``rules`` mapping with one ``RuleSettings`` per
        registered rule, seeded from its ``RuleDefinition`` defaults
        (enabled flag, thresholds, options). Loader code then layers
        user overrides on top via :meth:`with_rule_settings`.

        Args:
            registry: Registry of all built-in and plugin rules.

        Returns:
            Config with every known rule populated at its default values.
        """
        rules: dict[str, RuleSettings] = {}
        for rule in registry.all():
            definition = rule.definition()
            rules[definition.id] = RuleSettings(
                enabled=definition.default_enabled,
                thresholds=dict(definition.default_thresholds),
                options=dict(definition.default_options),
            )
        return cls(rules=rules)

    def rule_settings(self, rule_id: str) -> RuleSettings:
        """Return the merged settings for *rule_id*.

        Raises ``KeyError`` for unknown ids - this is a programming error
        on the caller's part, not a user-input issue (unknown rules in
        user config are flagged separately by the loader).

        Args:
            rule_id: Canonical rule id (e.g. ``"size.function-length"``).

        Returns:
            Resolved settings (enabled flag, thresholds, options).

        Raises:
            KeyError: When ``rule_id`` is not present in this config.
        """
        if rule_id not in self.rules:
            raise KeyError(f'Unknown rule id "{rule_id}".')
        return self.rules[rule_id]

    def with_rule_settings(self, rule_id: str, settings: RuleSettings) -> "AnalysisConfig":
        """Return a new config with *rule_id*'s settings replaced.

        Args:
            rule_id: Existing rule id; must already be present.
            settings: Replacement settings record.

        Returns:
            New ``AnalysisConfig`` with the single rule entry updated.

        Raises:
            KeyError: When ``rule_id`` is not present in this config.
        """
        if rule_id not in self.rules:
            raise KeyError(f'Unknown rule id "{rule_id}".')
        new_rules = dict(self.rules)
        new_rules[rule_id] = settings
        return replace(self, rules=new_rules)

    def with_minimum_python_version(self, version: tuple[int, int]) -> "AnalysisConfig":
        """Return a new config whose minimum-supported-Python pin is *version*.

        Used by modernisation rules to decide which language features are
        safe to require.

        Args:
            version: ``(major, minor)`` tuple, e.g. ``(3, 11)``.

        Returns:
            New ``AnalysisConfig`` with the pin updated.
        """
        return replace(self, minimum_python_version=version)

    def with_minimum_severity(self, minimum_severity: dict[str, FailThreshold]) -> "AnalysisConfig":
        """Return a new config whose per-command ``--fail-on`` defaults are *minimum_severity*.

        Consumed by the analyse / report / dashboard CLI consumers as the
        middle tier of the precedence rule (CLI flag wins, then this map,
        then the binary default).

        Args:
            minimum_severity: Mapping from gateable subcommand name to
                ``FailThreshold``. Empty mapping means "no per-command
                override; fall through to the binary default."

        Returns:
            New ``AnalysisConfig`` with the per-command defaults updated.
        """
        return replace(self, minimum_severity=dict(minimum_severity))

    def with_rule_selection(self, selection: RuleSelection) -> "AnalysisConfig":
        """Return a new config with the rule include/exclude selection swapped.

        Args:
            selection: ``RuleSelection`` capturing the CLI filter flags.

        Returns:
            New ``AnalysisConfig`` carrying the updated selection.
        """
        return replace(self, rule_selection=selection)

    def with_ignored_path_patterns(self, patterns: tuple[str, ...]) -> "AnalysisConfig":
        """Return a new config whose ignore-path globs are *patterns*.

        Args:
            patterns: Project-relative glob patterns to exclude from discovery.

        Returns:
            New ``AnalysisConfig`` with the patterns updated.
        """
        return replace(self, ignored_path_patterns=patterns)

    def with_accepted_abbreviations(self, abbrevs: tuple[str, ...]) -> "AnalysisConfig":
        """Return a new config whose naming-rule allowlist is *abbrevs*.

        Consumed by ``naming.abbreviation`` to exempt project-standard short
        forms (``ctx``, ``msg``, ``cfg``).

        Args:
            abbrevs: Allowed-abbreviation tokens, lowercase.

        Returns:
            New ``AnalysisConfig`` with the allowlist updated.
        """
        return replace(self, accepted_abbreviations=abbrevs)

    def with_allowed_secret_previews(self, previews: tuple[str, ...]) -> "AnalysisConfig":
        """Return a new config whose sensitive-data allowlist is *previews*.

        Each preview is the redacted token surfaced in a finding; matching
        previews are silently filtered before reporting.

        Args:
            previews: Redacted-preview strings copied from prior findings.

        Returns:
            New ``AnalysisConfig`` with the allowlist updated.
        """
        return replace(self, allowed_secret_previews=previews)

    def with_dead_code_allowlist(self, allowlist: DeadCodeAllowlist) -> "AnalysisConfig":
        """Return a new config whose dead-code allowlist is *allowlist*.

        Args:
            allowlist: Path/symbol/decorator allowlist used by the
                ``dead-code.*`` rules.

        Returns:
            New ``AnalysisConfig`` with the allowlist updated.
        """
        return replace(self, dead_code_allowlist=allowlist)
