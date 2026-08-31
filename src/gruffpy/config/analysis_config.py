"""Store the resolved analyser configuration for one run.

The loader builds this immutable value before rules execute. CLI and dashboard scans then share
the same rule settings, path filters, allowlists, and output behavior.
"""

from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING

from gruffpy.config.dead_code_allowlist import DeadCodeAllowlist
from gruffpy.config.rule_selection import RuleSelection
from gruffpy.config.rule_settings import RuleSettings, SeverityThreshold
from gruffpy.config.sensitive_exclusions import SensitiveExclusion
from gruffpy.finding.fail_threshold import FailThreshold
from gruffpy.finding.pillar import Pillar

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

DEEP_SCAN_DEFAULT_MAX_LINES = 20_000
DEEP_SCAN_DEFAULT_MAX_BYTES = 2_000_000


@dataclass(frozen=True, slots=True)
class DeepScanBudget:
    """Carry the effective paired bound for expensive Python source analysis."""

    enabled: bool = True
    max_lines: int = DEEP_SCAN_DEFAULT_MAX_LINES
    max_bytes: int = DEEP_SCAN_DEFAULT_MAX_BYTES
    override: str = "default"


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
        allowed_secret_previews: Retained legacy field; supported configs leave it empty and
            analysis ignores it.
        sensitive_exclusions: Reviewed scopes in which one sensitive-data rule stays quiet,
            sourced from the ``sensitiveExclusions:`` config block.
        sensitive_data_rule_ids: Registered rule ids inside the sensitive-data pillar.
            ``from_registry`` fills this because ``gruffpy.config`` cannot import the rule
            registry, and the ``sensitiveExclusions`` validator needs pillar facts.
        dead_code_allowlist: Symbols, decorators, and paths allowed for dead-code rules.
        output_volume_hint_threshold: Finding count at which ``analyse --format text``
            appends a hint pointing at ``summary --group-by=rule``. ``0`` disables the
            hint entirely.
    """

    rules: dict[str, RuleSettings] = field(default_factory=dict)
    minimum_python_version: tuple[int, int] = (3, 11)
    minimum_severity: dict[str, FailThreshold] = field(default_factory=dict)
    rule_selection: RuleSelection = field(default_factory=RuleSelection)
    ignored_path_patterns: tuple[str, ...] = ()
    # This exact family seed keeps fresh configs consistent across implementations.
    # A project list replaces the seed, so users include every accepted abbreviation.
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
    sensitive_exclusions: tuple[SensitiveExclusion, ...] = ()
    sensitive_data_rule_ids: frozenset[str] = frozenset()
    dead_code_allowlist: DeadCodeAllowlist = field(default_factory=DeadCodeAllowlist)
    output_volume_hint_threshold: int = 50
    deep_scan_budget: DeepScanBudget = field(default_factory=DeepScanBudget)

    def __post_init__(self) -> None:
        """Reject a Python target that would make the user's modernisation advice unsupported."""
        if self.minimum_python_version < (3, 11):
            raise ValueError("Minimum Python version must be at least 3.11.")

    @classmethod
    def from_registry(cls, registry: "RuleRegistry") -> "AnalysisConfig":
        """Build a baseline config from each rule's declared defaults.

        Each registered rule contributes its enabled state, thresholds, and options before the
        loader layers the user's overrides on top.

        Args:
            registry: Registry of all built-in and plugin rules.

        Returns:
            Config with every known rule populated at its default values.
        """
        rules: dict[str, RuleSettings] = {}
        sensitive_data_rule_ids: set[str] = set()
        for rule in registry.all():
            definition = rule.definition()
            # The sensitiveExclusions validator rejects a rule outside this pillar, and it runs
            # where the registry is not importable, so the pillar answer is captured here.
            if definition.pillar is Pillar.SENSITIVE_DATA:
                sensitive_data_rule_ids.add(definition.id)
            rules[definition.id] = RuleSettings(
                enabled=definition.default_enabled,
                thresholds=dict(definition.default_thresholds),
                options=dict(definition.default_options),
                severity_threshold=(
                    SeverityThreshold(definition.default_threshold, definition.default_severity) if definition.default_threshold is not None else None
                ),
            )
        return cls(rules=rules, sensitive_data_rule_ids=frozenset(sensitive_data_rule_ids))

    def rule_settings(self, rule_id: str) -> RuleSettings:
        """Return the merged settings for *rule_id*.

        Unknown IDs raise ``KeyError`` for callers; the loader reports unknown user config keys
        before they reach this method.

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

        The user's CLI flag wins, followed by this map and then the binary default.

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
        """Return a copy carrying the legacy secret-preview field.

        The loader accepts only an empty list and analysis ignores this field, so users cannot
        hide sensitive-data findings with preview text.

        Args:
            previews: Legacy values; an empty tuple means the retired setting has no effect for
                the user.

        Returns:
            New ``AnalysisConfig`` carrying the legacy field.
        """
        return replace(self, allowed_secret_previews=previews)

    def with_sensitive_exclusions(self, exclusions: tuple[SensitiveExclusion, ...]) -> "AnalysisConfig":
        """Return a new config whose reviewed sensitive-data suppressions are *exclusions*.

        Every entry is already validated; analysis drops the findings each one claims and reports
        the count, so a suppressed finding is never silently invisible.

        Args:
            exclusions: Validated entries in the order the user wrote them.

        Returns:
            New ``AnalysisConfig`` carrying the sensitive-data exclusions.
        """
        return replace(self, sensitive_exclusions=exclusions)

    def with_output_volume_hint_threshold(self, threshold: int) -> "AnalysisConfig":
        """Return a new config whose ``analyse --format text`` hint threshold is *threshold*.

        Args:
            threshold: Finding count at which ``analyse --format text`` appends
                the ``summary --group-by=rule`` hint; set to ``0`` to disable.

        Returns:
            New ``AnalysisConfig`` with the threshold updated.
        """
        return replace(self, output_volume_hint_threshold=threshold)

    def with_deep_scan_budget(self, budget: DeepScanBudget) -> "AnalysisConfig":
        """Return a new config with the effective deep-scan budget replaced.

        Args:
            budget: Validated paired line/byte limits and their provenance.

        Returns:
            New ``AnalysisConfig`` carrying the supplied budget.
        """
        return replace(self, deep_scan_budget=budget)

    def with_dead_code_allowlist(self, allowlist: DeadCodeAllowlist) -> "AnalysisConfig":
        """Return a new config whose dead-code allowlist is *allowlist*.

        Args:
            allowlist: Path/symbol/decorator allowlist used by the
                ``dead-code.*`` rules.

        Returns:
            New ``AnalysisConfig`` with the allowlist updated.
        """
        return replace(self, dead_code_allowlist=allowlist)
