"""Frozen value object holding the resolved analyser configuration for one run."""

from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING

from gruff.config.rule_selection import RuleSelection
from gruff.config.rule_settings import RuleSettings

if TYPE_CHECKING:
    from gruff.rule.registry import RuleRegistry


@dataclass(frozen=True, slots=True)
class AnalysisConfig:
    rules: dict[str, RuleSettings] = field(default_factory=dict)
    minimum_python_version: tuple[int, int] = (3, 11)
    rule_selection: RuleSelection = field(default_factory=RuleSelection)
    ignored_path_patterns: tuple[str, ...] = ()
    accepted_abbreviations: tuple[str, ...] = ()
    allowed_secret_previews: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.minimum_python_version < (3, 11):
            raise ValueError("Minimum Python version must be at least 3.11.")

    @classmethod
    def from_registry(cls, registry: "RuleRegistry") -> "AnalysisConfig":
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
        if rule_id not in self.rules:
            raise KeyError(f'Unknown rule id "{rule_id}".')
        return self.rules[rule_id]

    def with_rule_settings(self, rule_id: str, settings: RuleSettings) -> "AnalysisConfig":
        if rule_id not in self.rules:
            raise KeyError(f'Unknown rule id "{rule_id}".')
        new_rules = dict(self.rules)
        new_rules[rule_id] = settings
        return replace(self, rules=new_rules)

    def with_minimum_python_version(self, version: tuple[int, int]) -> "AnalysisConfig":
        return replace(self, minimum_python_version=version)

    def with_rule_selection(self, selection: RuleSelection) -> "AnalysisConfig":
        return replace(self, rule_selection=selection)

    def with_ignored_path_patterns(self, patterns: tuple[str, ...]) -> "AnalysisConfig":
        return replace(self, ignored_path_patterns=patterns)

    def with_accepted_abbreviations(self, abbrevs: tuple[str, ...]) -> "AnalysisConfig":
        return replace(self, accepted_abbreviations=abbrevs)

    def with_allowed_secret_previews(self, previews: tuple[str, ...]) -> "AnalysisConfig":
        return replace(self, allowed_secret_previews=previews)
