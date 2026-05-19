"""Tier/pillar/rule inclusion-exclusion selectors applied to the rule registry."""

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gruffpy.rule.definition import RuleDefinition


@dataclass(frozen=True, slots=True)
class RuleSelection:
    tiers: tuple[str, ...] = ()
    pillars: tuple[str, ...] = ()
    rules: tuple[str, ...] = ()
    exclude_pillars: tuple[str, ...] = ()
    exclude_rules: tuple[str, ...] = ()

    def is_allowed(self, definition: "RuleDefinition") -> bool:
        """Return whether *definition* survives both include and exclude selectors.

        Include selectors are OR'd (any tier/pillar/rule match passes).
        Exclude selectors always win — a rule explicitly excluded never
        runs, regardless of include matches.

        Args:
            definition: Rule definition to test.

        Returns:
            True when the rule should be registered and run.
        """
        if not self._is_included(definition):
            return False
        if definition.pillar.value in self.exclude_pillars:
            return False
        return definition.id not in self.exclude_rules

    def _is_included(self, definition: "RuleDefinition") -> bool:
        if not self.tiers and not self.pillars and not self.rules:
            return True
        return (
            definition.tier.value in self.tiers
            or definition.pillar.value in self.pillars
            or definition.id in self.rules
        )

    def to_dict(self) -> dict[str, list[str]]:
        """Serialise the selection into the camelCase shape used in report metadata.

        Returns:
            Plain dict with include and exclude lists for tiers, pillars,
            and rule ids.
        """
        return {
            "tiers": list(self.tiers),
            "pillars": list(self.pillars),
            "rules": list(self.rules),
            "excludePillars": list(self.exclude_pillars),
            "excludeRules": list(self.exclude_rules),
        }
