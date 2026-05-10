from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gruff.rule.definition import RuleDefinition


@dataclass(frozen=True, slots=True)
class RuleSelection:
    tiers: tuple[str, ...] = ()
    pillars: tuple[str, ...] = ()
    rules: tuple[str, ...] = ()
    exclude_pillars: tuple[str, ...] = ()
    exclude_rules: tuple[str, ...] = ()

    def allows(self, definition: "RuleDefinition") -> bool:
        included = not self.tiers and not self.pillars and not self.rules
        if not included and definition.tier.value in self.tiers:
            included = True
        if not included and definition.pillar.value in self.pillars:
            included = True
        if not included and definition.id in self.rules:
            included = True
        if not included:
            return False
        if definition.pillar.value in self.exclude_pillars:
            return False
        return definition.id not in self.exclude_rules

    def to_dict(self) -> dict[str, list[str]]:
        return {
            "tiers": list(self.tiers),
            "pillars": list(self.pillars),
            "rules": list(self.rules),
            "excludePillars": list(self.exclude_pillars),
            "excludeRules": list(self.exclude_rules),
        }
