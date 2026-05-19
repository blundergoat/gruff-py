"""Static metadata describing a rule (id, pillar, tier, defaults)."""

import re
from dataclasses import dataclass, field
from typing import Any

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity

_RULE_ID_PATTERN = re.compile(r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$")


@dataclass(frozen=True, slots=True)
class RuleDefinition:
    """Static rule metadata: id, pillar, tier, severity, confidence, threshold and option defaults.

    Every ``Rule`` subclass returns one of these from ``definition()``.
    The values are immutable and used by the registry, reporters, and
    SARIF/JSON serialisers; the rule id is validated against
    ``^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$`` on construction.
    """

    id: str
    name: str
    pillar: Pillar
    tier: RuleTier
    default_severity: Severity
    confidence: Confidence = Confidence.HIGH
    default_thresholds: dict[str, int | float] = field(default_factory=dict)
    secondary_pillars: tuple[Pillar, ...] = ()
    default_enabled: bool = True
    default_options: dict[str, Any] = field(default_factory=dict)
    description: str = ""

    def __post_init__(self) -> None:
        if not _RULE_ID_PATTERN.match(self.id):
            raise ValueError(f'Invalid rule id "{self.id}".')
        for name in self.default_thresholds:
            if name == "":
                raise ValueError(f'Rule "{self.id}" has an invalid threshold name.')
        for name in self.default_options:
            if name == "":
                raise ValueError(f'Rule "{self.id}" has an invalid option name.')

    def get_description(self) -> str:
        """Return the human-readable description, falling back to the rule name.

        SARIF and other consumers want a sentence — the ``description``
        field is optional, so reporters call this rather than testing for
        emptiness themselves.

        Returns:
            Non-empty description or the rule's display name.
        """
        return self.description or self.name
