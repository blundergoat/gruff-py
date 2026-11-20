"""Static metadata describing a rule (id, pillar, tier, defaults)."""

import re
from dataclasses import dataclass, field
from typing import Any

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity

_RULE_ID_PATTERN = re.compile(r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$")

# Knob names gruff-go already publishes for a single-threshold rubric, keyed by rule id. The
# family listing shape (M09, ratified 2026-09-09) carries every threshold as a named map; a rubric
# whose id has no knob name anywhere in the family publishes the one-key map ``{"threshold": N}``
# so no new permanent public identifier is invented.
_LISTING_THRESHOLD_KNOB_NAMES: dict[str, str] = {
    "complexity.cognitive": "maxComplexity",
    "complexity.cyclomatic": "maxComplexity",
    "complexity.nesting-depth": "maxDepth",
    "size.file-length": "maxLines",
    "size.function-length": "maxLines",
    "size.parameter-count": "maxParameters",
}


@dataclass(frozen=True, slots=True)
class RuleDefinition:
    """Static rule metadata: id, pillar, tier, severity, confidence, threshold and option defaults.

    Every ``Rule`` subclass returns one of these from ``definition()``.
    The values are immutable and used by the registry, reporters, and
    SARIF/JSON serialisers; the rule id is validated against
    ``^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$`` on construction.

    Attributes:
        id: Canonical public rule id.
        name: Human-readable rule name.
        pillar: Primary quality pillar.
        tier: Rule maturity tier.
        default_severity: Severity used when the rule emits a finding.
        confidence: Confidence rating for findings emitted by the rule.
        default_thresholds: Named numeric threshold defaults (semantic knobs only).
        default_threshold: Single threshold for a severity-bearing rubric, paired
            with ``default_severity``; ``None`` for non-rubric and knob rules.
        secondary_pillars: Additional pillars affected by the rule.
        default_enabled: Whether the rule runs by default.
        default_options: Free-form option defaults.
        description: Optional sentence used by generated metadata.
    """

    id: str
    name: str
    pillar: Pillar
    tier: RuleTier
    default_severity: Severity
    confidence: Confidence = Confidence.HIGH
    default_thresholds: dict[str, int | float] = field(default_factory=dict)
    default_threshold: int | float | None = None
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

        Reporters use this fallback because description is optional.

        Returns:
            Non-empty description or the rule's display name.
        """
        return self.description or self.name

    def threshold_payload(self) -> dict[str, Any]:
        """Return the JSON-projectable threshold shape for output consumers.

        Single-threshold rubrics follow ADR-014 and return a threshold key; severity remains in defaultSeverity.
        Named-knob rules return a thresholds map; rules with neither return an empty mapping.

        Returns:
            Mapping to splat into a rule-metadata payload.
        """
        if self.default_threshold is not None:
            return {"threshold": self.default_threshold}
        if self.default_thresholds:
            return {"thresholds": dict(self.default_thresholds)}
        return {}

    def listing_threshold_payload(self) -> dict[str, Any]:
        """Return the family listing projection of this rule's thresholds.

        Single values use a family knob name, falling back to threshold; named maps are copied unchanged.
        With neither form set, the payload is empty. threshold_payload keeps its separate shape for SARIF.

        Returns:
            A thresholds entry to merge into the rule listing, or an empty mapping when the rule has no threshold defaults.
        """
        if self.default_threshold is not None:
            knob = _LISTING_THRESHOLD_KNOB_NAMES.get(self.id, "threshold")
            return {"thresholds": {knob: self.default_threshold}}
        if self.default_thresholds:
            return {"thresholds": dict(self.default_thresholds)}
        return {}
