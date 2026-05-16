"""The single ``Finding`` value object emitted by every rule."""

from dataclasses import dataclass, field
from typing import Any

from gruff.finding.confidence import Confidence
from gruff.finding.fingerprint import fingerprint_for
from gruff.finding.pillar import Pillar
from gruff.finding.rule_tier import RuleTier
from gruff.finding.severity import Severity


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    message: str
    file_path: str
    line: int | None
    severity: Severity
    pillar: Pillar
    tier: RuleTier
    confidence: Confidence
    end_line: int | None = None
    column: int | None = None
    symbol: str | None = None
    remediation: str | None = None
    secondary_pillars: tuple[Pillar, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def fingerprint(self) -> str:
        return fingerprint_for(
            rule_id=self.rule_id,
            file_path=self.file_path,
            line=self.line,
            end_line=self.end_line,
            column=self.column,
            symbol=self.symbol,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "ruleId": self.rule_id,
            "message": self.message,
            "file": self.file_path,
            "line": self.line,
            "endLine": self.end_line,
            "column": self.column,
            "symbol": self.symbol,
            "severity": self.severity.value,
            "pillar": self.pillar.value,
            "secondaryPillars": [p.value for p in self.secondary_pillars],
            "tier": self.tier.value,
            "confidence": self.confidence.value,
            "remediation": self.remediation,
            "fingerprint": self.fingerprint(),
            "metadata": dict(self.metadata),
        }
