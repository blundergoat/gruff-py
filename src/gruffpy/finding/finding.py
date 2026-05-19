"""The single ``Finding`` value object emitted by every rule."""

from dataclasses import dataclass, field
from typing import Any

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.fingerprint import fingerprint_for
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity


@dataclass(frozen=True, slots=True)
class Finding:
    """One rule violation: rule id, location, severity, and optional remediation metadata.

    Immutable. Every rule's ``analyse()`` returns a list of these. The
    fingerprint computed from rule id + location + symbol is the stable
    cross-implementation identity used by baselines and dedup.
    """

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
        """Compute the stable 16-char identifier used for baselines and dedup.

        Byte-compatible with gruff-php so baselines cross-apply between
        implementations. See :mod:`gruffpy.finding.fingerprint` for the
        algorithm.

        Returns:
            str: Lowercase hex string, 16 characters of a SHA-256 prefix.
        """
        return fingerprint_for(
            rule_id=self.rule_id,
            file_path=self.file_path,
            line=self.line,
            end_line=self.end_line,
            column=self.column,
            symbol=self.symbol,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialise the finding to its ``gruff-py.analysis.v1`` JSON shape.

        Keys are camelCased to match the shared schema; the ``fingerprint``
        is computed on the fly to avoid serialising stale values when
        callers mutate metadata.

        Returns:
            JSON-ready dict with every public field plus computed fingerprint.
        """
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
