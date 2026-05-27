"""The single ``Finding`` value object emitted by every rule."""

from dataclasses import dataclass, field
from typing import Any

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.fingerprint import fingerprint_for, stable_identity_for
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity


@dataclass(frozen=True, slots=True)
class Finding:
    """One rule violation: rule id, location, severity, and optional remediation metadata.

    Immutable. Every rule's ``analyse()`` returns a list of these. The
    fingerprint computed from rule id + location + symbol is the stable
    cross-implementation identity used by baselines and dedup.

    Attributes:
        rule_id: Canonical rule id that emitted the finding.
        message: Human-readable finding message.
        file_path: Display path for the finding location.
        line: Optional one-based start line.
        severity: Finding severity.
        pillar: Primary quality pillar.
        tier: Rule maturity tier.
        confidence: Rule confidence rating.
        end_line: Optional one-based end line.
        column: Optional one-based column.
        symbol: Optional qualified symbol.
        remediation: Optional remediation guidance.
        secondary_pillars: Additional pillars affected by the finding.
        metadata: Rule-specific JSON-compatible metadata.
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

    def stable_identity(self) -> str:
        """Compute the line-insensitive 16-char identity for external diff tooling.

        Pairs with :meth:`fingerprint` per ADR-020: ``fingerprint`` stays the
        line-precise identity used by baselines and SARIF; ``stable_identity``
        is line-insensitive so consumers can match "the same logical finding"
        across unrelated line shifts. Uses ``[ruleId, file, symbol]`` when
        ``symbol`` is set, ``[ruleId, file, message]`` otherwise.

        Returns:
            str: Lowercase hex string, 16 characters of a SHA-256 prefix.
        """
        return stable_identity_for(
            rule_id=self.rule_id,
            file_path=self.file_path,
            symbol=self.symbol,
            message=self.message,
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
            "stableIdentity": self.stable_identity(),
            "metadata": dict(self.metadata),
        }
