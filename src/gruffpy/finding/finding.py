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
        baseline_identity: The ratified durable identity this run computed, or ``None`` when the finding is
            sensitive, or when a direct API caller built it outside the analysis pipeline. Never serialized.
        baseline_subject: The subject that identity hashed, such as ``process#2``; ``None`` whenever
            ``baseline_identity`` is. Never serialized.
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
    baseline_identity: str | None = None
    baseline_subject: str | None = None

    def fingerprint(self) -> str:
        """Compute the line-precise 16-character identifier serialized with finding reports.

        Uses the same JSON escaping and hash prefix as gruff-php for matching payload fields.

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
        """Compute the identity that external diff tools use to match findings across line shifts.

        ADR-020 keeps fingerprint line-precise for baselines and SARIF.
        The hash uses [ruleId, file, symbol] for any string symbol, including an empty one, or [ruleId, file, message] when symbol is None.

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
        """Serialize the native finding dictionary used by internal report paths.

        Preserve nullable model fields and copy metadata; compute both identities when serializing.
        The v3 machine adapter handles path normalization, optional-field omission and locationPrecision.

        Returns:
            JSON-ready native finding fields plus computed identities.
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
