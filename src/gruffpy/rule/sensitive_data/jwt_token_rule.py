"""``sensitive-data.jwt-token`` — JWT literal in source.

Pattern: three base64url segments joined by ``.``. The header almost always
starts ``eyJ`` (the base64 of ``{"``). False positives are possible on
non-token base64 triplets, but the ``eyJ`` prefix limits them sharply.
"""

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import SourceTextRule
from gruffpy.rule.sensitive_data._secret_scanner_helper import (
    compile_pattern,
    iter_matches,
    redact_preview,
)

_PATTERN = compile_pattern(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")


class JwtTokenRule(SourceTextRule):
    """Detect ``eyJ<header>.<payload>.<signature>``-shaped JWT literals committed to source."""

    ID = "sensitive-data.jwt-token"

    def definition(self) -> RuleDefinition:
        """Describe the JWT-token rule as a high-confidence warning.

        The ``eyJ`` prefix corresponds to the base64 of the standard JWT
        header ``{"`` — false positives are rare even on large corpora.

        Returns:
            Definition for the JWT-token rule under the sensitive-data pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="JWT token",
            pillar=Pillar.SENSITIVE_DATA,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag ``eyJ<header>.<payload>.<signature>``-shaped literals in source.

        Args:
            unit: Source file whose raw text is scanned.
            context: Rule execution context (unused — no thresholds).

        Returns:
            One finding per JWT-shaped triplet, with a redacted preview.
        """
        definition = self.definition()
        findings: list[Finding] = []
        for match in iter_matches(_PATTERN, unit.source):
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message="JWT-shaped token literal in source.",
                    file_path=unit.file.display_path,
                    line=match.line,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    remediation=(
                        "Hard-coded JWTs are short-lived but often leak signing intent. "
                        "Rotate the signing key, then load tokens at runtime."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={"preview": redact_preview(match.raw)},
                ),
            )
        return findings
