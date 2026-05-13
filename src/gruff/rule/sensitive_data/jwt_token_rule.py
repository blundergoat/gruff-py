"""``sensitive-data.jwt-token`` — JWT literal in source.

Pattern: three base64url segments joined by ``.``. The header almost always
starts ``eyJ`` (the base64 of ``{"``). False positives are possible on
non-token base64 triplets, but the ``eyJ`` prefix limits them sharply.
"""

from gruff.finding.confidence import Confidence
from gruff.finding.finding import Finding
from gruff.finding.pillar import Pillar
from gruff.finding.rule_tier import RuleTier
from gruff.finding.severity import Severity
from gruff.parser.analysis_unit import AnalysisUnit
from gruff.rule.context import RuleContext
from gruff.rule.definition import RuleDefinition
from gruff.rule.rule import SourceTextRule
from gruff.rule.sensitive_data._secret_scanner_helper import (
    compile_pattern,
    iter_matches,
    redact_preview,
)

_PATTERN = compile_pattern(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")


class JwtTokenRule(SourceTextRule):
    ID = "sensitive-data.jwt-token"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="JWT token",
            pillar=Pillar.SENSITIVE_DATA,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
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
