"""``sensitive-data.private-key`` — PEM-formatted private key header in source.

Detects ``-----BEGIN <ANY> PRIVATE KEY-----`` for RSA, EC, DSA, ED25519, and
OpenSSH formats. The header alone is sufficient signal — the rest of the PEM
body doesn't need to validate to confirm the leak.
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

_PATTERN = compile_pattern(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")


class PrivateKeyRule(SourceTextRule):
    ID = "sensitive-data.private-key"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Private key",
            pillar=Pillar.SENSITIVE_DATA,
            tier=RuleTier.V01,
            default_severity=Severity.ERROR,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        definition = self.definition()
        findings: list[Finding] = []
        for match in iter_matches(_PATTERN, unit.source):
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message="Private-key PEM header in source.",
                    file_path=unit.file.display_path,
                    line=match.line,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    remediation=(
                        "Move the private key out of the repository. Rotate the key, "
                        "store the new one in a secret manager, and reference it at runtime."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={"preview": redact_preview(match.raw)},
                ),
            )
        return findings
