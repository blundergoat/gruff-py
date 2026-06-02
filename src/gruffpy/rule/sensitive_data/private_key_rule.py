"""``sensitive-data.private-key`` - PEM-formatted private key header in source.

Detects ``-----BEGIN <ANY> PRIVATE KEY-----`` for RSA, EC, DSA, ED25519, and
OpenSSH formats. The header alone is sufficient signal - the rest of the PEM
body doesn't need to validate to confirm the leak.
"""

import re

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
_PEM_BLOCK_RE = re.compile(
    r"-----BEGIN[^-]*PRIVATE KEY-----.*?-----END[^-]*PRIVATE KEY-----",
    re.DOTALL,
)
_PEM_ARMOR_RE = re.compile(r"-----[^-]*-----")
_MIN_REAL_KEY_BODY_LEN = 100


class PrivateKeyRule(SourceTextRule):
    """Detect ``-----BEGIN <ANY> PRIVATE KEY-----`` PEM headers across RSA, EC, ED25519, etc."""

    ID = "sensitive-data.private-key"

    def definition(self) -> RuleDefinition:
        """Describe the private-key rule as a high-confidence ERROR.

        ERROR severity because the PEM header itself is the canonical
        signal of a committed private key; the body's validity isn't
        load-bearing.

        Returns:
            Definition for the private-key rule under the sensitive-data
            pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Private key",
            pillar=Pillar.SENSITIVE_DATA,
            tier=RuleTier.V01,
            default_severity=Severity.ERROR,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag any ``-----BEGIN <ANY> PRIVATE KEY-----`` PEM header in source.

        Covers RSA, EC, DSA, ED25519, and OpenSSH variants - the rule
        doesn't validate the rest of the PEM body because committed
        headers alone leak the intent and require rotation.

        Args:
            unit: Source file whose raw text is scanned.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per PEM header occurrence.
        """
        definition = self.definition()
        findings: list[Finding] = []
        for match in iter_matches(_PATTERN, unit.source):
            if _is_placeholder_pem_block(unit.source, match.start_offset):
                continue
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


def _is_placeholder_pem_block(source: str, header_offset: int) -> bool:
    """Return whether a full PEM block has only a short placeholder body."""
    for block_match in _PEM_BLOCK_RE.finditer(source):
        if not (block_match.start() <= header_offset < block_match.end()):
            continue
        body = _PEM_ARMOR_RE.sub("", block_match.group(0))
        body = re.sub(r"[^A-Za-z0-9+/=]", "", body)
        return len(body) < _MIN_REAL_KEY_BODY_LEN
    return False
