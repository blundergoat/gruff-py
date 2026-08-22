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
    fixed_preview,
    iter_matches,
)

_PATTERN = compile_pattern(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
_PEM_BLOCK_RE = re.compile(
    r"-----BEGIN[^-]*PRIVATE KEY-----.*?-----END[^-]*PRIVATE KEY-----",
    re.DOTALL,
)
_PEM_ARMOR_RE = re.compile(r"-----[^-]*-----")
_MIN_REAL_KEY_BODY_LEN = 100


class PrivateKeyRule(SourceTextRule):
    """Detect PEM private-key headers across common key formats.

    Users see the committed header's source line and rotation guidance for RSA, EC, DSA, ED25519,
    and OpenSSH keys, while the finding preview contains no key-derived text.
    """

    ID = "sensitive-data.private-key"

    def definition(self) -> RuleDefinition:
        """Describe the private-key rule as a high-confidence ERROR.

        A PEM header gives users a high-confidence signal, and error severity reflects the need to
        remove and rotate a committed private key.

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

        Users see common key headers without full PEM validation, while short placeholder bodies
        remain quiet.

        Args:
            unit: Source file whose raw text is scanned.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per PEM header occurrence.
        """
        definition = self.definition()
        findings: list[Finding] = []
        # Every PEM header is reviewed independently so users can rotate each committed key.
        for key_header_match in iter_matches(_PATTERN, unit.source):
            # Short placeholder bodies remain useful examples and do not require user remediation.
            if _is_placeholder_pem_block(unit.source, key_header_match.start_offset):
                continue
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message="Private-key PEM header in source.",
                    file_path=unit.file.display_path,
                    line=key_header_match.line,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    remediation=(
                        "Move the private key out of the repository. Rotate the key, "
                        "store the new one in a secret manager, and reference it at runtime."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={"preview": fixed_preview()},
                ),
            )
        return findings


def _is_placeholder_pem_block(source: str, header_offset: int) -> bool:
    """Return whether a full PEM block has only a short placeholder body."""
    # Only the block containing this header can determine whether the user's key is a placeholder.
    for block_match in _PEM_BLOCK_RE.finditer(source):
        # Other PEM blocks in the same file must not suppress this reported header.
        if not (block_match.start() <= header_offset < block_match.end()):
            continue
        body = _PEM_ARMOR_RE.sub("", block_match.group(0))
        body = re.sub(r"[^A-Za-z0-9+/=]", "", body)
        return len(body) < _MIN_REAL_KEY_BODY_LEN
    return False
