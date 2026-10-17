"""Warn when a developer scans source containing a private-key header.

The raw-text check includes incomplete keys and escaped strings so truncated material still receives a warning.
Only a complete block whose whole body is the word placeholder stays quiet; finding previews contain no key-derived text.
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
    category_preview,
    compile_pattern,
    iter_matches,
)

_PATTERN = compile_pattern(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
_PEM_BLOCK_RE = re.compile(
    r"-----BEGIN (?P<label>[A-Z0-9 ]*PRIVATE KEY)-----(?P<body>.*?)-----END (?P=label)-----",
    re.DOTALL,
)


class PrivateKeyRule(SourceTextRule):
    """Report private-key headers when a developer scans repository source.

    Use the raw-text stage so incomplete or escaped key material still raises a warning.
    Findings show the header's source line and rotation guidance, with a redacted preview.
    """

    ID = "sensitive-data.private-key"

    def definition(self) -> RuleDefinition:
        """Supply the warning metadata used when a scan finds a possible committed private key.

        Returns:
            Definition for a high-confidence warning in the sensitive-data pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Private key",
            pillar=Pillar.SENSITIVE_DATA,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Report each private-key header unless its complete block contains only the placeholder example word.

        Args:
            unit: Source file selected for the scan; empty source produces no findings.
            context: Scan context supplied by the rule runner; this check uses no configurable thresholds.

        Returns:
            Warnings for the remaining headers; an empty list means no reportable header was found.
        """
        definition = self.definition()
        findings: list[Finding] = []
        # Every PEM header is reviewed independently so users can rotate each committed key.
        for key_header_match in iter_matches(_PATTERN, unit.source):
            # The explicit example word names no credential; short opaque material still reports.
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
                    metadata={"preview": category_preview("private-key")},
                ),
            )
        return findings


def _is_placeholder_pem_block(source: str, header_offset: int) -> bool:
    """Recognise the explicit example body before the scan reports this header.

    A missing or incomplete block returns false, so unknown key material still receives a warning.
    """
    # Only a block beginning at this header can establish the user's complete placeholder example.
    for block_match in _PEM_BLOCK_RE.finditer(source):
        # An enclosing or unrelated block cannot explain away this header's warning.
        if block_match.start() != header_offset:
            continue
        return block_match.group("body").strip() == "placeholder"
    return False
