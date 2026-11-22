"""Check for Google Cloud service-account JSON with private-key material.

The scan looks for the account type marker together with a quoted key field or PEM block.
The finding points to the marker and uses a redacted preview so reviewers can locate it safely.
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

_TYPE_PATTERN = compile_pattern(r'"type"\s*:\s*"service_account"')
_PRIVATE_KEY_FIELD_RE = re.compile(r'"private_key"\s*:\s*"((?:\\.|[^"\\])*)"')
_PEM_BLOCK_RE = re.compile(
    r"-----BEGIN[^-]*PRIVATE KEY-----.*?-----END[^-]*PRIVATE KEY-----",
    re.DOTALL,
)
_PEM_ARMOR_RE = re.compile(r"-----[^-]*-----")
_MIN_REAL_KEY_BODY_LEN = 100


class GcpServiceAccountKeyRule(SourceTextRule):
    """Detect committed Google Cloud service-account key JSON.

    Users see the service-account marker's line when a scan finds real private-key material, while
    the report withholds every key-derived character and directs them to rotate the credential.
    """

    ID = "sensitive-data.gcp-service-account-key"

    def definition(self) -> RuleDefinition:
        """Describe the GCP-service-account-key rule as a high-confidence warning.

        Returns:
            Definition for the GCP-service-account-key rule under the sensitive-data pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="GCP service-account key",
            pillar=Pillar.SENSITIVE_DATA,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Report service-account JSON when the selected private-key field contains more than a placeholder.
        The report points to the type marker without revealing the key material.

        Args:
            unit: Source file whose raw text is scanned.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per matched type marker. Empty when no marker matches or the selected key text is missing or looks like a placeholder.
        """
        # The account type distinguishes these results from generic private-key findings.
        if "service_account" not in unit.source:
            return []

        private_key_material = _private_key_value(unit.source) or _pem_block(unit.source)
        # Missing or placeholder key material keeps examples out of the user's security findings.
        if private_key_material is None or _looks_like_placeholder_key(private_key_material, unit.source):
            return []

        definition = self.definition()
        # Use the type marker as the review location so the report never needs to show the private-key body.
        return [
            Finding(
                rule_id=definition.id,
                message="GCP service-account key JSON embeds private-key material.",
                file_path=unit.file.display_path,
                line=match.line,
                column=match.column,
                severity=definition.default_severity,
                pillar=definition.pillar,
                tier=definition.tier,
                confidence=definition.confidence,
                remediation=(
                    "Remove the service-account key from source, rotate it in Google Cloud IAM, "
                    "and load credentials from a secret manager or Workload Identity instead."
                ),
                secondary_pillars=definition.secondary_pillars,
                metadata={
                    "preview": category_preview("gcp-service-account"),
                    "provider": "gcp",
                    "category": "service-account-key",
                },
            )
            for match in iter_matches(_TYPE_PATTERN, unit.source)
        ]


def _private_key_value(source: str) -> str | None:
    """Return private-key material used only to classify a service-account finding.

    Args:
        source: Raw scanned text where the first quoted private-key field takes priority over PEM-shaped text.

    Returns:
        Captured field contents with escapes left as written, including an empty string for an empty field. Without a field, the first span from a
        private-key opening marker through a later closing marker, whose label may differ. None if neither form is found.
    """
    match = _PRIVATE_KEY_FIELD_RE.search(source)
    # A nonempty quoted field keeps other PEM text out of classification. An empty field lets the caller try PEM text separately.
    if match is not None:
        return match.group(1)
    pem_match = _PEM_BLOCK_RE.search(source)
    return None if pem_match is None else pem_match.group(0)


def _looks_like_placeholder_key(private_key_value: str | None, source: str) -> bool:
    """Identify short key bodies that the service-account detector treats as placeholders.

    Args:
        private_key_value: Extracted key text; None or an empty string falls back to a PEM block in source.
        source: Raw scanned text searched for a PEM block when the extracted value is absent or empty.

    Returns:
        True when key text is available and fewer than 100 base64-alphabet or padding characters remain after armor and other characters are removed.
        False when no key text is available or the remaining length reaches 100.
    """
    key_text = private_key_value or _pem_block(source)
    # No key text means there is no placeholder body to suppress at this helper boundary.
    if key_text is None:
        return False
    body = _PEM_ARMOR_RE.sub("", key_text)
    body = re.sub(r"[^A-Za-z0-9+/=]", "", body)
    return len(body) < _MIN_REAL_KEY_BODY_LEN


def _pem_block(source: str) -> str | None:
    """Extract the first span delimited by private-key PEM markers.

    Args:
        source: Raw scanned text searched for a private-key opening marker and a later closing marker.

    Returns:
        The first span including both markers, or None when no opening marker has a later closing marker. The marker labels may differ.
    """
    match = _PEM_BLOCK_RE.search(source)
    return None if match is None else match.group(0)
