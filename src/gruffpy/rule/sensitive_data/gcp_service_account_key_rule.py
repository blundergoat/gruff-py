"""``sensitive-data.gcp-service-account-key`` - GCP service-account key JSON.

Detects the Google-issued service-account JSON shape: ``"type":
"service_account"`` co-occurring with a ``private_key`` value or PEM private-key
body. The finding is anchored at the service-account marker so it is stable and
distinct from generic PEM-header evidence.
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
        """Describe the GCP-service-account-key rule as a high-confidence ERROR.

        Returns:
            Definition for the GCP-service-account-key rule under the sensitive-data pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="GCP service-account key",
            pillar=Pillar.SENSITIVE_DATA,
            tier=RuleTier.V01,
            default_severity=Severity.ERROR,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Scan raw source for service-account JSON carrying private-key material.

        Args:
            unit: Source file whose raw text is scanned.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per service-account type marker when key material is present.
        """
        # Files without the service-account marker cannot represent this user-facing credential
        # type.
        if "service_account" not in unit.source:
            return []

        private_key_material = _private_key_value(unit.source) or _pem_block(unit.source)
        # Missing or placeholder key material keeps examples out of the user's security findings.
        if private_key_material is None or _looks_like_placeholder_key(
            private_key_material, unit.source
        ):
            return []

        definition = self.definition()
        # Every service-account marker gets its own source location when one file embeds multiple
        # keys.
        return [
            Finding(
                rule_id=definition.id,
                message="GCP service-account key JSON embeds private-key material.",
                file_path=unit.file.display_path,
                line=match.line,
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
                    "preview": fixed_preview(),
                    "provider": "gcp",
                    "category": "service-account-key",
                },
            )
            for match in iter_matches(_TYPE_PATTERN, unit.source)
        ]


def _private_key_value(source: str) -> str | None:
    """Return private-key material used only to classify a service-account finding."""
    match = _PRIVATE_KEY_FIELD_RE.search(source)
    # A JSON private_key field is the clearest evidence users need to review.
    if match is not None:
        return match.group(1)
    pem_match = _PEM_BLOCK_RE.search(source)
    return None if pem_match is None else pem_match.group(0)


def _looks_like_placeholder_key(private_key_value: str | None, source: str) -> bool:
    """Return whether the candidate is too short to represent a real user credential."""
    key_text = private_key_value or _pem_block(source)
    # No key text means there is no placeholder body to suppress at this helper boundary.
    if key_text is None:
        return False
    body = _PEM_ARMOR_RE.sub("", key_text)
    body = re.sub(r"[^A-Za-z0-9+/=]", "", body)
    return len(body) < _MIN_REAL_KEY_BODY_LEN


def _pem_block(source: str) -> str | None:
    """Return a PEM block when JSON-shaped input carries the key outside a field match."""
    match = _PEM_BLOCK_RE.search(source)
    return None if match is None else match.group(0)
