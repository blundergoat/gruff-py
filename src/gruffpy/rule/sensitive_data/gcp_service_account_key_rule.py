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
    iter_matches,
    redact_preview,
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
    """Detect committed Google Cloud service-account key JSON."""

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
        if "service_account" not in unit.source:
            return []

        private_key_value = _private_key_value(unit.source) or _pem_block(unit.source)
        if private_key_value is None or _looks_like_placeholder_key(private_key_value, unit.source):
            return []

        definition = self.definition()
        preview = redact_preview(private_key_value)
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
                    "preview": preview,
                    "provider": "gcp",
                    "category": "service-account-key",
                },
            )
            for match in iter_matches(_TYPE_PATTERN, unit.source)
        ]


def _private_key_value(source: str) -> str | None:
    match = _PRIVATE_KEY_FIELD_RE.search(source)
    if match is not None:
        return match.group(1)
    pem_match = _PEM_BLOCK_RE.search(source)
    return None if pem_match is None else pem_match.group(0)


def _looks_like_placeholder_key(private_key_value: str | None, source: str) -> bool:
    key_text = private_key_value or _pem_block(source)
    if key_text is None:
        return False
    body = _PEM_ARMOR_RE.sub("", key_text)
    body = re.sub(r"[^A-Za-z0-9+/=]", "", body)
    return len(body) < _MIN_REAL_KEY_BODY_LEN


def _pem_block(source: str) -> str | None:
    match = _PEM_BLOCK_RE.search(source)
    return None if match is None else match.group(0)
