"""Detect vendor API key shapes for ``sensitive-data.api-key-pattern``.

Users see one finding when a scan finds a key shaped like Stripe, GitHub, GitLab, npm, Slack,
OpenAI, Anthropic, Google, Square, or Twilio credentials. The private vendor map favors precise
hosted-service patterns, and every finding uses a fixed marker instead of key-derived preview text.
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
    category_preview,
    compile_pattern,
    is_likely_placeholder_secret,
    iter_matches,
)

# Per-vendor patterns. The combined regex below alternates them so a single
# pass over the source captures all vendors at once.
_VENDOR_PATTERNS: dict[str, str] = {
    "stripe": r"(?:sk|rk)_live_[A-Za-z0-9]{24,}",
    "github": r"(?:gh[opusr]_[A-Za-z0-9_]{36}|github_pat_[A-Za-z0-9_]{22,})",
    "gitlab": r"glpat-[A-Za-z0-9_-]{20,}",
    "slack": r"xox[abporspu]-[A-Za-z0-9-]{10,}",
    "slack_webhook": r"https://hooks\.slack\.com/services/[A-Z0-9]{8,}/[A-Z0-9]{8,}/[A-Za-z0-9]{20,}",
    "openai": r"(?:sk-[A-Za-z0-9]{32,}|sk-proj-[A-Za-z0-9_-]{20,})",
    "anthropic": r"sk-ant-[A-Za-z0-9_-]{20,}",
    "npm": r"npm_[A-Za-z0-9]{20,}",
    "google": r"AIza[A-Za-z0-9_-]{35}",
    "square": r"EAAA[A-Za-z0-9_-]{40,}",
    "twilio": r"SK[a-f0-9]{32}",
}

_PATTERN = compile_pattern("|".join(f"(?P<{name}>{pat})" for name, pat in _VENDOR_PATTERNS.items()))

# Which vendors map onto a category FAMILY-CONTRACT.md section 5 ratifies. A vendor with no ratified
# category (openai, square, twilio) keeps the bare marker rather than inventing one the family cannot read.
_MARKER_CATEGORIES: dict[str, str] = {
    "stripe": "stripe-live-key",
    "github": "github-token",
    "gitlab": "gitlab-token",
    "slack": "slack-token",
    "anthropic": "anthropic-api-key",
    "npm": "npm-token",
    "google": "google-api-key",
}


class ApiKeyPatternRule(SourceTextRule):
    """Detect API key literals from common hosted-service providers.

    Users encounter this rule during source scans and can use the vendor label to find the right
    rotation workflow without exposing any part of the credential in output.
    """

    ID = "sensitive-data.api-key-pattern"

    def definition(self) -> RuleDefinition:
        """Describe the API-key-pattern rule as a high-confidence warning.

        Precise vendor shapes give users high-confidence findings; warning severity leaves
        rotation priority to the review workflow.

        Returns:
            Definition for the API-key-pattern rule under the sensitive-data
            pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="API key pattern",
            pillar=Pillar.SENSITIVE_DATA,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Scan the raw source text for vendor-specific API key shapes.

        Users receive a vendor and source line for each non-placeholder match, including keys in
        strings, comments, and docs; the preview remains a fixed marker.

        Args:
            unit: Source file whose raw text is scanned.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per detected vendor key, with a redacted preview.
        """
        definition = self.definition()
        findings: list[Finding] = []
        # Each provider-shaped token becomes an independently actionable item in the user's report.
        for api_key_match in iter_matches(_PATTERN, unit.source):
            # Documentation placeholders stay silent so examples do not clutter real secret review.
            if is_likely_placeholder_secret(api_key_match.raw):
                continue
            vendor = _identify_vendor(api_key_match.raw)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=f"{_display_vendor(vendor)}-shaped API key literal in source.",
                    file_path=unit.file.display_path,
                    line=api_key_match.line,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    remediation=("Rotate the key and load credentials from a secret manager or environment variable at runtime."),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={"preview": category_preview(_MARKER_CATEGORIES.get(vendor)), "vendor": vendor},
                ),
            )
        return findings


def _identify_vendor(api_key: str) -> str:
    """Return the provider label users see for a matched API key shape."""
    # Provider order follows the pattern map so the report label stays deterministic.
    for vendor_name, vendor_pattern in _VENDOR_PATTERNS.items():
        # A full-pattern match prevents a key fragment from being assigned to the wrong provider.
        if compile_pattern(f"^{vendor_pattern}$").match(api_key):
            return "slack" if vendor_name == "slack_webhook" else vendor_name
    return "unknown"


def contains_provider_api_key(text: str) -> bool:
    """Return whether *text* contains one of the provider API-key shapes.

    Args:
        text: Candidate raw source fragment or entropy candidate to inspect.

    Returns:
        True when the fragment includes a known provider API-key pattern.
    """
    return _PATTERN.search(text) is not None


def _display_vendor(vendor: str) -> str:
    """Return the provider spelling used in the finding message shown to users."""
    return {
        "github": "GitHub",
        "gitlab": "GitLab",
        "npm": "npm",
        "openai": "OpenAI",
        "gcp": "GCP",
    }.get(vendor, vendor.capitalize())
