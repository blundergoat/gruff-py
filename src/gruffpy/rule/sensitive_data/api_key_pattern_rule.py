"""``sensitive-data.api-key-pattern`` — vendor API key shapes.

Recognises Stripe (``sk_live_*``/``rk_live_*``), GitHub (``ghp_*``/``gho_*``/
``ghu_*``/``ghs_*``/``ghr_*``), Slack (``xoxb-*``/``xoxp-*``/``xoxa-*``/
``xoxs-*``), OpenAI (``sk-...``), Square (``EAAA*``), and Twilio (``SK*``).
Vocabulary is configurable via the rule's ``vendor_patterns`` option, where
the default is the curated map below.
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

# Per-vendor patterns. The combined regex below alternates them so a single
# pass over the source captures all vendors at once.
_VENDOR_PATTERNS: dict[str, str] = {
    "stripe": r"(?:sk|rk)_live_[A-Za-z0-9]{24,}",
    "github": r"gh[opusr]_[A-Za-z0-9]{36}",
    "slack": r"xox[abporspu]-[A-Za-z0-9-]{10,}",
    "openai": r"sk-[A-Za-z0-9]{32,}",
    "square": r"EAAA[A-Za-z0-9_-]{40,}",
    "twilio": r"SK[a-f0-9]{32}",
}

_PATTERN = compile_pattern("|".join(f"(?P<{name}>{pat})" for name, pat in _VENDOR_PATTERNS.items()))


class ApiKeyPatternRule(SourceTextRule):
    ID = "sensitive-data.api-key-pattern"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="API key pattern",
            pillar=Pillar.SENSITIVE_DATA,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        definition = self.definition()
        findings: list[Finding] = []
        for match in iter_matches(_PATTERN, unit.source):
            vendor = _identify_vendor(match.raw)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=f"{vendor.capitalize()}-shaped API key literal in source.",
                    file_path=unit.file.display_path,
                    line=match.line,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    remediation=(
                        "Rotate the key and load credentials from a secret manager "
                        "or environment variable at runtime."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={"preview": redact_preview(match.raw), "vendor": vendor},
                ),
            )
        return findings


def _identify_vendor(token: str) -> str:
    for name, pattern in _VENDOR_PATTERNS.items():
        if compile_pattern(f"^{pattern}$").match(token):
            return name
    return "unknown"
