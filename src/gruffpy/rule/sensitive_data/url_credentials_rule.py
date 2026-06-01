"""``sensitive-data.url-credentials`` - HTTP(S) URL with embedded credentials.

Detects ``http(s)://user:password@host`` URL literals. Database schemes remain
owned by ``sensitive-data.database-url-password`` so the two rules do not
duplicate the same finding.
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
    is_likely_placeholder_secret,
    iter_matches,
)

_PATTERN = compile_pattern(
    r"\bhttps?://(?P<user>[^:\s/@]+):(?P<password>[^@\s\"']+)@(?P<host>[^\s\"']+)",
    ignore_case=True,
)


class UrlCredentialsRule(SourceTextRule):
    """Detect HTTP(S) URLs that embed username/password credentials."""

    ID = "sensitive-data.url-credentials"

    def definition(self) -> RuleDefinition:
        """Describe the URL-credentials rule as a high-confidence ERROR.

        Returns:
            Definition for the URL-credentials rule under the sensitive-data pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="URL embedded credentials",
            pillar=Pillar.SENSITIVE_DATA,
            tier=RuleTier.V01,
            default_severity=Severity.ERROR,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Scan raw source for HTTP(S) URLs with inline ``user:password@`` credentials.

        Args:
            unit: Source file whose raw text is scanned.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per credential-bearing HTTP(S) URL with a redacted URL preview.
        """
        definition = self.definition()
        findings: list[Finding] = []
        for match in iter_matches(_PATTERN, unit.source):
            password = _extract_password(match.raw)
            if password is None or is_likely_placeholder_secret(password):
                continue
            preview = _redacted_url_preview(match.raw, password)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=f"HTTP(S) URL embeds an inline credential: {preview}.",
                    file_path=unit.file.display_path,
                    line=match.line,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    remediation=(
                        "Remove inline URL credentials; pass authentication via headers, "
                        "environment variables, or a secret store instead."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={"preview": preview, "category": "url-credentials"},
                ),
            )
        return findings


def _extract_password(url: str) -> str | None:
    """Return the password segment from an HTTP(S) URL userinfo block."""
    before_host = url.split("@", 1)[0]
    userinfo = before_host.split("://", 1)[-1]
    parts = userinfo.split(":", 1)
    if len(parts) != 2:
        return None
    return parts[1]


def _redacted_url_preview(url: str, password: str) -> str:
    """Return *url* with only the embedded password replaced by length."""
    return url.replace(f":{password}@", f":<redacted:{len(password)} chars>@", 1)
