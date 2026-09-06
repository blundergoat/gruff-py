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
    connection_string_preview,
    is_likely_placeholder_secret,
    iter_matches,
)

_PATTERN = compile_pattern(
    r"\bhttps?://(?P<user>[^:\s/@]+):(?P<password>[^@\s\"']+)@(?P<host>[^\s\"']+)",
    ignore_case=True,
)


class UrlCredentialsRule(SourceTextRule):
    """Detect HTTP(S) URLs that embed username and password credentials.

    Users see a finding after placing ``user:password@host`` in source and can move authentication
    to headers or runtime settings without the URL or password appearing in the preview.
    """

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
            One finding per credential-bearing HTTP(S) URL with a fixed preview marker.
        """
        definition = self.definition()
        findings: list[Finding] = []
        # Each credential-bearing URL remains independently actionable in the user's report.
        for credential_match in iter_matches(_PATTERN, unit.source):
            embedded_password = _extract_password(credential_match.raw)
            # Unparseable or placeholder passwords do not represent a credential the user must
            # rotate.
            if embedded_password is None or is_likely_placeholder_secret(embedded_password):
                continue
            # This rule's pattern matches only http and https, and the matched text starts with whichever it was.
            redacted_marker = connection_string_preview(credential_match.raw.split("://", 1)[0])
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=f"HTTP(S) URL embeds an inline credential: {redacted_marker}.",
                    file_path=unit.file.display_path,
                    line=credential_match.line,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    remediation=("Remove inline URL credentials; pass authentication via headers, environment variables, or a secret store instead."),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={"preview": redacted_marker, "category": "url-credentials"},
                ),
            )
        return findings


def _extract_password(url: str) -> str | None:
    """Return the password segment from an HTTP(S) URL userinfo block."""
    before_host = url.split("@", 1)[0]
    userinfo = before_host.split("://", 1)[-1]
    credential_parts = userinfo.split(":", 1)
    # Without a password separator, the user has not embedded a credential in this URL.
    if len(credential_parts) != 2:
        return None
    return credential_parts[1]
