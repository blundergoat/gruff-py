"""``security.github-actions-secrets-in-pr`` - PR-triggered workflow references repo secrets.

Fires when a workflow triggered by ``pull_request`` or ``pull_request_target``
references a repository secret other than the automatic ``GITHUB_TOKEN``. PR
workflows can expose secrets to untrusted fork contributions, so secret-using
jobs should stay out of PR-triggered workflows.
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
from gruffpy.rule.security._github_actions_helper import is_workflow_file, source_line
from gruffpy.rule.security._security_metadata import finding_security_metadata

_PR_TRIGGER_RE = re.compile(r"\bpull_request(?:_target)?\b")
_SECRET_REF_RE = re.compile(r"\$\{\{\s*secrets\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")


class GithubActionsSecretsInPrRule(SourceTextRule):
    """Flag PR-triggered workflows that reference a non-default repository secret."""

    ID = "security.github-actions-secrets-in-pr"

    def definition(self) -> RuleDefinition:
        """Describe the secrets-in-pr rule as a medium-confidence warning.

        Medium confidence because exposure depends on fork vs. same-repo PRs
        and on how the secret is used; the gate (PR trigger + non-GITHUB_TOKEN
        secret reference) keeps the noise bounded.

        Returns:
            Definition for the github-actions-secrets-in-pr rule under the
            security pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Repository secret in a PR-triggered workflow",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag each non-``GITHUB_TOKEN`` secret reference in a PR-triggered workflow.

        Args:
            unit: Source file whose raw text is scanned.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per referenced secret, when the workflow is PR-triggered.
        """
        if not is_workflow_file(unit.file.display_path):
            return []
        if _PR_TRIGGER_RE.search(unit.source) is None:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for match in _SECRET_REF_RE.finditer(unit.source):
            secret = match.group(1)
            if secret == "GITHUB_TOKEN":
                continue
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        f"PR-triggered workflow references secret `{secret}` - PR workflows "
                        "can expose secrets to untrusted fork contributions."
                    ),
                    file_path=unit.file.display_path,
                    line=source_line(unit.source, match.start()),
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    remediation=(
                        "Move secret-using steps out of PR-triggered workflows, or gate them "
                        "to same-repo branches; never expose secrets to fork pull requests."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={
                        "secret": secret,
                        **finding_security_metadata(definition.id),
                    },
                ),
            )
        return findings
