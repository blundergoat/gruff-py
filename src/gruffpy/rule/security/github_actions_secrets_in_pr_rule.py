"""``security.github-actions-secrets-in-pr`` - pull_request_target workflow references repo secrets.

Fires when a workflow whose ``on:`` key declares ``pull_request_target``
references a repository secret other than the automatic ``GITHUB_TOKEN``. That
trigger runs pull-request code with the repository's secrets, while a plain
``pull_request`` run from a fork receives none.
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
from gruffpy.rule.security._github_actions_helper import declared_workflow_events, is_workflow_file, source_line
from gruffpy.rule.security._security_metadata import finding_security_metadata

_SECRET_REF_RE = re.compile(r"\$\{\{\s*secrets\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")


class GithubActionsSecretsInPrRule(SourceTextRule):
    """Flag pull_request_target workflows that reference a non-default repository secret."""

    ID = "security.github-actions-secrets-in-pr"

    def definition(self) -> RuleDefinition:
        """Describe the secrets-in-pr rule as a medium-confidence warning.

        Medium confidence because exposure depends on how the secret is used;
        the gate (a pull_request_target trigger in ``on:`` plus a
        non-GITHUB_TOKEN secret reference) keeps the noise bounded.

        Returns:
            Definition for the github-actions-secrets-in-pr rule under the
            security pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Repository secret in a pull_request_target workflow",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag each non-``GITHUB_TOKEN`` secret reference in a pull_request_target workflow.

        Args:
            unit: Source file whose raw text is scanned.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per referenced secret, when ``on:`` declares pull_request_target.
        """
        if not is_workflow_file(unit.file.display_path):
            return []
        if "pull_request_target" not in declared_workflow_events(unit.source):
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
                        f"pull_request_target workflow references secret `{secret}` - "
                        "that trigger runs pull-request code with the repository's secrets."
                    ),
                    file_path=unit.file.display_path,
                    line=source_line(unit.source, match.start()),
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    remediation=(
                        "Move secret-using steps out of pull_request_target workflows, or run untrusted "
                        "pull-request code under pull_request, which receives no secrets from forks."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={
                        "secret": secret,
                        **finding_security_metadata(definition.id),
                    },
                ),
            )
        return findings
