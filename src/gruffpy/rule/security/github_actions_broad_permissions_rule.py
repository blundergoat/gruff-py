"""``security.github-actions-broad-permissions`` - workflow grants the token write-all.

Fires when a GitHub Actions workflow sets ``permissions: write-all``, granting
the automatic ``GITHUB_TOKEN`` write access to every scope. A compromised step
or action then inherits full repository write power; least-privilege scoping
limits the blast radius.
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

_WRITE_ALL_RE = re.compile(r"^\s*permissions:\s*write-all\b", re.MULTILINE)


class GithubActionsBroadPermissionsRule(SourceTextRule):
    """Flag workflows that grant the `GITHUB_TOKEN` `write-all` permissions."""

    ID = "security.github-actions-broad-permissions"

    def definition(self) -> RuleDefinition:
        """Describe the broad-permissions rule as a high-confidence posture warning.

        Returns:
            Definition for the github-actions-broad-permissions rule under the
            security pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Broad GitHub Actions token permissions",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag each ``permissions: write-all`` grant in a workflow file.

        Args:
            unit: Source file whose raw text is scanned.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per ``write-all`` permissions grant.
        """
        if not is_workflow_file(unit.file.display_path):
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for match in _WRITE_ALL_RE.finditer(unit.source):
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        "Workflow grants `write-all` token permissions - any compromised step "
                        "then inherits full repository write access via the GITHUB_TOKEN."
                    ),
                    file_path=unit.file.display_path,
                    line=source_line(unit.source, match.start()),
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    remediation=(
                        "Replace `write-all` with an explicit least-privilege "
                        "`permissions:` block (e.g. `contents: read`), adding only "
                        "the scopes each job needs."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata=finding_security_metadata(definition.id),
                ),
            )
        return findings
