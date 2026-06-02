"""``security.github-actions-pull-request-target`` - risky pull_request_target + PR checkout.

Fires when a workflow triggered by ``pull_request_target`` also checks out the
pull request's head ref (``github.event.pull_request.head.sha`` / ``.ref``).
That combination runs untrusted fork code with a read/write token and the
repository's secrets in scope - a well-known privilege-escalation pattern.
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

_PRT_RE = re.compile(r"\bpull_request_target\b")
_PR_HEAD_CHECKOUT_RE = re.compile(r"github\.event\.pull_request\.head\.(?:sha|ref)\b")


class GithubActionsPullRequestTargetRule(SourceTextRule):
    """Flag `pull_request_target` workflows that check out the untrusted PR head."""

    ID = "security.github-actions-pull-request-target"

    def definition(self) -> RuleDefinition:
        """Describe the pull-request-target rule as a high-confidence error.

        Error severity because checking out the PR head under
        ``pull_request_target`` runs untrusted code with secrets and a write
        token - a critical, precise pattern, not a posture smell.

        Returns:
            Definition for the github-actions-pull-request-target rule under the
            security pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Risky pull_request_target workflow",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.ERROR,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag a workflow that pairs ``pull_request_target`` with a PR-head checkout.

        Reports once per workflow, at the ``pull_request_target`` trigger line,
        only when a PR-head ref checkout is also present.

        Args:
            unit: Source file whose raw text is scanned.
            context: Rule execution context (unused - no thresholds).

        Returns:
            A single finding when the dangerous combination is present, else none.
        """
        if not is_workflow_file(unit.file.display_path):
            return []
        trigger = _PRT_RE.search(unit.source)
        if trigger is None or _PR_HEAD_CHECKOUT_RE.search(unit.source) is None:
            return []
        definition = self.definition()
        return [
            Finding(
                rule_id=definition.id,
                message=(
                    "`pull_request_target` workflow checks out the PR head ref - it runs "
                    "untrusted fork code with a write token and repository secrets in scope."
                ),
                file_path=unit.file.display_path,
                line=source_line(unit.source, trigger.start()),
                severity=definition.default_severity,
                pillar=definition.pillar,
                tier=definition.tier,
                confidence=definition.confidence,
                remediation=(
                    "Use `pull_request` for untrusted PRs, or split into a privileged "
                    "workflow that never checks out PR code; never execute fork code under "
                    "`pull_request_target`."
                ),
                secondary_pillars=definition.secondary_pillars,
                metadata=finding_security_metadata(
                    definition.id,
                    source_label="pull-request-head",
                    sink_label="privileged-workflow",
                ),
            )
        ]
