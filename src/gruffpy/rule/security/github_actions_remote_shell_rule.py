"""``security.github-actions-remote-shell`` - workflow pipes a remote download into a shell.

Fires on GitHub Actions workflow files whose ``run:`` scripts pipe a network
download straight into a shell interpreter (``curl ... | bash``, ``wget ... |
sh``). The fetched script is unverified and can change between runs, so a
reviewer cannot vouch for what executes on the runner.
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

_REMOTE_SHELL_RE = re.compile(
    r"(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh|dash|ksh|ash)\b",
    re.MULTILINE,
)


class GithubActionsRemoteShellRule(SourceTextRule):
    """Flag workflow `run:` steps that pipe a remote download into a shell."""

    ID = "security.github-actions-remote-shell"

    def definition(self) -> RuleDefinition:
        """Describe the remote-shell rule as a high-confidence posture warning.

        High confidence because the ``download | shell`` pipeline is matched
        textually; warning severity because piping installers to a shell is a
        common-but-risky idiom rather than a guaranteed exploit.

        Returns:
            Definition for the github-actions-remote-shell rule under the
            security pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Remote script piped into a shell in CI",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag each ``curl``/``wget`` download piped into a shell in a workflow.

        Args:
            unit: Source file whose raw text is scanned.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per remote-download-to-shell pipeline.
        """
        if not is_workflow_file(unit.file.display_path):
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for match in _REMOTE_SHELL_RE.finditer(unit.source):
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        "CI step pipes a remote download into a shell - the fetched "
                        "script is unverified and can change between runs."
                    ),
                    file_path=unit.file.display_path,
                    line=source_line(unit.source, match.start()),
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    remediation=(
                        "Download to a file, verify a pinned checksum or signature, then "
                        "execute it; or install from a pinned package with integrity checks."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata=finding_security_metadata(
                        definition.id,
                        source_label="remote-download",
                        sink_label="shell",
                    ),
                ),
            )
        return findings
