"""``security.dependency-git-reference`` - dependency installed from Git/VCS."""

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import SourceTextRule
from gruffpy.rule.security._dependency_posture_helper import (
    dependency_declarations,
    dependency_label,
    dependency_metadata,
    is_git_reference,
)
from gruffpy.rule.security._security_metadata import finding_security_metadata


class DependencyGitReferenceRule(SourceTextRule):
    """Flag package dependencies installed from Git references."""

    ID = "security.dependency-git-reference"

    def definition(self) -> RuleDefinition:
        """Describe the Git dependency rule.

        Returns:
            Definition for the dependency-git-reference rule under the security pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Dependency installed from Git reference",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag dependency declarations that install from Git/VCS references.

        Args:
            unit: Source or metadata file whose raw text is scanned.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per Git dependency declaration.
        """
        definition = self.definition()
        findings: list[Finding] = []
        for declaration in dependency_declarations(unit):
            if not is_git_reference(declaration):
                continue
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        f"{dependency_label(declaration).capitalize()} is installed from "
                        "a Git reference. VCS dependencies bypass normal package release "
                        "review and are easy to move accidentally."
                    ),
                    file_path=unit.file.display_path,
                    line=declaration.line,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    remediation=(
                        "Use a released registry package pinned to an exact version. If a "
                        "Git source is unavoidable, pin an immutable reviewed commit and "
                        "record why a registry release cannot be used."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={
                        **dependency_metadata(declaration, reference_kind="vcs-git"),
                        **finding_security_metadata(
                            definition.id,
                            source_label=declaration.source_label,
                            sink_label="git-dependency",
                        ),
                    },
                )
            )
        return findings
