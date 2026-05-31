"""``security.dependency-unpinned-version`` - dependency version is floating."""

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
    unpinned_constraint_kind,
)
from gruffpy.rule.security._security_metadata import finding_security_metadata


class DependencyUnpinnedVersionRule(SourceTextRule):
    """Flag package dependencies without exact non-wildcard version pins."""

    ID = "security.dependency-unpinned-version"

    def definition(self) -> RuleDefinition:
        """Describe the unpinned dependency rule.

        Returns:
            Definition for the dependency-unpinned-version rule under the security pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Dependency version is not exactly pinned",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag named dependencies that use missing, wildcard, or range constraints.

        Args:
            unit: Source or metadata file whose raw text is scanned.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per floating version declaration.
        """
        definition = self.definition()
        findings: list[Finding] = []
        for declaration in dependency_declarations(unit):
            constraint_kind = unpinned_constraint_kind(declaration)
            if constraint_kind is None:
                continue
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        f"{dependency_label(declaration).capitalize()} is not pinned "
                        "to an exact version. Floating constraints let future installs "
                        "resolve to code the reviewer did not inspect."
                    ),
                    file_path=unit.file.display_path,
                    line=declaration.line,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    remediation=(
                        "Pin dependencies with `==` or `===` to a concrete non-wildcard "
                        "version, then rely on the lockfile/update workflow to move them "
                        "deliberately."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={
                        **dependency_metadata(
                            declaration,
                            constraint_kind=constraint_kind,
                        ),
                        **finding_security_metadata(
                            definition.id,
                            source_label=declaration.source_label,
                            sink_label="version-resolution",
                        ),
                    },
                )
            )
        return findings
