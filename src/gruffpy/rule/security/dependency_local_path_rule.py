"""``security.dependency-local-path`` - dependency installed from local filesystem path."""

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
    is_local_path_reference,
)
from gruffpy.rule.security._security_metadata import finding_security_metadata


class DependencyLocalPathRule(SourceTextRule):
    """Flag package dependencies installed from local filesystem paths."""

    ID = "security.dependency-local-path"

    def definition(self) -> RuleDefinition:
        """Describe the local-path dependency rule.

        Returns:
            Definition for the dependency-local-path rule under the security pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Dependency installed from local path",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag dependency declarations that resolve through local filesystem paths.

        Args:
            unit: Source or metadata file whose raw text is scanned.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per local-path dependency declaration.
        """
        definition = self.definition()
        findings: list[Finding] = []
        for declaration in dependency_declarations(unit):
            if not is_local_path_reference(declaration):
                continue
            reference_kind = "file-url" if "file:" in declaration.raw.lower() else "local-path"
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        f"{dependency_label(declaration).capitalize()} is installed from "
                        "a local path. Local references depend on checkout layout and can "
                        "hide code outside the reviewed package boundary."
                    ),
                    file_path=unit.file.display_path,
                    line=declaration.line,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    remediation=(
                        "Replace local path dependencies with a reviewed registry release "
                        "pinned to an exact version, or vendor the dependency inside the "
                        "reviewed source tree with an explicit ownership note."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={
                        **dependency_metadata(declaration, reference_kind=reference_kind),
                        **finding_security_metadata(
                            definition.id,
                            source_label=declaration.source_label,
                            sink_label="local-path-dependency",
                        ),
                    },
                )
            )
        return findings
