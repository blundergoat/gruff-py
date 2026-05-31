"""``security.dependency-url-reference`` - dependency installed from a direct URL."""

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
    is_url_reference,
)
from gruffpy.rule.security._security_metadata import finding_security_metadata


class DependencyUrlReferenceRule(SourceTextRule):
    """Flag package dependencies installed directly from HTTP(S) artifact URLs."""

    ID = "security.dependency-url-reference"

    def definition(self) -> RuleDefinition:
        """Describe the direct-URL dependency rule.

        Returns:
            Definition for the dependency-url-reference rule under the security pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Dependency installed from direct URL",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag dependency declarations that install artifacts from direct HTTP(S) URLs.

        Args:
            unit: Source or metadata file whose raw text is scanned.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per direct URL dependency declaration.
        """
        definition = self.definition()
        findings: list[Finding] = []
        for declaration in dependency_declarations(unit):
            if not is_url_reference(declaration):
                continue
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        f"{dependency_label(declaration).capitalize()} is installed from "
                        "a direct artifact URL. Registry packages with exact versions are "
                        "easier to review and reproduce."
                    ),
                    file_path=unit.file.display_path,
                    line=declaration.line,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    remediation=(
                        "Publish or consume a registry package pinned to an exact version; "
                        "if a URL is unavoidable, review and lock the artifact digest outside "
                        "the dependency declaration."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={
                        **dependency_metadata(declaration, reference_kind="direct-url"),
                        **finding_security_metadata(
                            definition.id,
                            source_label=declaration.source_label,
                            sink_label="direct-url-dependency",
                        ),
                    },
                )
            )
        return findings
