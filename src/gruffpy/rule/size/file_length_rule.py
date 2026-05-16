"""``size.file-length`` — very large files slow navigation and review."""

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule


class FileLengthRule(Rule):
    ID = "size.file-length"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="File length",
            pillar=Pillar.SIZE,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
            default_thresholds={"warning": 400, "error": 800},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        definition = self.definition()
        settings = context.settings_for(definition)
        warning_threshold = settings.numeric_threshold("warning")
        error_threshold = settings.numeric_threshold("error")
        line_count = unit.line_count()

        if line_count <= warning_threshold:
            return []

        if line_count > error_threshold:
            severity = Severity.ERROR
            threshold: int | float = error_threshold
        else:
            severity = Severity.WARNING
            threshold = warning_threshold

        return [
            Finding(
                rule_id=definition.id,
                message=(
                    f"File has {line_count} lines, "
                    f"above the {severity.value} threshold of {_format_number(threshold)}."
                ),
                file_path=unit.file.display_path,
                line=1,
                severity=severity,
                pillar=definition.pillar,
                tier=definition.tier,
                confidence=definition.confidence,
                end_line=line_count,
                remediation=("Split oversized files or move responsibilities into smaller units."),
                secondary_pillars=definition.secondary_pillars,
                metadata={
                    "lines": line_count,
                    "measuredValue": line_count,
                    "threshold": threshold,
                    "thresholdDirection": "above",
                    "thresholdType": severity.value,
                },
            ),
        ]


def _format_number(value: int | float) -> str:
    if isinstance(value, float) and not value.is_integer():
        return str(value)
    return str(int(value))
