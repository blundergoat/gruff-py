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
        """Describe the file-length rule with a configurable line threshold (default 1000).

        Returns:
            Definition under the size pillar; thresholds are configurable via
            the ``warning``/``error`` keys.
        """
        return RuleDefinition(
            id=self.ID,
            name="File length",
            pillar=Pillar.SIZE,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
            default_thresholds={"warning": 1000, "error": 1000},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Emit one finding per file whose physical line count exceeds the configured threshold.

        Counts raw lines (no comment/blank-line stripping) so the metric
        matches what a human sees in their editor.

        Args:
            unit: Parsed source file whose line count is checked.
            context: Rule execution context that supplies the threshold.

        Returns:
            Empty list when under threshold; otherwise a single
            file-anchored finding spanning the whole file.
        """
        definition = self.definition()
        settings = context.settings_for(definition)
        line_count = unit.line_count()
        threshold_match = settings.high_value_threshold_match(line_count)
        if threshold_match is None:
            return []

        return [
            Finding(
                rule_id=definition.id,
                message=(
                    f"File has {line_count} lines, "
                    f"above the {threshold_match.severity.value} threshold of "
                    f"{_format_number(threshold_match.threshold)}."
                ),
                file_path=unit.file.display_path,
                line=1,
                severity=threshold_match.severity,
                pillar=definition.pillar,
                tier=definition.tier,
                confidence=definition.confidence,
                end_line=line_count,
                remediation=("Split oversized files or move responsibilities into smaller units."),
                secondary_pillars=definition.secondary_pillars,
                metadata={
                    "lines": line_count,
                    "measuredValue": line_count,
                    "threshold": threshold_match.threshold,
                    "thresholdDirection": "above",
                    "thresholdType": threshold_match.severity.value,
                },
            ),
        ]


def _format_number(value: int | float) -> str:
    if isinstance(value, float) and not value.is_integer():
        return str(value)
    return str(int(value))
