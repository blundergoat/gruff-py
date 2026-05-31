"""``docs.todo-density`` - too many TODO/FIXME/HACK/XXX/BUG markers per 1000 lines.

Operates on file content (comments and string literals), not the AST. Density is
``markers / max(1, line_count) * 1000`` and compared against the configured
threshold. Default threshold: 10 markers per 1000 lines at error severity.
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
from gruffpy.rule.rule import Rule

_MARKER_PATTERN = re.compile(r"\b(TODO|FIXME|HACK|XXX|BUG)\b")
_RULE_DEFINITION_FILE_SUFFIXES = (
    "gruffpy/rule/docs/todo_density_rule.py",
    "gruffpy/rule/waste/commented_out_code_rule.py",
)


class TodoDensityRule(Rule):
    """Detect files whose TODO-style marker density exceeds configured limits."""

    ID = "docs.todo-density"

    def definition(self) -> RuleDefinition:
        """Return the rule metadata used by the registry and reporters.

        Returns:
            Definition for the TODO density rule.
        """
        return RuleDefinition(
            id=self.ID,
            name="TODO density",
            pillar=Pillar.DOCUMENTATION,
            tier=RuleTier.V01,
            default_severity=Severity.ERROR,
            confidence=Confidence.MEDIUM,
            default_threshold=10,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Analyze source text for excessive TODO-style markers.

        Args:
            unit: Source unit whose raw text should be scanned.
            context: Rule execution context with threshold settings.

        Returns:
            A density finding when marker count exceeds the configured threshold.
        """
        if not unit.source:
            return []
        if _is_rule_definition_file(unit.file.display_path):
            return []
        definition = self.definition()
        settings = context.settings_for(definition)
        matches = _MARKER_PATTERN.findall(unit.source)
        marker_count = len(matches)
        if marker_count == 0:
            return []
        line_count = max(1, unit.line_count())
        density = marker_count * 1000 / line_count
        threshold_match = settings.high_value_threshold_match(density)
        if threshold_match is None:
            return []

        return [
            Finding(
                rule_id=definition.id,
                message=(
                    f"File has {marker_count} TODO/FIXME-style markers "
                    f"({density:.1f} per 1000 lines), above the threshold of "
                    f"{threshold_match.threshold}."
                ),
                file_path=unit.file.display_path,
                line=1,
                severity=threshold_match.severity,
                pillar=definition.pillar,
                tier=definition.tier,
                confidence=definition.confidence,
                end_line=line_count,
                remediation=(
                    "Triage outstanding TODOs into tracked issues, or fix and remove them inline."
                ),
                secondary_pillars=definition.secondary_pillars,
                metadata={
                    "markers": marker_count,
                    "lines": line_count,
                    "densityPer1000": round(density, 2),
                    "measuredValue": round(density, 2),
                    "threshold": threshold_match.threshold,
                    "thresholdDirection": "above",
                    "thresholdType": threshold_match.severity.value,
                },
            ),
        ]


def _is_rule_definition_file(display_path: str) -> bool:
    normalized = display_path.replace("\\", "/").removeprefix("./")
    return any(normalized.endswith(suffix) for suffix in _RULE_DEFINITION_FILE_SUFFIXES)
