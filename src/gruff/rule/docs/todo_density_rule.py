"""``docs.todo-density`` — too many TODO/FIXME/HACK/XXX/BUG markers per 1000 lines.

Operates on file content (comments and string literals), not the AST. Density is
``markers / max(1, line_count) * 1000`` and compared against the configured
threshold. Default threshold: 10 markers per 1000 lines.
"""

import re

from gruff.finding.confidence import Confidence
from gruff.finding.finding import Finding
from gruff.finding.pillar import Pillar
from gruff.finding.rule_tier import RuleTier
from gruff.finding.severity import Severity
from gruff.parser.analysis_unit import AnalysisUnit
from gruff.rule.context import RuleContext
from gruff.rule.definition import RuleDefinition
from gruff.rule.rule import Rule

_MARKER_PATTERN = re.compile(r"\b(TODO|FIXME|HACK|XXX|BUG)\b")


class TodoDensityRule(Rule):
    ID = "docs.todo-density"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="TODO density",
            pillar=Pillar.DOCUMENTATION,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
            default_thresholds={"warning": 10},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if not unit.source:
            return []
        definition = self.definition()
        settings = context.settings_for(definition)
        threshold = settings.numeric_threshold("warning")

        matches = _MARKER_PATTERN.findall(unit.source)
        marker_count = len(matches)
        if marker_count == 0:
            return []
        line_count = max(1, unit.line_count())
        density = marker_count * 1000 / line_count
        if density <= threshold:
            return []

        return [
            Finding(
                rule_id=definition.id,
                message=(
                    f"File has {marker_count} TODO/FIXME-style markers "
                    f"({density:.1f} per 1000 lines), above the threshold of {threshold}."
                ),
                file_path=unit.file.display_path,
                line=1,
                severity=definition.default_severity,
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
                    "threshold": threshold,
                },
            ),
        ]
