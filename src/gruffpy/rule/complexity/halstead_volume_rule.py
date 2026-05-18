"""Halstead volume per function.

Wraps the helper in ``_halstead.py``. See that module for the operator/
operand classification and known radon deltas.
"""

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.complexity._halstead import halstead_for
from gruffpy.rule.complexity._walks import iter_functions
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule
from gruffpy.rule.size._lines import parent_chain, qualified_symbol


class HalsteadVolumeRule(Rule):
    ID = "complexity.halstead-volume"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Halstead volume",
            pillar=Pillar.COMPLEXITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.MEDIUM,
            default_thresholds={"warning": 180, "error": 400},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []

        definition = self.definition()
        settings = context.settings_for(definition)

        findings: list[Finding] = []
        for fn in iter_functions(unit.tree):
            metrics = halstead_for(fn)
            volume = metrics.volume
            threshold_match = settings.high_value_threshold_match(volume)
            if threshold_match is None:
                continue

            parents = parent_chain(fn)
            symbol = qualified_symbol(fn, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        f"Function {symbol!r} has Halstead volume {volume:.0f}, "
                        f"above the {threshold_match.severity.value} threshold of "
                        f"{_format_number(threshold_match.threshold)}."
                    ),
                    file_path=unit.file.display_path,
                    line=fn.lineno,
                    severity=threshold_match.severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=fn.end_lineno,
                    symbol=symbol,
                    remediation=(
                        "Reduce operator/operand vocabulary; "
                        "extract subexpressions into named helpers."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={
                        "halsteadVolume": round(volume, 2),
                        "halsteadVocabulary": metrics.vocabulary,
                        "halsteadLength": metrics.length,
                        "measuredValue": round(volume, 2),
                        "threshold": threshold_match.threshold,
                        "thresholdDirection": "above",
                        "thresholdType": threshold_match.severity.value,
                    },
                ),
            )
        return findings


def _format_number(value: int | float) -> str:
    if isinstance(value, float) and not value.is_integer():
        return str(value)
    return str(int(value))
