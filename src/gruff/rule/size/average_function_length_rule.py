import ast

from gruff.finding.confidence import Confidence
from gruff.finding.finding import Finding
from gruff.finding.pillar import Pillar
from gruff.finding.rule_tier import RuleTier
from gruff.finding.severity import Severity
from gruff.parser.analysis_unit import AnalysisUnit
from gruff.rule.context import RuleContext
from gruff.rule.definition import RuleDefinition
from gruff.rule.rule import Rule
from gruff.rule.size._lines import lines_for_size, parent_chain, qualified_symbol


class AverageFunctionLengthRule(Rule):
    ID = "size.average-function-length"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Average function length per class",
            pillar=Pillar.SIZE,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
            default_thresholds={"warning": 30, "error": 60},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []

        definition = self.definition()
        settings = context.settings_for(definition)
        warning_threshold = settings.numeric_threshold("warning")
        error_threshold = settings.numeric_threshold("error")

        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.ClassDef):
                continue

            methods = [
                child
                for child in node.body
                if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef)
            ]
            if not methods:
                continue

            avg = sum(lines_for_size(m) for m in methods) / len(methods)
            if avg <= warning_threshold:
                continue

            if avg > error_threshold:
                severity = Severity.ERROR
                threshold: int | float = error_threshold
            else:
                severity = Severity.WARNING
                threshold = warning_threshold

            parents = parent_chain(node)
            symbol = qualified_symbol(node, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        f"Class {symbol!r} averages {avg:.1f} lines per method "
                        f"(over {len(methods)} methods), "
                        f"above the {severity.value} threshold of {_format_number(threshold)}."
                    ),
                    file_path=unit.file.display_path,
                    line=node.lineno,
                    severity=severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=node.end_lineno,
                    symbol=symbol,
                    remediation=(
                        "Shorten the typical method or split responsibilities; "
                        "tall averages usually signal a god class."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={
                        "averageLines": round(avg, 2),
                        "methodCount": len(methods),
                        "threshold": threshold,
                        "thresholdType": severity.value,
                    },
                ),
            )

        return findings


def _format_number(value: int | float) -> str:
    if isinstance(value, float) and not value.is_integer():
        return str(value)
    return str(int(value))
