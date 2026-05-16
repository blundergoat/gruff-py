"""``size.public-method-count`` — too many public methods widen the maintenance surface."""

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
from gruff.rule.size._lines import parent_chain, qualified_symbol


class PublicMethodCountRule(Rule):
    ID = "size.public-method-count"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Public method count",
            pillar=Pillar.SIZE,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
            default_thresholds={"warning": 15, "error": 25},
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

            count = _count_public_methods(node)
            if count <= warning_threshold:
                continue

            if count > error_threshold:
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
                        f"Class {symbol!r} has {count} public methods, "
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
                    remediation=("Split responsibilities; extract collaborator classes."),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={
                        "publicMethods": count,
                        "measuredValue": count,
                        "threshold": threshold,
                        "thresholdDirection": "above",
                        "thresholdType": severity.value,
                    },
                ),
            )

        return findings


def _count_public_methods(cls: ast.ClassDef) -> int:
    count = 0
    for stmt in cls.body:
        if not isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        name = stmt.name
        if name.startswith("_"):
            # Includes single-underscore private and dunder methods.
            continue
        count += 1
    return count


def _format_number(value: int | float) -> str:
    if isinstance(value, float) and not value.is_integer():
        return str(value)
    return str(int(value))
