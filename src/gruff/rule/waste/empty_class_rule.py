"""Class whose body is ``pass`` or ``...`` only.

Skipped for: Protocol/ABC/TypedDict/Enum-like bases (they intentionally have
empty bodies as marker classes); for ``@dataclass``-decorated classes; and
for classes with decorators marked as framework hooks.
"""

import ast

from gruff.finding.confidence import Confidence
from gruff.finding.finding import Finding
from gruff.finding.pillar import Pillar
from gruff.finding.rule_tier import RuleTier
from gruff.finding.severity import Severity
from gruff.parser.analysis_unit import AnalysisUnit
from gruff.rule._python_dynamism import (
    _is_empty_body,
    has_dataclass_decorator,
    has_framework_base,
    has_framework_decorator,
)
from gruff.rule.context import RuleContext
from gruff.rule.definition import RuleDefinition
from gruff.rule.rule import Rule
from gruff.rule.size._lines import parent_chain, qualified_symbol


class EmptyClassRule(Rule):
    ID = "waste.empty-class"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Empty class",
            pillar=Pillar.DEAD_CODE,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.ClassDef):
                continue
            if not _is_empty_body(node.body):
                continue
            if has_framework_base(node):
                continue
            if has_dataclass_decorator(node):
                continue
            if has_framework_decorator(node):
                continue

            parents = parent_chain(node)
            symbol = qualified_symbol(node, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=f"Class {symbol!r} has an empty body.",
                    file_path=unit.file.display_path,
                    line=node.lineno,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=node.end_lineno,
                    symbol=symbol,
                    remediation=(
                        "Delete the class, or implement it; "
                        "if it's a marker base, extend Protocol/ABC."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={},
                ),
            )
        return findings
