"""Function/method whose body is ``pass`` or ``...`` only.

Skipped for: abstract methods, ``@typing.overload`` stubs, methods in
Protocol/ABC subclasses, and functions carrying framework-hook decorators.
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
    has_framework_decorator,
    is_abstract_method,
    is_overload_stub,
    is_protocol_method_stub,
)
from gruff.rule.context import RuleContext
from gruff.rule.definition import RuleDefinition
from gruff.rule.rule import Rule
from gruff.rule.size._lines import parent_chain, qualified_symbol


class EmptyFunctionRule(Rule):
    ID = "waste.empty-function"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Empty function",
            pillar=Pillar.DEAD_CODE,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            if not _is_empty_body(node.body):
                continue
            parents = parent_chain(node)
            if is_abstract_method(node):
                continue
            if is_overload_stub(node):
                continue
            if is_protocol_method_stub(node, parents):
                continue
            if has_framework_decorator(node):
                continue

            symbol = qualified_symbol(node, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=f"Function {symbol!r} has an empty body.",
                    file_path=unit.file.display_path,
                    line=node.lineno,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=node.end_lineno,
                    symbol=symbol,
                    remediation=(
                        "Implement the function, delete it, or mark it as abstract/overload."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={},
                ),
            )
        return findings
