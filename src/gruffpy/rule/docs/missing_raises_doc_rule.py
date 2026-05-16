"""``docs.missing-raises-doc`` — documented function that raises but lacks a Raises section.

Public functions only. Walks the body for ``raise`` statements, stopping at
nested function/lambda boundaries (those raises belong to the nested scope).
"""

import ast

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule._python_dynamism import is_overload_stub
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.docs._docstring_parser import extract_docstring, parse_docstring
from gruffpy.rule.docs._helpers import (
    is_dunder,
    is_property_setter_or_deleter,
    is_public,
    raises_in_body,
)
from gruffpy.rule.rule import Rule
from gruffpy.rule.size._lines import parent_chain, qualified_symbol


class MissingRaisesDocRule(Rule):
    ID = "docs.missing-raises-doc"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Missing raises documentation",
            pillar=Pillar.DOCUMENTATION,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.LOW,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            if not is_public(node.name) or is_dunder(node.name):
                continue
            if is_overload_stub(node) or is_property_setter_or_deleter(node):
                continue
            if not raises_in_body(node):
                continue
            text = extract_docstring(node)
            if text is None:
                continue
            parsed = parse_docstring(text)
            if parsed is None:
                continue
            if parsed.raises:
                continue

            parents = parent_chain(node)
            symbol = qualified_symbol(node, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=f"Function {symbol!r} raises but has no Raises section.",
                    file_path=unit.file.display_path,
                    line=node.lineno,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=node.end_lineno,
                    symbol=symbol,
                    remediation=(
                        "Add a Raises / :raises: section naming each exception "
                        "and the trigger condition."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={"style": parsed.style.value},
                ),
            )
        return findings
