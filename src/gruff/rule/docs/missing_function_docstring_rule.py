"""``docs.missing-function-docstring`` — public function/method without a docstring.

Public = the name does not start with ``_``. Dunder methods, abstract methods,
pytest-style ``test_*`` functions in test files, ``@typing.overload`` stubs,
and ``@<name>.setter``/``@<name>.deleter`` methods are exempt. ``@property``
getters require a docstring like any public method.
"""

import ast

from gruff.finding.confidence import Confidence
from gruff.finding.finding import Finding
from gruff.finding.pillar import Pillar
from gruff.finding.rule_tier import RuleTier
from gruff.finding.severity import Severity
from gruff.parser.analysis_unit import AnalysisUnit
from gruff.rule._python_dynamism import (
    is_abstract_method,
    is_overload_stub,
    is_protocol_method_stub,
)
from gruff.rule.context import RuleContext
from gruff.rule.definition import RuleDefinition
from gruff.rule.docs._docstring_parser import extract_docstring
from gruff.rule.docs._helpers import (
    is_dunder,
    is_property_setter_or_deleter,
    is_public,
    is_test_file,
)
from gruff.rule.rule import Rule
from gruff.rule.size._lines import parent_chain, qualified_symbol


class MissingFunctionDocstringRule(Rule):
    ID = "docs.missing-function-docstring"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Missing function docstring",
            pillar=Pillar.DOCUMENTATION,
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
            if not is_public(node.name) or is_dunder(node.name):
                continue
            if node.name.startswith("test_") and is_test_file(unit.file.display_path):
                continue
            if extract_docstring(node) is not None:
                continue
            if is_abstract_method(node):
                continue
            if is_overload_stub(node):
                continue
            if is_property_setter_or_deleter(node):
                continue
            parents = parent_chain(node)
            if is_protocol_method_stub(node, parents):
                continue

            symbol = qualified_symbol(node, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=f"Function {symbol!r} has no docstring.",
                    file_path=unit.file.display_path,
                    line=node.lineno,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=node.end_lineno,
                    symbol=symbol,
                    remediation=(
                        "Add a docstring explaining the function's contract and any side effects."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={},
                ),
            )
        return findings
