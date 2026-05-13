"""``test-quality.private-reflection`` — test accesses ``_x`` / ``__x`` of the SUT.

Tests that reach into private attributes are tightly coupled to implementation.
Catches ``obj._private``, ``ClassName._private``, and dunder-mangled access
via ``getattr(obj, '_ClassName__name')``.
"""

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
from gruff.rule.test_quality._test_quality_node_helper import (
    test_functions,
    walk_test_body,
)


class PrivateReflectionRule(Rule):
    ID = "test-quality.private-reflection"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Private reflection in test",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for fn, _scope in test_functions(unit):
            for node in walk_test_body(fn):
                if not isinstance(node, ast.Attribute):
                    continue
                if not _is_private_name(node.attr):
                    continue
                # Skip self._x access inside the test class itself.
                if isinstance(node.value, ast.Name) and node.value.id in {"self", "cls"}:
                    continue
                parents = parent_chain(fn)
                symbol = qualified_symbol(fn, parents)
                findings.append(
                    Finding(
                        rule_id=definition.id,
                        message=(f"Test {symbol!r} reaches into private attribute {node.attr!r}."),
                        file_path=unit.file.display_path,
                        line=node.lineno,
                        severity=definition.default_severity,
                        pillar=definition.pillar,
                        tier=definition.tier,
                        confidence=definition.confidence,
                        end_line=node.end_lineno,
                        symbol=symbol,
                        remediation=(
                            "Test through the public API. If the private behaviour is "
                            "load-bearing, extract it into a public helper."
                        ),
                        secondary_pillars=definition.secondary_pillars,
                        metadata={"attribute": node.attr},
                    ),
                )
                break  # one finding per test
        return findings


def _is_private_name(name: str) -> bool:
    if name.startswith("__") and name.endswith("__"):
        return False  # dunder = framework hook, not private
    return name.startswith("_")
