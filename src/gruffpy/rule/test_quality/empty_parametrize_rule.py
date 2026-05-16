"""``test-quality.empty-parametrize`` — ``@pytest.mark.parametrize`` with an empty cases list.

A parametrize decorator with an empty list silently skips the test.
"""

import ast

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule
from gruffpy.rule.security._security_node_helper import call_target_name
from gruffpy.rule.size._lines import parent_chain, qualified_symbol
from gruffpy.rule.test_quality._test_quality_node_helper import test_functions


class EmptyParametrizeRule(Rule):
    ID = "test-quality.empty-parametrize"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Empty parametrize",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for fn, _scope in test_functions(unit):
            for decorator in fn.decorator_list:
                if not isinstance(decorator, ast.Call):
                    continue
                target = call_target_name(decorator)
                if target is None or not target.endswith("parametrize"):
                    continue
                if len(decorator.args) < 2:
                    continue
                cases = decorator.args[1]
                if not _is_empty_sequence(cases):
                    continue
                parents = parent_chain(fn)
                symbol = qualified_symbol(fn, parents)
                findings.append(
                    Finding(
                        rule_id=definition.id,
                        message=f"Test {symbol!r} has @parametrize with an empty cases list.",
                        file_path=unit.file.display_path,
                        line=decorator.lineno,
                        severity=definition.default_severity,
                        pillar=definition.pillar,
                        tier=definition.tier,
                        confidence=definition.confidence,
                        end_line=decorator.end_lineno,
                        symbol=symbol,
                        remediation=("Add at least one case, or delete the parametrize decorator."),
                        secondary_pillars=definition.secondary_pillars,
                        metadata={},
                    ),
                )
        return findings


def _is_empty_sequence(node: ast.AST) -> bool:
    return isinstance(node, ast.List | ast.Tuple) and len(node.elts) == 0
