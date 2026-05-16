"""``test-quality.exception-type-only`` — ``pytest.raises(Exception)`` without ``match=``.

Catching just the type doesn't verify *which* error was raised. The rule fires
on ``pytest.raises`` / ``pytest.warns`` contexts that omit the ``match`` argument
when catching a wide type (``Exception`` / ``BaseException``).
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
from gruffpy.rule.security._security_node_helper import call_keyword, call_target_name
from gruffpy.rule.size._lines import parent_chain, qualified_symbol
from gruffpy.rule.test_quality._test_quality_node_helper import (
    test_functions,
    walk_test_body,
)


class ExceptionTypeOnlyRule(Rule):
    ID = "test-quality.exception-type-only"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Exception type-only assertion",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for fn, _scope in test_functions(unit):
            for node in walk_test_body(fn):
                if not isinstance(node, ast.Call):
                    continue
                target = call_target_name(node)
                if target is None or target.split(".")[-1] not in {"raises", "warns"}:
                    continue
                if not node.args:
                    continue
                first = node.args[0]
                if not _is_wide_exception(first):
                    continue
                if call_keyword(node, "match") is not None:
                    continue
                parents = parent_chain(fn)
                symbol = qualified_symbol(fn, parents)
                findings.append(
                    Finding(
                        rule_id=definition.id,
                        message=(f"Test {symbol!r} catches a wide exception without `match=`."),
                        file_path=unit.file.display_path,
                        line=node.lineno,
                        severity=definition.default_severity,
                        pillar=definition.pillar,
                        tier=definition.tier,
                        confidence=definition.confidence,
                        end_line=node.end_lineno,
                        symbol=symbol,
                        remediation=(
                            "Narrow the exception type or add `match='expected substring'` "
                            "to bind the assertion to the message."
                        ),
                        secondary_pillars=definition.secondary_pillars,
                        metadata={},
                    ),
                )
        return findings


def _is_wide_exception(node: ast.expr) -> bool:
    if isinstance(node, ast.Name) and node.id in {"Exception", "BaseException"}:
        return True
    return isinstance(node, ast.Attribute) and node.attr in {"Exception", "BaseException"}
