"""``test-quality.sleep-in-test`` — ``time.sleep`` or ``asyncio.sleep`` in a test body.

Sleep-based waits are a classic source of flaky tests. The rule flags any call
whose dotted target ends in ``.sleep`` (covering ``time.sleep``, ``asyncio.sleep``,
``trio.sleep``, ``anyio.sleep``).
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
from gruffpy.rule.test_quality._test_quality_node_helper import (
    test_functions,
    walk_test_body,
)


class SleepInTestRule(Rule):
    ID = "test-quality.sleep-in-test"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Sleep in test",
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
            for node in walk_test_body(fn):
                if not isinstance(node, ast.Call):
                    continue
                target = call_target_name(node)
                if target is None or not target.endswith("sleep"):
                    continue
                parents = parent_chain(fn)
                symbol = qualified_symbol(fn, parents)
                findings.append(
                    Finding(
                        rule_id=definition.id,
                        message=f"Test {symbol!r} contains `{target}(...)` — flake risk.",
                        file_path=unit.file.display_path,
                        line=node.lineno,
                        severity=definition.default_severity,
                        pillar=definition.pillar,
                        tier=definition.tier,
                        confidence=definition.confidence,
                        end_line=node.end_lineno,
                        symbol=symbol,
                        remediation=(
                            "Poll for the condition with a timeout, use a fake clock, "
                            "or restructure the code under test to expose synchronisation hooks."
                        ),
                        secondary_pillars=definition.secondary_pillars,
                        metadata={"target": target},
                    ),
                )
        return findings
