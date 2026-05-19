"""``test-quality.global-state-mutation`` — test assigns to a module-level name.

Detects ``global x; x = ...`` and direct module-level rebinding from within
a test, which leaks state between tests.
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
from gruffpy.rule.size._lines import parent_chain, qualified_symbol
from gruffpy.rule.test_quality._test_quality_node_helper import (
    test_functions,
    walk_test_body,
)


class GlobalStateMutationRule(Rule):
    """Detect tests that rebind a module-level name or use `global` to mutate shared state."""

    ID = "test-quality.global-state-mutation"

    def definition(self) -> RuleDefinition:
        """Describe the global-state-mutation rule as a medium-confidence warning.

        Medium confidence because v0.1 detects only the explicit ``global``
        declaration shape — direct module-level rebinding without ``global``
        is not yet caught.

        Returns:
            Definition tagging this rule under the test-quality pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Global state mutation in test",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag test functions that declare ``global`` to rebind a module-level name.

        Stops at the first ``global`` statement per test (one finding per
        function is enough); module-level state leaks across tests and breaks
        order-independence.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused — no thresholds).

        Returns:
            One finding per test that uses ``global``, with the affected
            names captured in metadata.
        """
        if unit.tree is None:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for fn, _scope in test_functions(unit):
            for node in walk_test_body(fn):
                if not isinstance(node, ast.Global):
                    continue
                parents = parent_chain(fn)
                symbol = qualified_symbol(fn, parents)
                findings.append(
                    Finding(
                        rule_id=definition.id,
                        message=(f"Test {symbol!r} uses `global` to mutate module-level state."),
                        file_path=unit.file.display_path,
                        line=node.lineno,
                        severity=definition.default_severity,
                        pillar=definition.pillar,
                        tier=definition.tier,
                        confidence=definition.confidence,
                        end_line=node.end_lineno,
                        symbol=symbol,
                        remediation=(
                            "Replace global state with explicit parameters or a fixture; "
                            "isolate tests so order doesn't matter."
                        ),
                        secondary_pillars=definition.secondary_pillars,
                        metadata={"names": list(node.names)},
                    ),
                )
                break
        return findings
