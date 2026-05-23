"""``test-quality.unused-mock`` - mock variable created but never referenced afterwards.

Catches ``mock = Mock(); assert real_thing == 1`` where ``mock`` is never used.
The mock-detection extension to the helper finds the bindings; this rule scans
the test body for subsequent references.
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
    find_mock_bindings,
    test_functions,
    walk_test_body,
)


class UnusedMockRule(Rule):
    """Detect mock variables created in a test body that are never referenced afterwards."""

    ID = "test-quality.unused-mock"

    def definition(self) -> RuleDefinition:
        """Describe the unused-mock rule as a high-confidence warning.

        High confidence because the rule looks for any Load-context
        reference to the mock's name in the test body - a mock with zero
        such references is dead test scaffolding.

        Returns:
            Definition tagging this rule under the test-quality pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Unused mock",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag tests whose mock binding name is never read elsewhere in the function body.

        Considers a mock "used" only when its name appears as a
        Load-context ``Name`` node (attribute access, function argument,
        etc.); plain reassignment doesn't count.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per test, listing the unused mock names in the
            message and metadata.
        """
        if unit.tree is None:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for fn, _scope in test_functions(unit):
            bindings = find_mock_bindings(fn)
            if not bindings:
                continue
            referenced = _referenced_names(fn, set(bindings))
            unused = sorted(set(bindings) - referenced)
            if not unused:
                continue
            parents = parent_chain(fn)
            symbol = qualified_symbol(fn, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(f"Test {symbol!r} creates mock(s) never used afterwards: {unused}."),
                    file_path=unit.file.display_path,
                    line=fn.lineno,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=fn.end_lineno,
                    symbol=symbol,
                    remediation=(
                        "Delete the unused mock, or assert on its interactions to prove "
                        "the SUT calls it the way you expect."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={"mocks": list(unused)},
                ),
            )
        return findings


def _referenced_names(fn: ast.FunctionDef | ast.AsyncFunctionDef, names: set[str]) -> set[str]:
    """Return the subset of *names* that appear as Load-context Name references."""
    found: set[str] = set()
    for node in walk_test_body(fn):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in names:
            found.add(node.id)
    return found
