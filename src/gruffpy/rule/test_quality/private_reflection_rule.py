"""``test-quality.private-reflection`` — test accesses ``_x`` / ``__x`` of the SUT.

Tests that reach into private attributes are tightly coupled to implementation.
Catches ``obj._private``, ``ClassName._private``, and dunder-mangled access
via ``getattr(obj, '_ClassName__name')``.
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


class PrivateReflectionRule(Rule):
    """Detect tests accessing `_x`/`__x` attributes (or mangled `_Cls__name`) on the SUT."""

    ID = "test-quality.private-reflection"

    def definition(self) -> RuleDefinition:
        """Describe the private-reflection rule as a medium-confidence warning.

        Medium confidence because some legitimate test patterns access
        ``_private`` (e.g. testing a thoroughly internal helper); the rule
        catches the broad case and lets users suppress the rare exceptions.

        Returns:
            Definition tagging this rule under the test-quality pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Private reflection in test",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag tests that access ``_private`` attributes on objects other than ``self``/``cls``.

        Skips dunder names (``__init__``, ``__class__``) since those are
        framework hooks rather than private state; allows ``self._x`` and
        ``cls._x`` to permit ordinary in-class test helpers.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused — no thresholds).

        Returns:
            One finding per test reaching into a private attribute (capped
            at one per function).
        """
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
