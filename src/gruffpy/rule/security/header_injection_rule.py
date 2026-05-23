"""``security.header-injection`` - ``response.headers[<dynamic>] = ...``.

Heuristic: subscript-assignment to an attribute named ``headers`` where the
subscript key is not a string literal. Scoped to files that import a known
web framework (Flask / FastAPI / Django) to keep false-positive risk low.
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
from gruffpy.rule.security._security_node_helper import (
    frameworks_in_use,
    is_string_literal,
)

_FRAMEWORK_GATE: frozenset[str] = frozenset({"flask", "fastapi", "django"})


class HeaderInjectionRule(Rule):
    """Detect `response.headers[<dynamic>] = ...` assignments in web-framework modules."""

    ID = "security.header-injection"

    def definition(self) -> RuleDefinition:
        """Describe the header-injection rule as a medium-confidence warning.

        Medium confidence because the ``response.headers[x] = y`` shape
        could be from a non-web ``headers`` dict; the file-level framework
        gate trims most of that noise.

        Returns:
            Definition for the header-injection rule under the security pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Header injection",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag ``...headers[<non-literal>] = ...`` in files that import Flask/FastAPI/Django.

        The framework gate is intentional - without it the shape produces
        too many false positives on non-web ``headers`` dicts (HTTP
        clients, parser libraries, message queues).

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per dynamic-key header assignment in gated files.
        """
        if unit.tree is None or "headers" not in unit.source:
            return []
        if not (frameworks_in_use(unit.tree) & _FRAMEWORK_GATE):
            return []
        definition = self.definition()
        return [
            _header_injection_finding(unit, definition, node)
            for node in _dynamic_header_assignments(unit.tree)
        ]


def _dynamic_header_assignments(tree: ast.AST) -> list[ast.Assign]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign) and any(_is_dynamic_header_target(t) for t in node.targets)
    ]


def _is_dynamic_header_target(target: ast.expr) -> bool:
    if not isinstance(target, ast.Subscript):
        return False
    value = target.value
    if not (isinstance(value, ast.Attribute) and value.attr == "headers"):
        return False
    return not is_string_literal(target.slice)


def _header_injection_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    node: ast.Assign,
) -> Finding:
    return Finding(
        rule_id=definition.id,
        message="Response header key is dynamic - header injection risk.",
        file_path=unit.file.display_path,
        line=node.lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=node.end_lineno,
        remediation=(
            "Use literal header names. If a runtime-chosen name is "
            "essential, validate against an explicit allowlist."
        ),
        secondary_pillars=definition.secondary_pillars,
        metadata={},
    )
