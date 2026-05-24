"""``test-quality.mocking-domain-object`` - mock factory wraps a domain type.

Configurable: requires ``domain_namespaces`` option (list of dotted prefixes
that identify the project's domain types). The rule fires when a mock factory's
positional argument names a type rooted in one of those namespaces.
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
    is_mock_factory_call,
    test_functions,
    walk_test_body,
)


class MockingDomainObjectRule(Rule):
    """Flag mock factories whose target type lives under a configured `domain_namespaces` prefix."""

    ID = "test-quality.mocking-domain-object"

    def definition(self) -> RuleDefinition:
        """Describe the mocking-domain-object rule as a medium-confidence advisory.

        The rule cannot identify "domain" namespaces without project-specific
        configuration, so it stays silent until ``domain_namespaces`` is set.

        Returns:
            Definition with the ``domain_namespaces`` option seeded to an empty list.
        """
        return RuleDefinition(
            id=self.ID,
            name="Mocking domain object",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
            default_options={"domain_namespaces": []},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag mock factory calls whose ``spec=`` / first arg names a configured domain type.

        Resolves dotted names from the factory's positional or ``spec``/
        ``spec_set`` keyword argument and matches against the
        ``domain_namespaces`` prefix list; emits nothing when the option is
        empty.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context supplying the
                ``domain_namespaces`` list option.

        Returns:
            One finding per mock factory targeting a configured domain type.
        """
        if unit.tree is None:
            return []
        definition = self.definition()
        settings = context.settings_for(definition)
        namespaces = settings.string_list_option("domain_namespaces")
        if not namespaces:
            return []
        findings: list[Finding] = []
        for fn, _scope in test_functions(unit):
            for node in walk_test_body(fn):
                if not isinstance(node, ast.Call) or not is_mock_factory_call(node):
                    continue
                target_type = _spec_target(node)
                if target_type is None:
                    continue
                if not any(
                    target_type == ns or target_type.startswith(ns + ".") for ns in namespaces
                ):
                    continue
                parents = parent_chain(fn)
                symbol = qualified_symbol(fn, parents)
                findings.append(
                    Finding(
                        rule_id=definition.id,
                        message=(f"Test {symbol!r} mocks a domain type ({target_type!r})."),
                        file_path=unit.file.display_path,
                        line=node.lineno,
                        severity=definition.default_severity,
                        pillar=definition.pillar,
                        tier=definition.tier,
                        confidence=definition.confidence,
                        end_line=node.end_lineno,
                        symbol=symbol,
                        remediation=(
                            "Construct a real instance of the domain type with test-friendly "
                            "data. Mocks belong at infrastructure boundaries, not domain."
                        ),
                        secondary_pillars=definition.secondary_pillars,
                        metadata={"type": target_type},
                    ),
                )
        return findings


def _spec_target(call: ast.Call) -> str | None:
    """Return the dotted name of the type passed to Mock(spec=...) / create_autospec."""
    if call.args:
        name = _dotted(call.args[0])
        if name is not None:
            return name
    for kw in call.keywords:
        if kw.arg in {"spec", "spec_set"}:
            name = _dotted(kw.value)
            if name is not None:
                return name
    return None


def _dotted(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted(node.value)
        if prefix is None:
            return node.attr
        return f"{prefix}.{node.attr}"
    return None
