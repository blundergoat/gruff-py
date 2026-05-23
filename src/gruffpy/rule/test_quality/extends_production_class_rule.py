"""``test-quality.extends-production-class`` - test class inherits from production code.

Tests should not subclass the code they're testing. Doing so couples the test to
internal behaviour and risks bypassing the public API. The rule fires on
``class TestFoo(Foo)`` shapes where ``Foo`` is imported from non-test code.

Heuristic: any class named ``Test*`` whose first base is a non-standard-library
name and not ``object`` / ``TestCase`` / a typing class.
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

_TESTING_BASES: frozenset[str] = frozenset(
    {
        "object",
        "TestCase",
        "IsolatedAsyncioTestCase",
        "unittest.TestCase",
        "Protocol",
        "ABC",
        "Generic",
    }
)


class ExtendsProductionClassRule(Rule):
    """Detect `Test<X>` classes whose base is a non-test production type imported from app code."""

    ID = "test-quality.extends-production-class"

    def definition(self) -> RuleDefinition:
        """Describe the extends-production-class rule as a high-confidence warning.

        High confidence because the rule allowlists the conventional testing
        bases (``TestCase``, ``Protocol``, ``ABC``, ``Generic``, ``object``);
        anything outside that list is almost certainly production code being
        subclassed by tests.

        Returns:
            Definition tagging this rule under the test-quality pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Test class extends production class",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag ``class Test*`` definitions whose first base is non-testing production code.

        Only runs inside test files (path contains ``tests/`` or filename
        matches ``test_*.py``); the allowlist of bases includes ``object``,
        ``TestCase``, ``IsolatedAsyncioTestCase``, ``Protocol``, ``ABC``, and
        ``Generic``.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per offending ``Test*`` class.
        """
        if unit.tree is None:
            return []
        if not _is_test_file(unit.file.display_path):
            return []
        definition = self.definition()
        return [
            _extends_production_class_finding(unit, definition, node, base_name)
            for node, base_name in _production_subclasses(unit.tree)
        ]


def _production_subclasses(tree: ast.AST) -> list[tuple[ast.ClassDef, str]]:
    findings: list[tuple[ast.ClassDef, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
            base_name = _production_base_name(node)
            if base_name is not None:
                findings.append((node, base_name))
    return findings


def _production_base_name(node: ast.ClassDef) -> str | None:
    for base in node.bases:
        base_name = _base_name(base)
        if base_name is None or base_name in _TESTING_BASES:
            continue
        if base_name.split(".")[-1] not in _TESTING_BASES:
            return base_name
    return None


def _extends_production_class_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    node: ast.ClassDef,
    base_name: str,
) -> Finding:
    return Finding(
        rule_id=definition.id,
        message=(f"Test class {node.name!r} extends production class {base_name!r}."),
        file_path=unit.file.display_path,
        line=node.lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=node.end_lineno,
        symbol=node.name,
        remediation=(
            "Test via the public API, not by subclassing the SUT. If you need "
            "test-only behaviour, compose rather than inherit."
        ),
        secondary_pillars=definition.secondary_pillars,
        metadata={"base": base_name},
    )


def _base_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _base_name(node.value)
        if prefix is None:
            return node.attr
        return f"{prefix}.{node.attr}"
    return None


def _is_test_file(display_path: str) -> bool:
    normalized = display_path.replace("\\", "/").lower()
    name = normalized.rsplit("/", 1)[-1]
    if normalized.startswith("tests/") or "/tests/" in normalized:
        return True
    return "/" not in normalized and name.startswith("test_") and name.endswith(".py")
