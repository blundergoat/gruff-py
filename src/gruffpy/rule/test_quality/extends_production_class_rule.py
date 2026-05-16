"""``test-quality.extends-production-class`` — test class inherits from production code.

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
    ID = "test-quality.extends-production-class"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Test class extends production class",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        if not _is_test_file(unit.file.display_path):
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.ClassDef):
                continue
            if not node.name.startswith("Test"):
                continue
            for base in node.bases:
                base_name = _base_name(base)
                if base_name is None or base_name in _TESTING_BASES:
                    continue
                if base_name.split(".")[-1] in _TESTING_BASES:
                    continue
                findings.append(
                    Finding(
                        rule_id=definition.id,
                        message=(
                            f"Test class {node.name!r} extends production class {base_name!r}."
                        ),
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
                    ),
                )
                break
        return findings


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
