"""``test-quality.naming-consistency`` - mixed test-naming conventions in one file.

Emits once per file where two or more of these conventions coexist among
module-level test functions / classes:

- ``def test_foo`` (snake_case, pytest)
- ``def testFoo`` (camelCase, unittest)
- ``class TestFoo`` (PascalCase pytest class)
- ``class FooTest`` (PascalCase suffix)
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


class NamingConsistencyRule(Rule):
    """Detect test files that mix `test_foo`, `testFoo`, `TestFoo`, and `FooTest` naming styles."""

    ID = "test-quality.naming-consistency"

    def definition(self) -> RuleDefinition:
        """Describe the naming-consistency rule as a medium-confidence advisory.

        Medium confidence because mixed pytest/unittest naming sometimes
        reflects legitimate migration in progress; the rule fires on the
        observable mix without judging intent.

        Returns:
            Definition tagging this rule under the test-quality pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Test-naming consistency",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Emit one finding per test file that mixes two or more test-naming conventions.

        Conventions tracked: ``test_snake`` (``def test_foo``), ``testCamel``
        (``def testFoo``), ``TestPrefix`` (``class TestFoo``), and
        ``SuffixTest`` (``class FooTest``). Fires only when 2+ are present.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            A single file-anchored finding listing the observed conventions,
            or empty when fewer than two coexist.
        """
        if not isinstance(unit.tree, ast.Module):
            return []
        if (
            not unit.file.display_path.endswith(".py")
            or "test" not in unit.file.display_path.lower()
        ):
            return []
        conventions: set[str] = set()
        for node in unit.tree.body:
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                if node.name.startswith("test_"):
                    conventions.add("test_snake")
                elif node.name.startswith("test") and len(node.name) > 4 and node.name[4].isupper():
                    conventions.add("testCamel")
            elif isinstance(node, ast.ClassDef):
                if node.name.startswith("Test"):
                    conventions.add("TestPrefix")
                elif node.name.endswith("Test"):
                    conventions.add("SuffixTest")
        if len(conventions) < 2:
            return []
        definition = self.definition()
        return [
            Finding(
                rule_id=definition.id,
                message=(f"File mixes test-naming conventions: {sorted(conventions)}. Pick one."),
                file_path=unit.file.display_path,
                line=1,
                severity=definition.default_severity,
                pillar=definition.pillar,
                tier=definition.tier,
                confidence=definition.confidence,
                remediation=(
                    "Pick one convention per project (pytest's `def test_foo` is the "
                    "modern default) and rename the outliers."
                ),
                secondary_pillars=definition.secondary_pillars,
                metadata={"conventions": sorted(conventions)},
            ),
        ]
