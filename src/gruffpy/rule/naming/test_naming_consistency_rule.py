"""Mixed test-naming conventions in a single test file.

Conventions detected:

- ``test_<snake_case>`` — pytest module-level convention.
- ``test<camelCase>`` — unittest-camelCase (rare in Python but seen in ports).
- ``Test<CapWords>`` — class-style: ``class TestUserService`` (no extra
  signal; only flag if naming styles for *functions* differ).

The rule fires when a single test file contains ≥2 distinct naming styles
for test functions.

Scope: only Python files whose name starts with ``test_`` or whose path is
under a ``tests/`` directory. The presence of any function with a name
starting with ``test`` flags the file as a "test file".
"""

import ast
import re
from collections.abc import Iterator
from pathlib import Path

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule

_SNAKE_TEST = re.compile(r"^test(_[a-z0-9_]+)+$")
_CAMEL_TEST = re.compile(r"^test[A-Z][A-Za-z0-9]*$")


class TestNamingConsistencyRule(Rule):
    ID = "naming.test-naming-consistency"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Test naming consistency",
            pillar=Pillar.NAMING,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if not isinstance(unit.tree, ast.Module):
            return []
        if not _is_test_file(unit.file.display_path):
            return []
        snake: list[str] = []
        camel: list[str] = []
        for node in _walk_test_functions(unit.tree):
            if _SNAKE_TEST.match(node.name):
                snake.append(node.name)
            elif _CAMEL_TEST.match(node.name):
                camel.append(node.name)
        if not snake or not camel:
            return []

        definition = self.definition()
        return [
            Finding(
                rule_id=definition.id,
                message=(
                    f"File mixes {len(snake)} snake_case test name(s) and "
                    f"{len(camel)} camelCase test name(s); pick one style."
                ),
                file_path=unit.file.display_path,
                line=1,
                severity=definition.default_severity,
                pillar=definition.pillar,
                tier=definition.tier,
                confidence=definition.confidence,
                end_line=1,
                symbol=None,
                remediation=(
                    "Use one naming convention for tests (snake_case is idiomatic in pytest)."
                ),
                secondary_pillars=definition.secondary_pillars,
                metadata={
                    "snakeCaseCount": len(snake),
                    "camelCaseCount": len(camel),
                    "snakeCaseSample": snake[:3],
                    "camelCaseSample": camel[:3],
                },
            )
        ]


def _is_test_file(display_path: str) -> bool:
    name = Path(display_path).name
    if name.startswith("test_") and name.endswith(".py"):
        return True
    return "/tests/" in display_path or display_path.startswith("tests/")


def _walk_test_functions(
    tree: ast.Module,
) -> Iterator[ast.FunctionDef | ast.AsyncFunctionDef]:
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name.startswith(
            "test"
        ):
            yield node
        elif isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
            for child in node.body:
                if isinstance(
                    child, ast.FunctionDef | ast.AsyncFunctionDef
                ) and child.name.startswith("test"):
                    yield child
