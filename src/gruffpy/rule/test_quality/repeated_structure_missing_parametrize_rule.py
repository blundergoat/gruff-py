"""``test-quality.repeated-structure-missing-parametrize`` — many near-identical tests.

Heuristic: 3+ module-level test functions whose AST bodies, after stripping
constant values, hash to the same shape. They're candidates for
``@pytest.mark.parametrize``.
"""

import ast
import collections
import hashlib
from typing import Any

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
from gruffpy.rule.test_quality._test_quality_node_helper import test_functions


class RepeatedStructureMissingParametrizeRule(Rule):
    """Detect groups of three or more test functions whose AST shape collapses to the same hash."""

    ID = "test-quality.repeated-structure-missing-parametrize"

    def definition(self) -> RuleDefinition:
        """Describe the repeated-structure rule with a ``minGroupSize`` threshold (default 3).

        Medium confidence because the structural hash ignores constant
        values to find shape duplicates — but legitimately distinct tests
        can occasionally hash the same when they share boilerplate scaffolding.

        Returns:
            Definition with the ``minGroupSize`` threshold key.
        """
        return RuleDefinition(
            id=self.ID,
            name="Repeated structure without parametrize",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
            default_thresholds={"minGroupSize": 3},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag tests sharing a body-shape hash with at least ``minGroupSize - 1`` siblings.

        Hashes each test body's structural skeleton (node types, names,
        attributes — but not constant values) and groups by hash; skips
        tests that already have a call-style decorator (they're presumed
        intentionally individualised).

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context supplying the ``minGroupSize``
                numeric threshold.

        Returns:
            One finding per test belonging to a shape-equivalent group whose
            size meets the threshold.
        """
        if unit.tree is None:
            return []
        definition = self.definition()
        settings = context.settings_for(definition)
        min_group = int(settings.numeric_threshold("minGroupSize"))
        findings: list[Finding] = []
        groups: dict[str, list[ast.FunctionDef | ast.AsyncFunctionDef]] = collections.defaultdict(
            list
        )
        for fn, _scope in test_functions(unit):
            if any(isinstance(d, ast.Call) for d in fn.decorator_list):
                continue  # decorated tests are already structured
            groups[_shape_hash(fn)].append(fn)
        for fns in groups.values():
            if len(fns) < min_group:
                continue
            for fn in fns:
                parents = parent_chain(fn)
                symbol = qualified_symbol(fn, parents)
                findings.append(
                    Finding(
                        rule_id=definition.id,
                        message=(
                            f"Test {symbol!r} shares a body shape with {len(fns) - 1} other "
                            f"test(s) — candidate for @pytest.mark.parametrize."
                        ),
                        file_path=unit.file.display_path,
                        line=fn.lineno,
                        severity=definition.default_severity,
                        pillar=definition.pillar,
                        tier=definition.tier,
                        confidence=definition.confidence,
                        end_line=fn.end_lineno,
                        symbol=symbol,
                        remediation=(
                            "Collapse the duplicated tests into one parametrised test that "
                            "iterates the differing values."
                        ),
                        secondary_pillars=definition.secondary_pillars,
                        metadata={"groupSize": len(fns)},
                    ),
                )
        return findings


def _shape_hash(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    """Hash the *structural* shape of a function body, ignoring constant values."""
    parts: list[str] = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Constant):
            parts.append(_constant_shape(node.value))
        elif isinstance(node, ast.Name):
            parts.append(f"Name:{node.id}")
        elif isinstance(node, ast.Attribute):
            parts.append(f"Attribute:{node.attr}")
        else:
            parts.append(type(node).__name__)
    blob = "|".join(parts).encode()
    return hashlib.sha256(blob).hexdigest()


def _constant_shape(value: Any) -> str:
    if isinstance(value, str) and ("\n" in value or len(value) > 80):
        digest = hashlib.sha256(value.encode()).hexdigest()
        return f"Const:str:{digest}"
    return f"Const:{type(value).__name__}"
