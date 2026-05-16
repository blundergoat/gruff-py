"""``test-quality.repeated-structure-missing-parametrize`` — many near-identical tests.

Heuristic: 3+ module-level test functions whose AST bodies, after stripping
constant values, hash to the same shape. They're candidates for
``@pytest.mark.parametrize``.
"""

import ast
import collections
import hashlib
from typing import Any

from gruff.finding.confidence import Confidence
from gruff.finding.finding import Finding
from gruff.finding.pillar import Pillar
from gruff.finding.rule_tier import RuleTier
from gruff.finding.severity import Severity
from gruff.parser.analysis_unit import AnalysisUnit
from gruff.rule.context import RuleContext
from gruff.rule.definition import RuleDefinition
from gruff.rule.rule import Rule
from gruff.rule.size._lines import parent_chain, qualified_symbol
from gruff.rule.test_quality._test_quality_node_helper import test_functions


class RepeatedStructureMissingParametrizeRule(Rule):
    ID = "test-quality.repeated-structure-missing-parametrize"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Repeated structure without parametrize",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
            default_thresholds={"warning": 3},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        definition = self.definition()
        settings = context.settings_for(definition)
        min_group = int(settings.numeric_threshold("warning"))
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
    return hashlib.sha1(blob).hexdigest()


def _constant_shape(value: Any) -> str:
    if isinstance(value, str) and ("\n" in value or len(value) > 80):
        digest = hashlib.sha1(value.encode()).hexdigest()
        return f"Const:str:{digest}"
    return f"Const:{type(value).__name__}"
