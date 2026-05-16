"""``test-quality.magic-number-assertion`` — assertion against an unexplained numeric literal.

Default allowlist: HTTP status codes (200, 201, 204, 301, 302, 400, 401, 403,
404, 409, 422, 429, 500, 502, 503, 504) and 0 / 1 / -1. Configurable via the
rule's ``allowed_numbers`` option.
"""

import ast
from typing import TypeGuard

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
from gruff.rule.test_quality._test_quality_node_helper import (
    test_functions,
    walk_test_body,
)

_DEFAULT_ALLOWED: frozenset[int] = frozenset(
    {-1, 0, 1, 200, 201, 204, 301, 302, 400, 401, 403, 404, 409, 422, 429, 500, 502, 503, 504}
)


class MagicNumberAssertionRule(Rule):
    ID = "test-quality.magic-number-assertion"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Magic-number assertion",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
            default_options={"allowed_numbers": sorted(_DEFAULT_ALLOWED)},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        definition = self.definition()
        settings = context.settings_for(definition)
        allowed_raw = settings.options.get(
            "allowed_numbers", definition.default_options["allowed_numbers"]
        )
        allowed = frozenset(int(n) for n in allowed_raw if isinstance(n, int))
        findings: list[Finding] = []
        for fn, _scope in test_functions(unit):
            for node in walk_test_body(fn):
                if not isinstance(node, ast.Assert):
                    continue
                magic = _magic_numbers(node.test, allowed)
                if not magic:
                    continue
                parents = parent_chain(fn)
                symbol = qualified_symbol(fn, parents)
                findings.append(
                    Finding(
                        rule_id=definition.id,
                        message=(f"Test {symbol!r} asserts against magic number(s): {magic}."),
                        file_path=unit.file.display_path,
                        line=node.lineno,
                        severity=definition.default_severity,
                        pillar=definition.pillar,
                        tier=definition.tier,
                        confidence=definition.confidence,
                        end_line=node.end_lineno,
                        symbol=symbol,
                        remediation=(
                            "Name the value (`expected_count = 17`) or add it to the "
                            "rule's `allowed_numbers` option if it's a domain constant."
                        ),
                        secondary_pillars=definition.secondary_pillars,
                        metadata={"numbers": list(magic)},
                    ),
                )
        return findings


def _magic_numbers(expr: ast.expr, allowed: frozenset[int]) -> list[int]:
    out: list[int] = []
    ignored = _len_count_constants(expr)
    for node in ast.walk(expr):
        if node in ignored:
            continue
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, int)
            and not isinstance(node.value, bool)
            and node.value not in allowed
        ):
            out.append(node.value)
    return out


def _len_count_constants(expr: ast.expr) -> set[ast.Constant]:
    ignored: set[ast.Constant] = set()
    for node in ast.walk(expr):
        if not isinstance(node, ast.Compare):
            continue
        if len(node.ops) != 1 or len(node.comparators) != 1:
            continue
        if not isinstance(node.ops[0], ast.Eq | ast.NotEq):
            continue
        left = node.left
        right = node.comparators[0]
        if _is_len_call(left) and _is_int_constant(right):
            ignored.add(right)
        elif _is_int_constant(left) and _is_len_call(right):
            ignored.add(left)
    return ignored


def _is_len_call(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "len"


def _is_int_constant(node: ast.AST) -> TypeGuard[ast.Constant]:
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, int)
        and not isinstance(node.value, bool)
    )
