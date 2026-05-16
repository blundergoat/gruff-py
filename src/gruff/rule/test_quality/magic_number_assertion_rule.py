"""``test-quality.magic-number-assertion`` — assertion against an unexplained numeric literal.

Default allowlist: HTTP status codes (200, 201, 204, 301, 302, 400, 401, 403,
404, 409, 422, 429, 500, 502, 503, 504) and -1 through 3. Configurable via the
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
    {
        -1,
        0,
        1,
        2,
        3,
        200,
        201,
        204,
        301,
        302,
        400,
        401,
        403,
        404,
        409,
        422,
        429,
        500,
        502,
        503,
        504,
    }
)
_ANALYSER_METRIC_KEYS: frozenset[str] = frozenset(
    {
        "attributes",
        "averageLines",
        "cognitive",
        "complexity",
        "count",
        "depth",
        "durationMs",
        "endLine",
        "error",
        "errorCrossings",
        "errorThreshold",
        "filesDiscovered",
        "filesParsed",
        "findings",
        "functions",
        "halsteadLength",
        "halsteadVolume",
        "halsteadVocabulary",
        "ignored",
        "line",
        "lines",
        "maintainabilityIndex",
        "max",
        "measuredValue",
        "methodCount",
        "min",
        "missing",
        "npath",
        "parameters",
        "parseErrors",
        "p50",
        "p90",
        "p95",
        "publicMethods",
        "threshold",
        "thresholds",
        "total",
        "warning",
        "warningCrossings",
        "warningThreshold",
    }
)
_ANALYSER_METRIC_ATTRIBUTES: frozenset[str] = frozenset(
    {
        "column",
        "default_thresholds",
        "distinct_operands",
        "distinct_operators",
        "end_line",
        "end_lineno",
        "files_discovered",
        "files_parsed",
        "function_count",
        "length",
        "line",
        "lineno",
        "metadata",
        "thresholds",
        "total_operands",
        "total_operators",
        "vocabulary",
        "volume",
    }
)
_ANALYSER_METRIC_HELPERS: frozenset[str] = frozenset(
    {
        "cognitive_for",
        "cyclomatic_for",
        "halstead_for",
        "lines_for_size",
        "maintainability_index_for",
        "npath_for",
    }
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
    ignored = (
        _len_count_constants(expr)
        | _analyser_metric_constants(expr)
        | _threshold_keyword_constants(expr)
    )
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


def _analyser_metric_constants(expr: ast.expr) -> set[ast.Constant]:
    ignored: set[ast.Constant] = set()
    for node in ast.walk(expr):
        if not isinstance(node, ast.Compare):
            continue
        operands = [node.left, *node.comparators]
        for left, right in zip(operands, operands[1:], strict=False):
            if _is_analyser_metric_expression(left):
                ignored.update(_int_constants(right))
            if _is_analyser_metric_expression(right):
                ignored.update(_int_constants(left))
    return ignored


def _threshold_keyword_constants(expr: ast.expr) -> set[ast.Constant]:
    ignored: set[ast.Constant] = set()
    for node in ast.walk(expr):
        if not isinstance(node, ast.Call):
            continue
        for keyword in node.keywords:
            if keyword.arg in {"warning", "error", "threshold"}:
                ignored.update(_int_constants(keyword.value))
    return ignored


def _is_analyser_metric_expression(expr: ast.AST) -> bool:
    if isinstance(expr, ast.Call) and _call_name(expr) in _ANALYSER_METRIC_HELPERS:
        return True
    for node in ast.walk(expr):
        if isinstance(node, ast.Attribute) and node.attr in _ANALYSER_METRIC_ATTRIBUTES:
            return True
        if isinstance(node, ast.Subscript):
            key = _string_key(node.slice)
            if key in _ANALYSER_METRIC_KEYS:
                return True
    return False


def _int_constants(expr: ast.AST) -> set[ast.Constant]:
    return {node for node in ast.walk(expr) if _is_int_constant(node)}


def _call_name(call: ast.Call) -> str:
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _string_key(node: ast.AST) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


def _is_len_call(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "len"


def _is_int_constant(node: ast.AST) -> TypeGuard[ast.Constant]:
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, int)
        and not isinstance(node.value, bool)
    )
