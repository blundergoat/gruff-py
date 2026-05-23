"""Halstead operator/operand counter for complexity rules.

Approximation of radon's `HalsteadVisitor` (radon 6.0.1). Aims for ±10%
Halstead-volume delta on the gruff-py fixtures (see
``tests/fixtures/complexity/radon_ground_truth.md``).

Definitions:

- **Operators**: ``ast.operator`` instances (the `op` field of BinOp,
  AugAssign), ``ast.unaryop`` (UnaryOp.op), ``ast.cmpop`` (each in
  Compare.ops), ``ast.boolop`` (BoolOp.op).
- **Operands**: each ``ast.Name`` occurrence (Load and Store contexts) and
  each ``ast.Constant`` occurrence in the function body. Function parameter
  names in the signature are NOT counted (they are declarations, not
  expressions). Names that ARE the function itself (i.e. recursion calls)
  are counted like any other Name.

Keywords (``if``, ``return``, ``for``, etc.) are NOT counted as operators -
this matches radon's expression-focused interpretation.
"""

import ast
import math
from collections.abc import Callable
from dataclasses import dataclass

from gruffpy.rule.complexity._walks import FunctionLike

OperandCollector = Callable[[ast.AST, list[str], list[str]], None]


@dataclass(frozen=True)
class HalsteadMetrics:
    """Aggregated Halstead counts for one function-like node.

    Attributes:
        distinct_operators: Number of unique operators.
        distinct_operands: Number of unique operands.
        total_operators: Total operator occurrences.
        total_operands: Total operand occurrences.
    """

    distinct_operators: int  # η1
    distinct_operands: int  # η2
    total_operators: int  # N1
    total_operands: int  # N2

    @property
    def vocabulary(self) -> int:
        """Return the number of distinct operators plus operands.

        Returns:
            Halstead vocabulary size.
        """
        return self.distinct_operators + self.distinct_operands

    @property
    def length(self) -> int:
        """Return the total operator plus operand occurrences.

        Returns:
            Halstead program length.
        """
        return self.total_operators + self.total_operands

    @property
    def volume(self) -> float:
        """Return the Halstead volume for the collected counts.

        Returns:
            Halstead volume, or zero when vocabulary is too small to score.
        """
        if self.vocabulary <= 1:
            return 0.0
        return self.length * math.log2(self.vocabulary)


_HALSTEAD_CACHE_ATTR = "_gruffpy_halstead_metrics"


def halstead_for(fn: FunctionLike) -> HalsteadMetrics:
    """Compute Halstead metrics for a function-like node's body.

    Operands are only counted when they appear inside an operator-bearing
    expression (BinOp, UnaryOp, BoolOp, Compare, AugAssign). Bare Names and
    Constants in statements (``return x``, ``x = 1``) do NOT contribute -
    matching radon's expression-focused interpretation.

    Args:
        fn: Function, async function, or lambda node to score.

    Returns:
        Halstead metrics for the node body.
    """
    cached = getattr(fn, _HALSTEAD_CACHE_ATTR, None)
    if isinstance(cached, HalsteadMetrics):
        return cached

    operators: list[str] = []
    operands: list[str] = []

    body: list[ast.AST] = [fn.body] if isinstance(fn, ast.Lambda) else list(fn.body)

    for stmt in body:
        _walk_stmt(stmt, operators, operands)

    metrics = HalsteadMetrics(
        distinct_operators=len(set(operators)),
        distinct_operands=len(set(operands)),
        total_operators=len(operators),
        total_operands=len(operands),
    )
    setattr(fn, _HALSTEAD_CACHE_ATTR, metrics)
    return metrics


def _walk_stmt(node: ast.AST, operators: list[str], operands: list[str]) -> None:
    """Walk a statement; collect operators from operator-bearing nodes and
    operands only from inside those nodes' operand sub-trees."""
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda | ast.ClassDef):
        return
    if isinstance(node, ast.AugAssign):
        operators.append(type(node.op).__name__ + "Assign")
        _collect_operands(node.target, operators, operands)
        _collect_operands(node.value, operators, operands)
        return
    if isinstance(node, ast.BinOp | ast.UnaryOp | ast.BoolOp | ast.Compare):
        _collect_operands(node, operators, operands)
        return
    # Statement-level node: keep descending into children
    for child in ast.iter_child_nodes(node):
        _walk_stmt(child, operators, operands)


def _collect_operands(node: ast.AST, operators: list[str], operands: list[str]) -> None:
    """Recurse into an operator-rooted expression, accumulating operators and
    operands. Nested operator nodes contribute their own operators and their
    own operands; nested non-operator nodes (Calls, Subscripts, etc.) are
    treated as opaque operand atoms via their constituent Names/Constants."""
    operator_collector = _operator_collector(node)
    if operator_collector is not None:
        operator_collector(node, operators, operands)
        return
    if _has_collected_direct_operand(node, operands):
        return
    if _has_collected_opaque_operand(node, operands):
        return
    for child in ast.iter_child_nodes(node):
        _collect_operands(child, operators, operands)


def _operator_collector(node: ast.AST) -> OperandCollector | None:
    if isinstance(node, ast.BinOp):
        return _collect_binop_operands
    if isinstance(node, ast.UnaryOp):
        return _collect_unary_operands
    if isinstance(node, ast.BoolOp):
        return _collect_boolop_operands
    if isinstance(node, ast.Compare):
        return _collect_compare_operands
    return None


def _collect_binop_operands(node: ast.AST, operators: list[str], operands: list[str]) -> None:
    assert isinstance(node, ast.BinOp)
    operators.append(type(node.op).__name__)
    _collect_operands(node.left, operators, operands)
    _collect_operands(node.right, operators, operands)


def _collect_unary_operands(node: ast.AST, operators: list[str], operands: list[str]) -> None:
    assert isinstance(node, ast.UnaryOp)
    operators.append(type(node.op).__name__)
    _collect_operands(node.operand, operators, operands)


def _collect_boolop_operands(node: ast.AST, operators: list[str], operands: list[str]) -> None:
    assert isinstance(node, ast.BoolOp)
    operators.append(type(node.op).__name__)
    for value in node.values:
        _collect_operands(value, operators, operands)


def _collect_compare_operands(node: ast.AST, operators: list[str], operands: list[str]) -> None:
    assert isinstance(node, ast.Compare)
    for op in node.ops:
        operators.append(type(op).__name__)
    _collect_operands(node.left, operators, operands)
    for comparator in node.comparators:
        _collect_operands(comparator, operators, operands)


def _has_collected_direct_operand(node: ast.AST, operands: list[str]) -> bool:
    if isinstance(node, ast.Name):
        operands.append(node.id)
        return True
    if isinstance(node, ast.Constant):
        operands.append(repr(node.value))
        return True
    return False


def _has_collected_opaque_operand(node: ast.AST, operands: list[str]) -> bool:
    # Call / Subscript / Attribute / Tuple / etc. - treat as opaque operand
    # atoms keyed by their `ast.unparse` representation. This matches radon's
    # behaviour: ``f(x) + g(x)`` contributes 2 operand atoms, not 4.
    if isinstance(node, ast.Call | ast.Subscript | ast.Attribute):
        try:
            operands.append(ast.unparse(node))
        except Exception:  # pragma: no cover - ast.unparse rarely raises on valid source nodes
            operands.append(type(node).__name__)
        return True
    return False
