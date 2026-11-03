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
    """Walk a statement, collecting operators from operator-bearing nodes and operands only from their operand sub-trees.

    Args:
        node: Node to scan: a function body statement, a lambda's body expression, or a child reached while descending. A function, lambda or class
            definition reached here is skipped, so nothing inside it adds to the enclosing function's counts.
        operators: Accumulator that receives one operator name per counted operator occurrence, such as Add, or AddAssign for an augmented assignment.
            Operators inside a Call, Subscript or Attribute that is itself an operand are not counted. Mutated in place.
        operands: Accumulator that receives one operand key per operand found inside an operator-bearing node or an augmented assignment. Mutated in
            place.
    """
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
    """Add the operators and operands of one expression sub-tree to the shared accumulators.

    An operator-bearing node (BinOp, UnaryOp, BoolOp or Compare) records its operator names and recurses into its operands. A Name or Constant is
    recorded as one operand. A Call, Subscript or Attribute is recorded as one opaque operand keyed by its unparsed source, so the Names, Constants
    and operators inside it are not counted. Any other node, such as a Tuple, List or IfExp, is descended into, so its own Names, Constants and nested
    operators are counted.

    Args:
        node: Node to count: an operator-bearing node, one of its operand sub-trees or their children, or the target or value of an augmented
            assignment.
        operators: Accumulator that receives the operator names counted in the sub-tree. Mutated in place.
        operands: Accumulator that receives the operand keys counted in the sub-tree. Mutated in place.
    """
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
    """Pick the collector that matches a BinOp, UnaryOp, BoolOp or Compare node, so _collect_operands can hand off to it.

    Args:
        node: Node whose type selects the collector.

    Returns:
        The BinOp, UnaryOp, BoolOp or Compare collector that matches the node type, or None for any other node type, which _collect_operands then
        records as an operand or descends into.
    """
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
    """Record a binary operation's operator name, then collect the operands of its left and right sides.

    Args:
        node: BinOp node chosen by _operator_collector. It is typed as ast.AST to fit the OperandCollector signature.
        operators: Accumulator that receives this operation's operator name plus the operator names counted from either side. Mutated in place.
        operands: Accumulator that receives the operand keys from both sides. Mutated in place.
    """
    assert isinstance(node, ast.BinOp)
    operators.append(type(node.op).__name__)
    _collect_operands(node.left, operators, operands)
    _collect_operands(node.right, operators, operands)


def _collect_unary_operands(node: ast.AST, operators: list[str], operands: list[str]) -> None:
    """Record a unary operation's operator name, then collect operands from its single operand.

    Args:
        node: UnaryOp node chosen by _operator_collector. It is typed as ast.AST to fit the OperandCollector signature.
        operators: Accumulator that receives this operation's operator name plus the operator names counted from its operand. Mutated in place.
        operands: Accumulator that receives the operand keys from the operand sub-tree. Mutated in place.
    """
    assert isinstance(node, ast.UnaryOp)
    operators.append(type(node.op).__name__)
    _collect_operands(node.operand, operators, operands)


def _collect_boolop_operands(node: ast.AST, operators: list[str], operands: list[str]) -> None:
    """Record a boolean operation's operator name once, then collect operands from every value it joins.

    A chain such as a and b and c is one BoolOp node, so it adds one And occurrence and three operands.

    Args:
        node: BoolOp node chosen by _operator_collector. It is typed as ast.AST to fit the OperandCollector signature.
        operators: Accumulator that receives this operation's operator name plus the operator names counted from its values. Mutated in place.
        operands: Accumulator that receives the operand keys from every joined value. Mutated in place.
    """
    assert isinstance(node, ast.BoolOp)
    operators.append(type(node.op).__name__)
    for value in node.values:
        _collect_operands(value, operators, operands)


def _collect_compare_operands(node: ast.AST, operators: list[str], operands: list[str]) -> None:
    """Record one operator name per comparison, then collect operands from the left side and every comparator.

    A chained comparison such as a < b < c adds two Lt occurrences and three operands.

    Args:
        node: Compare node chosen by _operator_collector. It is typed as ast.AST to fit the OperandCollector signature.
        operators: Accumulator that receives one operator name per comparison plus the operator names counted from the compared expressions. Mutated
            in place.
        operands: Accumulator that receives the operand keys from the left side and each comparator. Mutated in place.
    """
    assert isinstance(node, ast.Compare)
    for op in node.ops:
        operators.append(type(op).__name__)
    _collect_operands(node.left, operators, operands)
    for comparator in node.comparators:
        _collect_operands(comparator, operators, operands)


def _has_collected_direct_operand(node: ast.AST, operands: list[str]) -> bool:
    """Record a Name or Constant node as one operand key and report whether the node matched.

    Args:
        node: Node to test. A Name is recorded whatever its load, store or delete context, so an augmented assignment target counts like a read.
        operands: Accumulator that receives the Name identifier, or the repr of the Constant value, as the operand key. Mutated in place only when the
            node matches.

    Returns:
        True when the node was a Name or Constant and its operand key was appended, so the caller stops descending. False when nothing was recorded.
    """
    if isinstance(node, ast.Name):
        operands.append(node.id)
        return True
    if isinstance(node, ast.Constant):
        operands.append(repr(node.value))
        return True
    return False


def _has_collected_opaque_operand(node: ast.AST, operands: list[str]) -> bool:
    """Record a Call, Subscript or Attribute as one opaque operand keyed by its unparsed source.

    The Names, Constants and operators inside such a node are not counted. When ast.unparse raises, the node's class name is recorded as the key
    instead.

    Args:
        node: Expression node to test against the Call, Subscript and Attribute types.
        operands: Accumulator that receives the unparsed source text, or the node class name if unparsing fails, as the operand key. Mutated in place
            only when the node matches.

    Returns:
        True when the node was a Call, Subscript or Attribute and its operand key was appended, so the caller stops descending. False when nothing was
        recorded.
    """
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
