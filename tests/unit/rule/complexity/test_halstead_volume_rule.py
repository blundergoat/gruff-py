import ast

from gruffpy.rule.complexity._halstead import halstead_for


def _first_fn(source: str) -> ast.FunctionDef:
    """Return the first top-level, non-async function definition in source.

    Args:
        source: Python source to parse.

    Returns:
        That function definition.

    Raises:
        AssertionError: The source has no top-level, non-async function.
    """
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            return node
    raise AssertionError("no function found")


def test_simple_function_low_volume():
    """Measure x + 1 as one distinct operator and two distinct operands with a volume of about 4.75.

    Returns:
        None after the assertions pass.
    """
    import math

    src = "def f(x):\n    return x + 1\n"
    metrics = halstead_for(_first_fn(src))
    # h1=1 (+), h2=2 (x, 1), N1=1, N2=2, V = 3 * log2(3) ~= 4.75
    assert metrics.distinct_operators == 1
    assert metrics.distinct_operands == 2
    assert math.isclose(metrics.volume, 4.754887502163469, rel_tol=1e-9)


def test_binop_chain_increases_vocabulary():
    """Count three operators and four operands in a + b * c - d, all of them distinct.

    Returns:
        None. Checks that the total and distinct counts agree for both operators and operands.
    """
    src = "def f(a, b, c, d):\n    return a + b * c - d\n"
    metrics = halstead_for(_first_fn(src))
    assert metrics.distinct_operators == 3  # +, *, -
    assert metrics.distinct_operands == 4
    assert metrics.total_operators == 3
    assert metrics.total_operands == 4


def test_compare_operators_counted():
    """Count a < b < c as two less-than operators, one distinct, and three distinct operands.

    Returns:
        None after the assertions pass.
    """
    src = "def f(a, b, c):\n    return a < b < c\n"
    metrics = halstead_for(_first_fn(src))
    # Compare node has 2 ops (Lt, Lt)
    assert metrics.total_operators == 2
    assert metrics.distinct_operators == 1
    assert metrics.distinct_operands == 3


def test_boolop_counted():
    """Count ``a and b`` as one distinct operator and two distinct operands.

    Returns:
        None. Checks the distinct operator and operand counts for a Boolean conjunction.
    """
    src = "def f(a, b):\n    return a and b\n"
    metrics = halstead_for(_first_fn(src))
    assert metrics.distinct_operators == 1  # And
    assert metrics.distinct_operands == 2


def test_unary_op_counted():
    """Count ``-x`` as one distinct operator and one distinct operand.

    Returns:
        None. Checks the distinct operator and operand counts for unary minus.
    """
    src = "def f(x):\n    return -x\n"
    metrics = halstead_for(_first_fn(src))
    assert metrics.distinct_operators == 1  # USub
    assert metrics.distinct_operands == 1


def test_aug_assign_counted_as_operator():
    """Count one operator in total for a function that applies x += 1 and returns x.

    Returns:
        None after the assertions pass.
    """
    src = "def f(x):\n    x += 1\n    return x\n"
    metrics = halstead_for(_first_fn(src))
    assert "AddAssign" in {type(node.op).__name__ + "Assign" for node in ast.walk(ast.parse(src)) if isinstance(node, ast.AugAssign)}
    assert metrics.total_operators == 1


def test_nested_function_not_included():
    """Count no operators for an outer function whose only operator is in its nested function.

    Returns:
        None after the assertion passes.
    """
    src = "def outer():\n    def inner(a, b):\n        return a + b\n    return inner\n"
    metrics = halstead_for(_first_fn(src))
    assert metrics.total_operators == 0


_RADON_VOLUMES = {
    "simple": 4.75,
    "with_branches": 20.68,
    "with_loop": 13.93,
    "with_boolops": 15.51,
    "with_comprehension": 13.93,
    "a1": 4.75,
    "a2": 9.51,
}


def _halstead_deltas_against_radon() -> list[float]:
    """Compute absolute relative Halstead volume errors against radon for the cc_fixture.

    Returns:
        Relative deltas, one per non-async function in _RADON_VOLUMES found in the fixture's parsed AST.
    """
    from pathlib import Path

    fixture = Path(__file__).resolve().parents[3] / "fixtures" / "complexity" / "cc_fixture.py"
    tree = ast.parse(fixture.read_text())
    return [
        abs(halstead_for(node).volume - _RADON_VOLUMES[node.name]) / _RADON_VOLUMES[node.name]
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name in _RADON_VOLUMES
    ]


def test_radon_delta_within_threshold():
    """Cross-check Halstead volume against radon 6.0.1 ground-truth.

    Allow at most 15% average absolute relative error on the reference fixture.
    Refresh _RADON_VOLUMES and radon_ground_truth.md with output from uvx radon@6.0.1 hal tests/fixtures/complexity/cc_fixture.py -f.

    Returns:
        None. Checks that the mean absolute relative difference from the stored Radon volumes is at most 15%.
    """
    deltas = _halstead_deltas_against_radon()
    average = sum(deltas) / len(deltas)
    assert average <= 0.15, f"average Halstead delta {average:.1%} exceeds 15%"
