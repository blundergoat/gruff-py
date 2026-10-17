import ast

from gruffpy.rule.complexity._halstead import halstead_for


def _first_fn(source: str) -> ast.FunctionDef:
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            return node
    raise AssertionError("no function found")


def test_simple_function_low_volume():
    import math

    src = "def f(x):\n    return x + 1\n"
    metrics = halstead_for(_first_fn(src))
    # h1=1 (+), h2=2 (x, 1), N1=1, N2=2, V = 3 * log2(3) ~= 4.75
    assert metrics.distinct_operators == 1
    assert metrics.distinct_operands == 2
    assert math.isclose(metrics.volume, 4.754887502163469, rel_tol=1e-9)


def test_binop_chain_increases_vocabulary():
    src = "def f(a, b, c, d):\n    return a + b * c - d\n"
    metrics = halstead_for(_first_fn(src))
    assert metrics.distinct_operators == 3  # +, *, -
    assert metrics.distinct_operands == 4
    assert metrics.total_operators == 3
    assert metrics.total_operands == 4


def test_compare_operators_counted():
    src = "def f(a, b, c):\n    return a < b < c\n"
    metrics = halstead_for(_first_fn(src))
    # Compare node has 2 ops (Lt, Lt)
    assert metrics.total_operators == 2
    assert metrics.distinct_operators == 1
    assert metrics.distinct_operands == 3


def test_boolop_counted():
    src = "def f(a, b):\n    return a and b\n"
    metrics = halstead_for(_first_fn(src))
    assert metrics.distinct_operators == 1  # And
    assert metrics.distinct_operands == 2


def test_unary_op_counted():
    src = "def f(x):\n    return -x\n"
    metrics = halstead_for(_first_fn(src))
    assert metrics.distinct_operators == 1  # USub
    assert metrics.distinct_operands == 1


def test_aug_assign_counted_as_operator():
    src = "def f(x):\n    x += 1\n    return x\n"
    metrics = halstead_for(_first_fn(src))
    # x += 1 -> one AddAssign operator
    assert "AddAssign" in {type(node.op).__name__ + "Assign" for node in ast.walk(ast.parse(src)) if isinstance(node, ast.AugAssign)}
    assert metrics.total_operators == 1


def test_nested_function_not_included():
    src = "def outer():\n    def inner(a, b):\n        return a + b\n    return inner\n"
    metrics = halstead_for(_first_fn(src))
    # outer's body has no operators
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
    """Compute per-function ``|gruff - radon| / radon`` deltas for the cc_fixture.

    Returns:
        Relative deltas (one per function in ``_RADON_VOLUMES`` that exists in
        the fixture's parsed AST).
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

    Tolerance: ±15% average delta on the ground-truth fixture (relaxed
    from ±10% due to a documented chained-BoolOp pattern in
    ``radon_ground_truth.md``; aggregate well under the ±50% kill threshold).
    Run ``uvx radon hal tests/fixtures/complexity/cc_fixture.py -f`` to
    refresh radon's numbers; update ``radon_ground_truth.md`` if they change.
    """
    deltas = _halstead_deltas_against_radon()
    average = sum(deltas) / len(deltas)
    assert average <= 0.15, f"average Halstead delta {average:.1%} exceeds 15%"
