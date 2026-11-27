import ast
import math

from gruffpy.command.metric_calibration import _maintainability_index_for
from gruffpy.rule.size._lines import code_line_numbers


def _mi(source: str) -> float:
    """Compute the maintainability index of the first top-level, non-async function in source.

    Args:
        source: Python source to parse.

    Returns:
        That function's maintainability index.

    Raises:
        StopIteration: The source has no top-level, non-async function.
    """
    tree = ast.parse(source)
    fn = next(node for node in tree.body if isinstance(node, ast.FunctionDef))
    return _maintainability_index_for(fn, code_line_numbers(source, tree))


def _branched_body(branch_count: int, with_elif: bool = False) -> str:
    """Generate source for a function f with repeated conditional blocks for maintainability index tests.

    Args:
        branch_count: Number of if statements to generate, each paired with an else or elif.
        with_elif: Use an elif and longer arithmetic in both arms when true. The default uses else and simpler arithmetic.

    Returns:
        The function source, which ends by returning x.
    """
    lines: list[str] = []
    for i in range(branch_count):
        lines.append(f"    if a{i} > b{i}:")
        lines.append(f"        x = a{i} + b{i}")
        if with_elif:
            lines.append(f"        x = a{i} + b{i} * c{i} - d{i}")
            lines.append(f"    elif a{i} < b{i}:")
            lines.append(f"        x = a{i} - b{i} / c{i} + d{i}")
        else:
            lines.append("    else:")
            lines.append(f"        x = a{i} - b{i}")
    return "def f():\n" + "\n".join(lines) + "\n    return x\n"


def test_trivial_function_has_max_mi():
    """Give a function that only returns ``x + 1`` the maximum index of 100.

    Returns:
        None. Checks that the short function's reported index is 100.
    """
    src = "def f(x):\n    return x + 1\n"
    mi = _mi(src)
    assert mi == 100.0  # clamped at upper bound


_MI_CLAMP_MAX = 100.0


def test_mi_formula_matches_canonical_values():
    """Verify the upper clamp with a fixture whose hand-calculated maintainability index exceeds the maximum.

    Returns:
        None. Checks that the raw score exceeds the ceiling and the reported score equals it.
    """
    src = "def f(x):\n    return x + 1\n"
    raw = 171 - 5.2 * math.log(4.7548875) - 0.23 * 1 - 16.2 * math.log(2)
    assert raw > _MI_CLAMP_MAX  # A raw score equal to the ceiling would satisfy the output assertion even without clamping.
    assert _mi(src) == _MI_CLAMP_MAX


def test_complex_function_lowers_mi():
    """Score a function with 40 if/else branches below 80.

    Returns:
        None. Checks the generated function's maintainability index against the cutoff of 80.
    """
    src = _branched_body(40)
    mi = _mi(src)
    assert mi < 80.0  # This test's cutoff is higher than the calibration error threshold of 70.


def test_documenting_a_function_leaves_its_index_unchanged():
    """Keep a ten-branch function's index, below 100, unchanged after a long docstring and ten comment lines are added.

    Returns:
        None after the assertions pass.
    """
    plain = _branched_body(10)
    notes = "\n".join(f"    Branch {i} is explained here." for i in range(30))
    comments = "".join(f"    # Step {i}.\n" for i in range(10))
    documented = plain.replace("def f():\n", f'def f():\n    """Pick x from the paired inputs.\n\n{notes}\n    """\n{comments}', 1)
    assert _mi(plain) < 100.0
    assert _mi(documented) == _mi(plain)
