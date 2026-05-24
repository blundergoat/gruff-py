import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.complexity._halstead import halstead_for
from gruffpy.rule.complexity.halstead_volume_rule import HalsteadVolumeRule
from gruffpy.rule.context import RuleContext
from gruffpy.source.source_file import SourceFile


def _first_fn(source: str) -> ast.FunctionDef:
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            return node
    raise AssertionError("no function found")


def _make_unit(source: str) -> AnalysisUnit:
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]  # AST parent links
    file = SourceFile(absolute_path="/x.py", display_path="x.py", type="python")
    return AnalysisUnit(file=file, source=source, tree=tree)


def _ctx(warning: int = 180, error: int = 400) -> RuleContext:
    rule = HalsteadVolumeRule()
    config = AnalysisConfig(
        rules={
            rule.definition().id: RuleSettings(
                enabled=True,
                thresholds={"warning": warning, "error": error},
            ),
        }
    )
    return RuleContext(project_root="/", config=config)


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
    assert "AddAssign" in {
        type(node.op).__name__ + "Assign"
        for node in ast.walk(ast.parse(src))
        if isinstance(node, ast.AugAssign)
    }
    assert metrics.total_operators == 1


def test_nested_function_not_included():
    src = "def outer():\n    def inner(a, b):\n        return a + b\n    return inner\n"
    metrics = halstead_for(_first_fn(src))
    # outer's body has no operators
    assert metrics.total_operators == 0


def test_huge_function_emits_finding():
    # Force vocabulary and length high with both BinOps and Compares.
    # Volume well over the error threshold -> finding.
    pairs = "\n".join(
        f"    if a{i} + b{i} == c{i} - d{i}:\n        x{i} = a{i} * b{i} + c{i} / d{i}"
        for i in range(60)
    )
    src = f"def f():\n{pairs}\n"
    findings = HalsteadVolumeRule().analyse(_make_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].severity == Severity.ERROR
    assert findings[0].metadata["halsteadVolume"] > 400


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
