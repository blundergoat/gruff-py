"""Case IDs keep table failures identifiable without decorator-level IDs."""

import pytest

from gruffpy.rule.test_quality.parametrize_annotation_rule import ParametrizeAnnotationRule
from tests.unit.rule.test_quality._helpers import default_ctx, make_unit


@pytest.mark.parametrize(
    ("cases", "expected"),
    [
        ("pytest.param(1, id='one'), pytest.param(2, id='two'), pytest.param(3, id='three')", 0),
        ("pytest.param(1, id='one'), pytest.param(2, id='two'), pytest.param(3)", 1),
        ("pytest.param(1, id='one'), pytest.param(2, id='two'), pytest.param(3, id='')", 1),
        ("pytest.param(1, id='one'), pytest.param(2, id='two'), pytest.param(3, id=None)", 1),
        ("1, 2, 3", 1),
        ("1, 2", 0),
        ("custom.param(1, id='one'), custom.param(2, id='two'), custom.param(3, id='three')", 1),
    ],
    ids=["all-named", "one-unnamed", "empty-id", "none-id", "raw-cases", "small-table", "foreign-case-builder"],
)
def test_case_ids_and_unlabelled_controls(cases: str, expected: int) -> None:
    """Accept complete per-case labels and keep missing labels reportable.

    Args:
        cases: Literal case expressions in the decorator's table.
        expected: Number of annotation findings.

    Returns:
        None.
    """
    source = f"import pytest\n@pytest.mark.parametrize('value', [{cases}])\ndef test_values(value):\n    assert double(value) == value * 2\n"
    findings = ParametrizeAnnotationRule().analyse(make_unit(source), default_ctx())
    assert len(findings) == expected
