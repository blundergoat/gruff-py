from gruffpy.rule.docs.todo_density_rule import TodoDensityRule
from tests.unit.rule.docs._helpers import default_ctx, make_unit


def _marker(*parts: str) -> str:
    """Join parts into one marker word without writing the marker in this file.

    Args:
        parts: Fragments of the marker word.

    Returns:
        The joined marker.
    """
    return "".join(parts)


_DENSE_MARKERS = (
    _marker("TO", "DO"),
    _marker("FIX", "ME"),
    _marker("HAC", "K"),
    _marker("XX", "X"),
    _marker("BU", "G"),
)
_DEFAULT_TODO_DENSITY_THRESHOLD = 10


def _todo_marker() -> str:
    """Return the first marker for use in a fixture with one marker comment.

    Returns:
        That marker word.
    """
    return _DENSE_MARKERS[0]


def _dense_marker_source() -> str:
    """Return source with one comment line per marker word, followed by ten assignments.

    Returns:
        The source text.
    """
    marker_lines = "\n".join(f"# {marker}: marker" for marker in _DENSE_MARKERS)
    return f"{marker_lines}\n" + ("x = 1\n" * 10)


def test_no_markers_emits_nothing():
    """Report nothing for source without markers.

    Returns:
        None. Checks that marker-free source produces no density finding.
    """
    src = "def f():\n    return 1\n"
    assert TodoDensityRule().analyse(make_unit(src), default_ctx()) == []


def test_low_density_emits_nothing():
    """Report nothing for one marker comment followed by 100 assignments.

    Returns:
        None. Checks that the below-threshold marker density produces no finding.
    """
    body = "\n".join(f"x{i} = {i}" for i in range(100))
    src = f"# {_todo_marker()}: refactor\n{body}\n"
    findings = TodoDensityRule().analyse(make_unit(src), default_ctx())
    # One marker across more than 100 lines stays below 10 per thousand, so no finding is expected.
    assert findings == []


def test_high_density_emits():
    """Report five markers once, with a density above 10 per thousand lines.

    Returns:
        None. Checks that one finding reports five markers and a density above 10 per thousand lines.
    """
    src = _dense_marker_source()
    findings = TodoDensityRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["markers"] == 5
    assert findings[0].metadata["densityPer1000"] > 10


def test_rule_defining_docs_file_is_exempt():
    """Report nothing for dense markers at the marker-density rule's own source path.

    Returns:
        None. Checks that dense markers yield no finding when the fixture uses the density rule's own display path.
    """
    src = _dense_marker_source()
    unit = make_unit(src, display_path="src/gruffpy/rule/docs/todo_density_rule.py")

    assert TodoDensityRule().analyse(unit, default_ctx()) == []


def test_same_filename_outside_rule_package_still_emits():
    """Report dense markers in a tools file that shares the marker-density rule's file name.

    Returns:
        None after the assertion succeeds.
    """
    src = _dense_marker_source()
    unit = make_unit(src, display_path="tools/todo_density_rule.py")

    assert TodoDensityRule().analyse(unit, default_ctx())


def test_default_threshold():
    """Default the marker-density threshold to 10.

    Returns:
        None after the assertion succeeds.
    """
    rule = TodoDensityRule()
    assert rule.definition().default_threshold == _DEFAULT_TODO_DENSITY_THRESHOLD
