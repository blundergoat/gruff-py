from gruffpy.rule.docs.todo_density_rule import TodoDensityRule
from tests.unit.rule.docs._helpers import default_ctx, make_unit


def _marker(*parts: str) -> str:
    return "".join(parts)


_DENSE_MARKERS = (
    _marker("TO", "DO"),
    _marker("FIX", "ME"),
    _marker("HAC", "K"),
    _marker("XX", "X"),
    _marker("BU", "G"),
)


def _todo_marker() -> str:
    return _DENSE_MARKERS[0]


def _dense_marker_source() -> str:
    marker_lines = "\n".join(f"# {marker}: marker" for marker in _DENSE_MARKERS)
    return f"{marker_lines}\n" + ("x = 1\n" * 10)


def test_no_markers_emits_nothing():
    src = "def f():\n    return 1\n"
    assert TodoDensityRule().analyse(make_unit(src), default_ctx()) == []


def test_low_density_emits_nothing():
    body = "\n".join(f"x{i} = {i}" for i in range(100))
    src = f"# {_todo_marker()}: refactor\n{body}\n"
    findings = TodoDensityRule().analyse(make_unit(src), default_ctx())
    # 1 marker in ~101 lines = ~10/1000 — at threshold, NOT above. No finding.
    assert findings == []


def test_high_density_emits():
    src = _dense_marker_source()
    findings = TodoDensityRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["markers"] == 5
    assert findings[0].metadata["densityPer1000"] > 10


def test_rule_defining_docs_file_is_exempt():
    src = _dense_marker_source()
    unit = make_unit(src, display_path="src/gruffpy/rule/docs/todo_density_rule.py")

    assert TodoDensityRule().analyse(unit, default_ctx()) == []


def test_rule_defining_commented_out_code_file_is_exempt():
    src = _dense_marker_source()
    unit = make_unit(src, display_path="src/gruffpy/rule/waste/commented_out_code_rule.py")

    assert TodoDensityRule().analyse(unit, default_ctx()) == []


def test_same_filename_outside_rule_package_still_emits():
    src = _dense_marker_source()
    unit = make_unit(src, display_path="tools/todo_density_rule.py")

    assert TodoDensityRule().analyse(unit, default_ctx())


def test_default_threshold():
    rule = TodoDensityRule()
    assert rule.definition().default_thresholds == {"warning": 10, "error": 10}
