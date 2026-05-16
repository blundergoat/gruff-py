from gruffpy.rule.test_quality.repeated_structure_missing_parametrize_rule import (
    RepeatedStructureMissingParametrizeRule,
)
from tests.unit.rule.test_quality._helpers import default_ctx, make_unit


def test_repeated_same_helper_shape_emits():
    src = """
def test_alpha():
    assert classify("a") == "alpha"

def test_beta():
    assert classify("b") == "beta"

def test_gamma():
    assert classify("g") == "gamma"
"""
    findings = RepeatedStructureMissingParametrizeRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 3
    assert {finding.metadata["groupSize"] for finding in findings} == {3}


def test_same_statement_shape_with_different_helpers_skipped():
    src = """
def test_cyclomatic():
    assert cyclomatic_for(source) == 2

def test_cognitive():
    assert cognitive_for(source) == 2

def test_nesting():
    assert nesting_depth_for(source) == 2
"""
    findings = RepeatedStructureMissingParametrizeRule().analyse(make_unit(src), default_ctx())
    assert findings == []


def test_same_harness_with_different_multiline_source_fixtures_skipped():
    src = '''
def test_if_score():
    source = """def f():
    if value:
        return 1
    return 0
"""
    assert score(source) == 2

def test_for_score():
    source = """def f():
    for item in items:
        print(item)
"""
    assert score(source) == 2

def test_try_score():
    source = """def f():
    try:
        work()
    except ValueError:
        return 0
"""
    assert score(source) == 2
'''
    findings = RepeatedStructureMissingParametrizeRule().analyse(make_unit(src), default_ctx())
    assert findings == []


def test_same_statement_shape_with_different_attributes_skipped():
    src = """
def test_json_reporter():
    assert JsonReporter().render(report) == "ok"

def test_text_reporter():
    assert TextReporter().render(report) == "ok"

def test_markdown_reporter():
    assert MarkdownReporter().render(report) == "ok"
"""
    findings = RepeatedStructureMissingParametrizeRule().analyse(make_unit(src), default_ctx())
    assert findings == []


def test_decorated_tests_skipped():
    src = """
@pytest.mark.parametrize("value", ["a", "b", "c"])
def test_alpha(value):
    assert classify(value) == "alpha"

def test_beta():
    assert classify("b") == "beta"

def test_gamma():
    assert classify("g") == "gamma"
"""
    findings = RepeatedStructureMissingParametrizeRule().analyse(make_unit(src), default_ctx())
    assert findings == []
