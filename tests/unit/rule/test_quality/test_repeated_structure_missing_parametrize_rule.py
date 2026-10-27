import ast

import pytest

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.finding.finding import Finding
from gruffpy.rule.context import RuleContext
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


def _grouped(src: str, min_group_size: int = 3, display_path: str = "test_x.py") -> list[Finding]:
    """Analyse *src* with ``groupFindings`` on, as the section 16 measurement enables it."""
    settings = RuleSettings(thresholds={"minGroupSize": min_group_size}, options={"groupFindings": True})
    context = RuleContext(project_root="/tmp/no-such-root", config=AnalysisConfig(rules={RepeatedStructureMissingParametrizeRule.ID: settings}))
    return RepeatedStructureMissingParametrizeRule().analyse(make_unit(src, display_path), context)


def test_group_findings_reports_one_finding_listing_every_member():
    src = """
def test_parses_small():
    value = parse("1")
    assert value == 1

def test_parses_medium():
    value = parse("25")
    assert value == 25

def test_parses_large():
    value = parse("300")
    assert value == 300
"""
    findings = _grouped(src)
    assert [(f.symbol, f.line, f.metadata["groupSize"]) for f in findings] == [("test_parses_small", 2, 3)]
    assert [m["symbol"] for m in findings[0].metadata["members"]] == ["test_parses_small", "test_parses_medium", "test_parses_large"]
    assert "'test_parses_large' (line 10)" in findings[0].message
    assert "@pytest.mark.parametrize` test with a descriptive label per case" in findings[0].message
    assert len(RepeatedStructureMissingParametrizeRule().analyse(make_unit(src), default_ctx())) == 3


def test_group_findings_pair_reports_only_when_min_group_size_is_two():
    src = """
def test_rounds_down():
    value = round_cents(1.004)
    assert value == 1.0

def test_rounds_up():
    value = round_cents(1.006)
    assert value == 1.01
"""
    assert _grouped(src) == []
    assert [f.metadata["groupSize"] for f in _grouped(src, min_group_size=2)] == [2]


def test_group_findings_splits_groups_on_a_differing_own_decorator():
    src = """
def test_reads_a():
    row = read("a")
    assert row.ok

def test_reads_b():
    row = read("b")
    assert row.ok

def test_reads_c():
    row = read("c")
    assert row.ok

@pytest.mark.slow
def test_reads_d():
    row = read("d")
    assert row.ok

@pytest.mark.slow
def test_reads_e():
    row = read("e")
    assert row.ok

@pytest.mark.slow
def test_reads_f():
    row = read("f")
    assert row.ok
"""
    assert [(f.symbol, f.metadata["groupSize"]) for f in _grouped(src)] == [("test_reads_a", 3), ("test_reads_d", 3)]


def test_group_findings_splits_groups_on_a_differing_class_decorator():
    src = """
class TestLocal:
    def test_reads_a(self):
        row = read("a")
        assert row.ok

    def test_reads_b(self):
        row = read("b")
        assert row.ok

    def test_reads_c(self):
        row = read("c")
        assert row.ok

@pytest.mark.network
class TestRemote:
    def test_reads_d(self):
        row = read("d")
        assert row.ok

    def test_reads_e(self):
        row = read("e")
        assert row.ok

    def test_reads_f(self):
        row = read("f")
        assert row.ok
"""
    assert [(f.symbol, f.metadata["groupSize"]) for f in _grouped(src)] == [("TestLocal.test_reads_a", 3), ("TestRemote.test_reads_d", 3)]


@pytest.mark.parametrize("other_class", ["TestRemote", "TestLocal"])
def test_group_findings_keeps_distinct_class_containers_separate(other_class: str):
    src = f"""
class TestLocal:
    def test_reads_a(self):
        row = read("a")
        assert row.ok

    def test_reads_b(self):
        row = read("b")
        assert row.ok

class {other_class}:
    def test_reads_c(self):
        row = read("c")
        assert row.ok
"""
    assert _grouped(src) == []


@pytest.mark.parametrize("whitespace", [" ", "\t", "\n", "\r", "\f", "\v"])
def test_group_findings_keeps_whitespace_text_exact(whitespace: str):
    src = "\n\n".join(
        f"def test_case_{index}():\n    value = parse({('payload' + whitespace + str(index))!r})\n    assert value.ok" for index in range(3)
    )
    assert _grouped(src) == []


def test_group_findings_keeps_interpolated_text_exact():
    src = "\n\n".join(f'def test_case_{index}():\n    value = parse(f"payload {index}: {{field}}")\n    assert value.ok' for index in range(3))
    assert _grouped(src) == []


@pytest.mark.parametrize(
    "expression",
    [
        '{{"field_{index}": 1}}',
        'record["field_{index}"]',
        "record[{index}]",
        "record[{index}:]",
    ],
)
def test_group_findings_keeps_literal_keys_and_indices_exact(expression: str):
    src = "\n\n".join(f"def test_case_{index}():\n    value = {expression.format(index=index)}\n    assert value" for index in range(3))
    assert _grouped(src) == []


@pytest.mark.parametrize(
    "values",
    [
        ("same payload", "same payload", "same payload"),
        (b"payload a", b"payload b", b"payload c"),
        ("payload\x1ca", "payload\x1cb", "payload\x1cc"),
    ],
)
def test_group_findings_still_normalizes_eligible_literal_values(values: tuple[str | bytes, ...]):
    src = "\n\n".join(f"def test_case_{index}():\n    value = parse({value!r})\n    assert value == {index}" for index, value in enumerate(values))
    assert [finding.metadata["groupSize"] for finding in _grouped(src)] == [3]


def test_group_findings_still_normalizes_dictionary_values():
    src = "\n\n".join(f'def test_case_{index}():\n    value = {{"field": {index}}}\n    assert value' for index in range(3))
    assert [finding.metadata["groupSize"] for finding in _grouped(src)] == [3]


def test_group_findings_skips_one_statement_bodies_after_the_docstring():
    src = '''
def test_accepts_small_amount():
    """A small amount is positive."""
    assert is_positive_amount(100)

def test_accepts_medium_amount():
    """A medium amount is positive."""
    assert is_positive_amount(250)

def test_accepts_large_amount():
    """A large amount is positive."""
    assert is_positive_amount(1000)
'''
    assert _grouped(src) == []


def test_group_findings_groups_tests_sharing_one_call_decorator():
    src = """
@patch("app.clock.now")
def test_stamps_morning(now):
    now.return_value = 9
    assert stamp() == "am"

@patch("app.clock.now")
def test_stamps_noon(now):
    now.return_value = 12
    assert stamp() == "pm"

@patch("app.clock.now")
def test_stamps_evening(now):
    now.return_value = 19
    assert stamp() == "pm"
"""
    assert [f.metadata["groupSize"] for f in _grouped(src)] == [3]


def test_group_findings_keeps_literal_kinds_significant():
    src = """
def test_loads_text():
    value = load("7")
    assert value.ok

def test_loads_number():
    value = load(7)
    assert value.ok
"""
    assert _grouped(src, min_group_size=2) == []


def test_group_findings_keeps_callees_significant():
    src = """
def test_loads_fresh():
    value = load("7")
    assert value.ok

def test_loads_cached():
    value = load_cached("8")
    assert value.ok
"""
    assert _grouped(src, min_group_size=2) == []


def test_group_findings_ignores_conftest_fixtures_and_helpers():
    src = """
def make_alpha():
    item = build("alpha")
    return item

def make_beta():
    item = build("beta")
    return item

def make_gamma():
    item = build("gamma")
    return item
"""
    assert _grouped(src, display_path="conftest.py") == []


def test_group_findings_leaves_parametrized_tests_out():
    src = """
@pytest.mark.parametrize("text", ["1", "2"], ids=["one", "two"])
def test_parses_decimal(text):
    value = parse(text, base=10)
    assert value.ok

@pytest.mark.parametrize("text", ["1", "2"], ids=["one", "two"])
def test_parses_hex(text):
    value = parse(text, base=16)
    assert value.ok

@pytest.mark.parametrize("text", ["1", "2"], ids=["one", "two"])
def test_parses_octal(text):
    value = parse(text, base=8)
    assert value.ok
"""
    assert _grouped(src) == []


def test_group_findings_names_subtest_for_unittest_groups():
    src = """
class ParseTest(unittest.TestCase):
    def test_small(self):
        value = parse("1")
        self.assertEqual(value, 1)

    def test_medium(self):
        value = parse("25")
        self.assertEqual(value, 25)

    def test_large(self):
        value = parse("300")
        self.assertEqual(value, 300)
"""
    findings = _grouped(src)
    assert len(findings) == 1
    assert "self.subTest(...)" in findings[0].message


def test_group_findings_leaves_subtest_and_literal_loop_tests_out():
    src = """
def test_parses_decimal_table():
    parser = make_parser(10)
    for text, expected in [("1", 1), ("2", 2)]:
        assert parser(text) == expected

def test_parses_hex_table():
    parser = make_parser(16)
    for text, expected in [("a", 10), ("b", 11)]:
        assert parser(text) == expected

def test_parses_octal_table():
    parser = make_parser(8)
    for text, expected in [("7", 7), ("10", 8)]:
        assert parser(text) == expected

class ParseTest(unittest.TestCase):
    def test_decimal(self):
        parser = make_parser(10)
        with self.subTest(text="1"):
            self.assertEqual(parser("1"), 1)

    def test_hex(self):
        parser = make_parser(16)
        with self.subTest(text="a"):
            self.assertEqual(parser("a"), 10)

    def test_octal(self):
        parser = make_parser(8)
        with self.subTest(text="7"):
            self.assertEqual(parser("7"), 7)
"""
    assert _grouped(src) == []


def test_group_findings_leaves_class_and_module_parametrized_tests_out():
    class_src = """
@pytest.mark.parametrize("backend", ["sqlite", "postgres"])
class TestStore:
    def test_saves_small(self, backend):
        store = open_store(backend)
        assert store.save(1)

    def test_saves_medium(self, backend):
        store = open_store(backend)
        assert store.save(25)

    def test_saves_large(self, backend):
        store = open_store(backend)
        assert store.save(300)
"""
    module_src = """
pytestmark = [pytest.mark.parametrize("backend", ["sqlite", "postgres"])]

def test_loads_small(backend):
    store = open_store(backend)
    assert store.load(1)

def test_loads_medium(backend):
    store = open_store(backend)
    assert store.load(25)

def test_loads_large(backend):
    store = open_store(backend)
    assert store.load(300)
"""
    assert _grouped(class_src) == []
    assert _grouped(module_src) == []


def test_group_findings_splits_groups_on_a_differing_class_pytestmark():
    src = """
class TestLocal:
    def test_reads_a(self):
        row = read("a")
        assert row.ok

    def test_reads_b(self):
        row = read("b")
        assert row.ok

    def test_reads_c(self):
        row = read("c")
        assert row.ok

class TestRemote:
    pytestmark = pytest.mark.network

    def test_reads_d(self):
        row = read("d")
        assert row.ok

    def test_reads_e(self):
        row = read("e")
        assert row.ok

    def test_reads_f(self):
        row = read("f")
        assert row.ok
"""
    assert [(f.symbol, f.metadata["groupSize"]) for f in _grouped(src)] == [("TestLocal.test_reads_a", 3), ("TestRemote.test_reads_d", 3)]


def test_group_findings_never_mixes_unittest_and_pytest_tests():
    src = """
class ParseTest(unittest.TestCase):
    def test_small(self):
        value = parse("1")
        assert value.ok

    def test_medium(self):
        value = parse("25")
        assert value.ok

    def test_large(self):
        value = parse("300")
        assert value.ok

def test_parses_small():
    value = parse("2")
    assert value.ok

def test_parses_medium():
    value = parse("26")
    assert value.ok

def test_parses_large():
    value = parse("301")
    assert value.ok
"""
    findings = _grouped(src)
    assert [(f.metadata["groupSize"], "self.subTest(...)" in f.message) for f in findings] == [(3, True), (3, False)]


@pytest.mark.parametrize(
    ("body", "expected_groups"),
    [
        pytest.param("def helper():\n    return {n}\nvalue = helper()\nassert value", 0, id="nested_function"),
        pytest.param("async def helper():\n    return {n}\nvalue = helper()\nassert value", 0, id="nested_async_function"),
        pytest.param("class Helper:\n    value = {n}\nvalue = Helper.value\nassert value", 0, id="nested_class"),
        pytest.param("if ready:\n    def helper():\n        return {n}\nvalue = helper()\nassert value", 0, id="declaration_in_block"),
        pytest.param('def helper():\n    """case{n}"""\n    return 1\nvalue = helper()\nassert value', 0, id="nested_documentation"),
        pytest.param("@mark.case({n})\ndef helper():\n    return 1\nvalue = helper()\nassert value", 0, id="body_decorator"),
        pytest.param("helper = lambda: {n}\nvalue = helper()\nassert value", 1, id="lambda_values"),
        pytest.param("def helper():\n    return 1\nvalue = read({n})\nassert value", 1, id="identical_declaration"),
        pytest.param(
            'type Token = "Alias{n}"\nvalue = read(1)\nassert value',
            0,
            id="type_alias",
            marks=pytest.mark.skipif(not hasattr(ast, "TypeAlias"), reason="requires Python 3.12 syntax"),
        ),
    ],
)
def test_group_findings_keep_body_declarations_exact(body: str, expected_groups: int):
    source = "\n\n".join(f"def test_case_{index}():\n" + "\n".join("    " + line for line in body.format(n=index).splitlines()) for index in range(3))
    findings = _grouped(source)
    assert len(findings) == expected_groups
    if findings:
        assert findings[0].metadata["groupSize"] == 3
