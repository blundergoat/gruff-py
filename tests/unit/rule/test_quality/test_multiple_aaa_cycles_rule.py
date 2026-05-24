"""Focused tests for the refined ``multiple-aaa-cycles`` heuristic.

The rule counts a non-assertion statement as a cycle boundary only when it
contains a function call. Pure data-access (attribute, subscript,
literal/dict-comp restructuring) between asserts does not count - it is
treated as continuation of the same assertion phase.
"""

from gruffpy.rule.test_quality.multiple_aaa_cycles_rule import MultipleAaaCyclesRule
from tests.unit.rule.test_quality._helpers import default_ctx, make_unit


def test_subscript_unpacking_between_asserts_does_not_fire():
    src = (
        "def test_foo():\n"
        "    findings = run_rule()\n"
        "    assert len(findings) == 1\n"
        "    finding = findings[0]\n"
        "    assert finding.severity == 'warning'\n"
        "    metadata = {k: finding.metadata[k] for k in ('lines',)}\n"
        "    assert metadata == {'lines': 10}\n"
    )
    assert MultipleAaaCyclesRule().analyse(make_unit(src), default_ctx()) == []


def test_attribute_access_between_asserts_does_not_fire():
    src = (
        "def test_foo():\n"
        "    tree = parse('x = 1')\n"
        "    assign = tree.body[0]\n"
        "    assert isinstance(assign, Assign)\n"
        "    target = assign.targets[0]\n"
        "    assert target.id == 'x'\n"
    )
    assert MultipleAaaCyclesRule().analyse(make_unit(src), default_ctx()) == []


def test_response_unpacking_pattern_does_not_fire():
    src = (
        "def test_foo():\n"
        "    result = invoke_cli()\n"
        "    assert result.exit_code == 0\n"
        "    payload = json.loads(result.output)\n"
        "    assert 'summary' in payload\n"
        "    summary = payload['summary']\n"
        "    elapsed = summary['elapsedSeconds']\n"
        "    assert summary['paths'] == ['src']\n"
        "    assert elapsed >= 0\n"
    )
    assert MultipleAaaCyclesRule().analyse(make_unit(src), default_ctx()) == []


def test_three_distinct_calls_between_asserts_fires():
    src = (
        "def test_foo():\n"
        "    first = exercise()\n"
        "    assert first == 1\n"
        "    second = exercise()\n"
        "    assert second == 2\n"
        "    third = exercise()\n"
        "    assert third == 3\n"
    )
    findings = MultipleAaaCyclesRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["cycles"] == 3


def test_one_call_boundary_with_access_only_tail_does_not_fire():
    src = (
        "def test_foo():\n"
        "    a = call_one()\n"
        "    assert a == 1\n"
        "    b = call_two()\n"
        "    assert b == 2\n"
        "    inner = b.payload\n"
        "    deeper = inner['key']\n"
        "    assert deeper == 'value'\n"
    )
    assert MultipleAaaCyclesRule().analyse(make_unit(src), default_ctx()) == []


def test_literal_only_statements_do_not_count_as_cycles():
    src = (
        "def test_foo():\n"
        "    x = 1\n"
        "    assert x == 1\n"
        "    y = 2\n"
        "    assert y == 2\n"
        "    z = 3\n"
        "    assert z == 3\n"
    )
    assert MultipleAaaCyclesRule().analyse(make_unit(src), default_ctx()) == []


def test_nested_def_between_asserts_does_not_end_cycle():
    src = (
        "def test_foo():\n"
        "    a = run()\n"
        "    assert a == 1\n"
        "    def helper():\n"
        "        return foo()\n"
        "    assert helper.__name__ == 'helper'\n"
    )
    assert MultipleAaaCyclesRule().analyse(make_unit(src), default_ctx()) == []


def test_lambda_between_asserts_does_not_end_cycle():
    src = (
        "def test_foo():\n"
        "    a = run()\n"
        "    assert a == 1\n"
        "    handler = lambda: side_effect()\n"
        "    assert handler is not None\n"
    )
    assert MultipleAaaCyclesRule().analyse(make_unit(src), default_ctx()) == []
