from gruffpy.rule.test_quality.magic_number_assertion_rule import MagicNumberAssertionRule
from tests.unit.rule.test_quality._helpers import default_ctx, make_unit


def test_magic_number_emits():
    src = "def test_foo():\n    assert result == 17\n"
    findings = MagicNumberAssertionRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert 17 in findings[0].metadata["numbers"]


def test_http_status_skipped():
    src = "def test_foo():\n    assert response.status_code == 200\n"
    assert MagicNumberAssertionRule().analyse(make_unit(src), default_ctx()) == []


def test_zero_and_one_skipped():
    src = "def test_foo():\n    assert count == 0\n    assert other == 1\n"
    assert MagicNumberAssertionRule().analyse(make_unit(src), default_ctx()) == []


def test_common_small_expected_counts_skipped():
    src = "def test_foo():\n    assert count == 2\n    assert other == 3\n"
    assert MagicNumberAssertionRule().analyse(make_unit(src), default_ctx()) == []


def test_named_constant_skipped():
    src = "MAX = 42\ndef test_foo():\n    assert result == MAX\n"
    assert MagicNumberAssertionRule().analyse(make_unit(src), default_ctx()) == []


def test_exact_len_count_assertion_skipped():
    src = "def test_foo():\n    assert len(findings) == 2\n"
    assert MagicNumberAssertionRule().analyse(make_unit(src), default_ctx()) == []


def test_reversed_exact_len_count_assertion_skipped():
    src = "def test_foo():\n    assert 2 == len(findings)\n"
    assert MagicNumberAssertionRule().analyse(make_unit(src), default_ctx()) == []


def test_len_threshold_assertion_still_emits():
    src = "def test_foo():\n    assert len(password) >= 8\n"
    findings = MagicNumberAssertionRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["numbers"] == [8]


def test_rule_threshold_metadata_assertion_skipped():
    src = (
        "def test_foo():\n"
        "    assert definition.default_thresholds == {'warning': 15, 'error': 30}\n"
    )
    assert MagicNumberAssertionRule().analyse(make_unit(src), default_ctx()) == []


def test_finding_metric_metadata_assertion_skipped():
    src = "def test_foo():\n    assert finding.metadata['threshold'] == 2000\n"
    assert MagicNumberAssertionRule().analyse(make_unit(src), default_ctx()) == []


def test_finding_metric_threshold_comparison_skipped():
    src = "def test_foo():\n    assert finding.metadata['halsteadVolume'] > 2000\n"
    assert MagicNumberAssertionRule().analyse(make_unit(src), default_ctx()) == []


def test_metric_summary_assertion_skipped():
    src = "def test_foo():\n    assert metrics['cyclomatic']['max'] == 12\n"
    assert MagicNumberAssertionRule().analyse(make_unit(src), default_ctx()) == []


def test_report_metadata_assertion_skipped():
    src = "def test_foo():\n    assert payload['durationMs'] == 345\n"
    assert MagicNumberAssertionRule().analyse(make_unit(src), default_ctx()) == []


def test_metric_helper_assertion_skipped():
    src = "def test_foo():\n    assert cognitive_for(fn) == 6\n"
    assert MagicNumberAssertionRule().analyse(make_unit(src), default_ctx()) == []


def test_threshold_helper_arguments_skipped():
    src = "def test_foo():\n    assert Rule().analyse(unit, _ctx(warning=5, error=20)) == []\n"
    assert MagicNumberAssertionRule().analyse(make_unit(src), default_ctx()) == []


def test_source_line_assertion_skipped():
    src = "def test_foo():\n    assert [m.line for m in matches] == [2, 4]\n"
    assert MagicNumberAssertionRule().analyse(make_unit(src), default_ctx()) == []


def test_len_count_outside_allowlist_skipped():
    src = "def test_foo():\n    assert len(items) == 5\n"
    assert MagicNumberAssertionRule().analyse(make_unit(src), default_ctx()) == []


def test_reversed_len_count_outside_allowlist_skipped():
    src = "def test_foo():\n    assert 7 == len(items)\n"
    assert MagicNumberAssertionRule().analyse(make_unit(src), default_ctx()) == []


def test_opaque_equality_with_same_literal_still_fires():
    # `5` is suppressed as a count above, but a bare expected value is still
    # magic - the opaque-vs-cardinality distinction the rule must preserve.
    src = "def test_foo():\n    assert result == 5\n"
    findings = MagicNumberAssertionRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["numbers"] == [5]
