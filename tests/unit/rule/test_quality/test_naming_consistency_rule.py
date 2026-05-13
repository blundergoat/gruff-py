from gruff.rule.test_quality.naming_consistency_rule import NamingConsistencyRule
from tests.unit.rule.test_quality._helpers import default_ctx, make_unit


def test_consistent_snake_case_skipped():
    src = "def test_foo():\n    pass\ndef test_bar():\n    pass\n"
    assert NamingConsistencyRule().analyse(make_unit(src), default_ctx()) == []


def test_mixed_conventions_emits():
    src = "def test_foo():\n    pass\ndef testCamel():\n    pass\nclass TestThings:\n    pass\n"
    findings = NamingConsistencyRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_non_test_file_skipped():
    src = "def test_foo():\n    pass\ndef testCamel():\n    pass\n"
    findings = NamingConsistencyRule().analyse(make_unit(src, "src/main.py"), default_ctx())
    assert findings == []
