from gruffpy.rule.test_quality.naming_consistency_rule import NamingConsistencyRule
from tests.unit.rule.test_quality._helpers import default_ctx, make_unit


def test_consistent_snake_case_skipped():
    """Report nothing for a test file whose two test functions are both snake case."""
    src = "def test_foo():\n    pass\ndef test_bar():\n    pass\n"
    assert NamingConsistencyRule().analyse(make_unit(src), default_ctx()) == []


def test_mixed_conventions_emits():
    """Report one finding for a test file holding a snake-case test, a camel-case test and a test class."""
    src = "def test_foo():\n    pass\ndef testCamel():\n    pass\nclass TestThings:\n    pass\n"
    findings = NamingConsistencyRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_non_test_file_skipped():
    """Report nothing for mixed test names in ``src/main.py``."""
    src = "def test_foo():\n    pass\ndef testCamel():\n    pass\n"
    findings = NamingConsistencyRule().analyse(make_unit(src, "src/main.py"), default_ctx())
    assert findings == []
