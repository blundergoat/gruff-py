from gruff.rule.sensitive_data.high_entropy_string_rule import HighEntropyStringRule
from tests.unit.rule.sensitive_data._helpers import default_ctx, make_unit

_HIGH_ENTROPY = "aB3xF7p1Q9zR4" + "yT8vW2sN5kL6" + "mP0qH1jD8wEr+/="


def test_high_entropy_random_string_emits():
    src = f"KEY = {_HIGH_ENTROPY!r}\n"
    findings = HighEntropyStringRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["entropy"] > 4.5


def test_pascal_case_identifier_skipped():
    src = "name = 'SomeReallyLongPascalCaseIdentifier'\n"
    assert HighEntropyStringRule().analyse(make_unit(src), default_ctx()) == []


def test_path_string_skipped():
    src = "PATH = '/usr/local/bin/some_random_binary_name'\n"
    assert HighEntropyStringRule().analyse(make_unit(src), default_ctx()) == []


def test_short_high_entropy_skipped():
    src = "key = 'aB3xF7p1'\n"
    assert HighEntropyStringRule().analyse(make_unit(src), default_ctx()) == []


def test_low_entropy_long_string_skipped():
    src = "x = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'\n"
    assert HighEntropyStringRule().analyse(make_unit(src), default_ctx()) == []
