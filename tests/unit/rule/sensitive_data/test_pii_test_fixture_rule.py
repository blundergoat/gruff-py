from gruffpy.rule.sensitive_data.pii_test_fixture_rule import PiiTestFixtureRule
from tests.unit.rule.sensitive_data._helpers import default_ctx, make_unit

_REAL_EMAIL = "jane.doe" + "@" + "gmail.com"
_PLACEHOLDER_PHONE = "+1-" + "415-" + "555-" + "1234"
_REAL_PHONE = "+1-" + "415-" + "867-" + "5309"


def test_real_email_in_test_file_emits():
    src = f"user_email = {_REAL_EMAIL!r}\n"
    findings = PiiTestFixtureRule().analyse(make_unit(src, "tests/test_users.py"), default_ctx())
    assert len(findings) == 1


def test_example_email_skipped():
    src = "user_email = 'user@example.com'\n"
    findings = PiiTestFixtureRule().analyse(make_unit(src, "tests/test_users.py"), default_ctx())
    assert findings == []


def test_escaped_decorator_source_string_skipped():
    src = 'code = "import pytest\\n@pytest.fixture\\ndef thing(): pass\\n"\n'
    findings = PiiTestFixtureRule().analyse(make_unit(src, "tests/test_users.py"), default_ctx())
    assert findings == []


def test_real_phone_in_fixture_emits():
    src = f"phone = {_PLACEHOLDER_PHONE!r}\n"
    # 555 is a placeholder area code so this should NOT fire.
    findings = PiiTestFixtureRule().analyse(make_unit(src, "tests/test_users.py"), default_ctx())
    assert findings == []


def test_non_555_phone_in_fixture_emits():
    src = f"phone = {_REAL_PHONE!r}\n"
    findings = PiiTestFixtureRule().analyse(make_unit(src, "tests/test_users.py"), default_ctx())
    assert len(findings) == 1


def test_non_test_path_skipped():
    src = f"user_email = {_REAL_EMAIL!r}\n"
    findings = PiiTestFixtureRule().analyse(make_unit(src, "src/main.py"), default_ctx())
    assert findings == []
