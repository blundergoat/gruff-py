from gruffpy.rule.sensitive_data.pii_test_fixture_rule import PiiTestFixtureRule
from tests.unit.rule.sensitive_data._helpers import default_ctx, make_unit

_REAL_EMAIL = "jane.doe" + "@" + "gmail.com"
_WOOLOCAL_EMAIL = "user" + "@" + "woolocal.com"
_EXAMPLE_MIDLABEL_EMAIL = "ops" + "@" + "contoso.example.com"
_PLACEHOLDER_PHONE = "+1-" + "415-" + "555-" + "1234"
_REAL_PHONE = "+1-" + "415-" + "867-" + "5309"
_REAL_BARE_PHONE = "415" + "867" + "5309"
_CREATED_AT = "123" + "456" + "7890"
_UPDATED_AT = "123" + "456" + "7891"
_RESET_AT = "170" + "406" + "9000"
_RESETS_AT = "190" + "000" + "0000"
_TIME_VALUE = "170" + "531" + "2200"
_CREATED_VALUE = "123" + "456" + "7890"


def test_real_email_in_test_file_emits():
    src = f"user_email = {_REAL_EMAIL!r}\n"
    findings = PiiTestFixtureRule().analyse(make_unit(src, "tests/test_users.py"), default_ctx())
    assert len(findings) == 1


def test_example_email_skipped():
    src = "user_email = 'user@example.com'\n"
    findings = PiiTestFixtureRule().analyse(make_unit(src, "tests/test_users.py"), default_ctx())
    assert findings == []


def test_reserved_tld_email_domains_skipped():
    reserved_emails = (
        "user" + "@" + "woo.local",
        "admin" + "@" + "app.test",
        "dev" + "@" + "svc.invalid",
        "a" + "@" + "b.localhost",
        "team" + "@" + "corp.example",
    )
    src = "\n".join(
        f"user_email_{index} = {email!r}" for index, email in enumerate(reserved_emails)
    )

    findings = PiiTestFixtureRule().analyse(
        make_unit(f"{src}\n", "tests/test_users.py"), default_ctx()
    )

    assert findings == []


def test_reserved_tld_boundary_does_not_skip_real_domains():
    src = f"user_email = {_WOOLOCAL_EMAIL!r}\nops_email = {_EXAMPLE_MIDLABEL_EMAIL!r}\n"
    findings = PiiTestFixtureRule().analyse(make_unit(src, "tests/test_users.py"), default_ctx())
    assert len(findings) == 2
    assert {finding.metadata["kind"] for finding in findings} == {"email"}


def test_scp_style_git_reference_skipped():
    src = "dependency = 'git@github.com:org/repo.git#egg=widget'\n"
    findings = PiiTestFixtureRule().analyse(make_unit(src, "tests/test_users.py"), default_ctx())
    assert findings == []


def test_real_email_with_colon_still_emits():
    src = f"user_email = {_REAL_EMAIL!r}  # owner:\n"
    findings = PiiTestFixtureRule().analyse(make_unit(src, "tests/test_users.py"), default_ctx())
    assert len(findings) == 1


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


def test_non_555_bare_phone_with_phone_key_still_emits():
    src = f"phone = {_REAL_BARE_PHONE!r}\n"
    findings = PiiTestFixtureRule().analyse(make_unit(src, "tests/test_users.py"), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["kind"] == "phone"


def test_timestamp_context_bare_numbers_skipped():
    src = (
        f"created_at = {_CREATED_AT}\n"
        f"updated_at = {_UPDATED_AT}\n"
        f'headers = {{"x-codex-primary-reset-at": "{_RESET_AT}"}}\n'
        f"assert payload.resets_at == {_RESETS_AT}\n"
        f'spans = detector.detect("Time: {_TIME_VALUE}")\n'
        f'assert spans[0].text == "{_TIME_VALUE}"\n'
        f'payload = {{"created": {_CREATED_VALUE}}}\n'
    )
    findings = PiiTestFixtureRule().analyse(make_unit(src, "tests/test_users.py"), default_ctx())
    assert findings == []


def test_decimal_metric_fragment_is_not_phone() -> None:
    src = f"payload = 'revenue: {_CREATED_VALUE}.12, growth: 0.087'\n"

    findings = PiiTestFixtureRule().analyse(make_unit(src, "tests/test_users.py"), default_ctx())
    assert findings == []


def test_non_test_path_skipped():
    src = f"user_email = {_REAL_EMAIL!r}\n"
    findings = PiiTestFixtureRule().analyse(make_unit(src, "src/main.py"), default_ctx())
    assert findings == []
