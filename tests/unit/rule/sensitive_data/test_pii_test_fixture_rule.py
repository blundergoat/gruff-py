import pytest

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


def test_555_placeholder_phone_in_fixture_is_skipped() -> None:
    """Keep the reserved 555 range available for safe fixtures."""
    src = f"phone = {_PLACEHOLDER_PHONE!r}\n"
    findings = PiiTestFixtureRule().analyse(make_unit(src, "tests/test_users.py"), default_ctx())
    assert findings == []


def test_formatted_realistic_phone_in_fixture_emits() -> None:
    """Keep formatted non-placeholder phone numbers visible to reviewers."""
    src = f"phone = {_REAL_PHONE!r}\n"
    findings = PiiTestFixtureRule().analyse(make_unit(src, "tests/test_users.py"), default_ctx())
    assert len(findings) == 1


def test_phone_label_keeps_bare_realistic_number_in_scope() -> None:
    """Keep separator-free phone values when their fixture key identifies them."""
    src = f"phone = {_REAL_BARE_PHONE!r}\n"
    findings = PiiTestFixtureRule().analyse(make_unit(src, "tests/test_users.py"), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["kind"] == "phone"


def test_unlabelled_bare_realistic_number_remains_in_scope() -> None:
    """Preserve the PII signal when a bare number has no nearby phone label."""
    source = f"contact = {_REAL_BARE_PHONE!r}\n"

    findings = PiiTestFixtureRule().analyse(make_unit(source, "tests/test_users.py"), default_ctx())

    assert len(findings) == 1
    assert findings[0].metadata["kind"] == "phone"


def test_rfc3986_digit_charset_is_not_a_phone_number() -> None:
    """Exclude the separator-free digit run in requests' RFC 3986 character set."""
    source = (
        'UNRESERVED_SET = "ABCDEFGHIJKLM" "NOPQRSTUVWXYZ" '
        '"abcdefghijklm" "nopqrstuvwxyz" + "0123456789-._~"\n'
    )

    findings = PiiTestFixtureRule().analyse(make_unit(source, "tests/test_utils.py"), default_ctx())

    assert findings == []


def test_sequential_digit_test_string_is_not_a_phone_number() -> None:
    """Exclude pytest's repeated width-test sequence without hiding arbitrary bare numbers."""
    source = 'value = "1234567890" * 5\n'

    findings = PiiTestFixtureRule().analyse(make_unit(source, "tests/test_width.py"), default_ctx())

    assert findings == []


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


@pytest.mark.parametrize(
    "display_path",
    [
        "/workspace/test-scan-repos/py/requests/pyproject.toml",
        "/workspace/test-scan-repos/py/requests/src/requests/__version__.py",
    ],
    ids=["project-metadata", "package-metadata"],
)
def test_scan_parent_name_does_not_classify_package_metadata_as_fixture(
    display_path: str,
) -> None:
    """Keep author metadata outside the fixture rule despite an incidental parent name.

    Args:
        display_path: Production metadata path beneath the corpus's ``test-scan-repos`` parent.
    """
    source = f"author_email = {_REAL_EMAIL!r}\n"

    findings = PiiTestFixtureRule().analyse(make_unit(source, display_path), default_ctx())

    assert findings == []


@pytest.mark.parametrize(
    "display_path",
    [
        "integration_tests/users.py",
        "unit_tests/data.py",
        "test-fixtures/seed.py",
    ],
    ids=["integration-tests", "unit-tests", "test-fixtures"],
)
def test_compound_test_directory_names_are_scanned(display_path: str) -> None:
    """Recognise the common compound conventions, not just a bare ``tests`` directory.

    Args:
        display_path: Fixture path whose directory ends in a test or fixture token.
    """
    source = f"user_email = {_REAL_EMAIL!r}\n"

    findings = PiiTestFixtureRule().analyse(make_unit(source, display_path), default_ctx())

    assert len(findings) == 1


@pytest.mark.parametrize(
    "display_path",
    [
        "latest/config.py",
        "contest_results/data.py",
        "manifest/app.py",
    ],
    ids=["latest", "contest-results", "manifest"],
)
def test_directories_merely_containing_test_text_are_not_scanned(display_path: str) -> None:
    """Keep production directories whose names only embed the letters ``test`` out of scope.

    Args:
        display_path: Production path whose final directory token is not a test word.
    """
    source = f"user_email = {_REAL_EMAIL!r}\n"

    findings = PiiTestFixtureRule().analyse(make_unit(source, display_path), default_ctx())

    assert findings == []
