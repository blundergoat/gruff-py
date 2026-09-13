"""Exercise findings for HTTP(S) URLs with embedded user credentials.

The suite covers valid, public, placeholder, and database URLs plus registry routing. User output
must retain a fixed preview without exposing the password or credential-bearing URL.
"""

import pytest

from gruffpy.rule.registry import RuleRegistry
from gruffpy.rule.sensitive_data.url_credentials_rule import UrlCredentialsRule
from tests.unit.rule.sensitive_data._helpers import default_ctx, make_unit

_PASSWORD = "rem0te" + "Secret!42"
_URL = f"https://deploy:{_PASSWORD}@api.example.test/v1"


def test_https_url_with_embedded_password_emits_redacted_preview():
    findings = UrlCredentialsRule().analyse(make_unit(f"REMOTE = {_URL!r}\n"), default_ctx())

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "sensitive-data.url-credentials"
    assert finding.metadata == {
        "category": "url-credentials",
        "preview": "[redacted:connection-string:https]",
    }
    _assert_url_raw_values_redacted(finding.message, str(finding.metadata))


def test_http_url_with_embedded_password_emits():
    url = "http://user:" + _PASSWORD + "@example.test"

    findings = UrlCredentialsRule().analyse(make_unit(f"REMOTE = {url!r}\n"), default_ctx())

    assert len(findings) == 1


def test_url_credentials_routes_through_default_registry():
    findings = RuleRegistry.defaults().analyse([make_unit(f"REMOTE = {_URL!r}\n")], default_ctx())
    rule_ids = {finding.rule_id for finding in findings}

    assert "sensitive-data.url-credentials" in rule_ids
    assert "sensitive-data.database-url-password" not in rule_ids


def test_placeholder_url_password_skipped():
    src = "REMOTE = 'https://deploy:password@" + "example.test/v1'\n"

    assert UrlCredentialsRule().analyse(make_unit(src), default_ctx()) == []


def test_public_url_without_credentials_skipped():
    src = "REMOTE = 'https://example.test/v1'\n"

    assert UrlCredentialsRule().analyse(make_unit(src), default_ctx()) == []


def test_database_url_not_duplicated_by_url_credentials_rule():
    src = "DATABASE_URL = 'postgresql://admin:realSecret123@" + "db.example.test/app'\n"

    assert UrlCredentialsRule().analyse(make_unit(src), default_ctx()) == []


@pytest.mark.parametrize(
    "source",
    [
        'PROXY = "http://{}:{}@proxy.example.test".format(user, secret)\n',
        'PROXY = f"http://{ENCODED_USER}:{ENCODED_PASSWORD}@proxy.example.test"\n',
        'PROXY = "http://%s:%s@proxy.example.test" % (user, secret)\n',
        'ROWS = ["http://foo:bar:baz@example.test"]\n',
        'ROWS = ["http://user:pass/extra@example.test"]\n',
    ],
    ids=["str-format-template", "f-string-template", "printf-template", "second-colon", "path-separator"],
)
def test_templated_or_over_captured_password_is_not_a_credential(source: str) -> None:
    """Clear the M17 hunt's template and over-capture shapes, whose captured segment is no literal password.

    Args:
        source: URL literal whose password segment carries template syntax or a separator.
    """
    assert UrlCredentialsRule().analyse(make_unit(source), default_ctx()) == []


def test_real_credentials_still_report_at_error_including_percent_escapes() -> None:
    """Keep reporting literal passwords, including one whose special character is percent-encoded."""
    plain = "http://admin:" + "S3cr3tPassw0rd" + "@db.internal"
    encoded = "https://deploy:" + "S3cr%40tValue42" + "@api.example.test"
    findings = UrlCredentialsRule().analyse(make_unit(f"PLAIN = {plain!r}\nENCODED = {encoded!r}\n"), default_ctx())

    assert [finding.line for finding in findings] == [1, 2]
    assert {finding.severity.value for finding in findings} == {"error"}


def test_url_repeated_on_the_next_line_is_reported_once() -> None:
    """Report a wrapped row written twice once, while distinct credentials on adjacent lines stay separate."""
    repeated = f"CASES = [\n    {_URL!r},\n    {_URL!r},\n]\n"
    other = "https://deploy:" + "an0ther" + "Secret!7" + "@api.example.test/v1"
    distinct = f"CASES = [\n    {_URL!r},\n    {other!r},\n]\n"

    assert [finding.line for finding in UrlCredentialsRule().analyse(make_unit(repeated), default_ctx())] == [2]
    assert [finding.line for finding in UrlCredentialsRule().analyse(make_unit(distinct), default_ctx())] == [2, 3]


def _assert_url_raw_values_redacted(*rendered_values: str) -> None:
    for raw_value in (_PASSWORD, _URL):
        assert all(raw_value not in rendered for rendered in rendered_values)
