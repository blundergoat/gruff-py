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
        "preview": "https://deploy:<redacted:15 chars>@api.example.test/v1",
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


def _assert_url_raw_values_redacted(*rendered_values: str) -> None:
    for raw_value in (_PASSWORD, _URL):
        assert all(raw_value not in rendered for rendered in rendered_values)
