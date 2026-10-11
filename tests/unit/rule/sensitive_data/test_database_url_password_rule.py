import pytest

from gruffpy.rule.sensitive_data.database_url_password_rule import DatabaseUrlPasswordRule
from tests.unit.rule.sensitive_data._helpers import default_ctx, make_unit


@pytest.mark.parametrize(
    ("variable", "url"),
    [
        ("DATABASE_URL", "postgresql://admin:" + "s3cret!" + "@db.example.com/myapp"),
        ("MONGO", "mongodb+srv://user:" + "realSecret123" + "@cluster.mongodb.net"),
        ("REDIS", "rediss://default:" + "reallyL0ngP4ss!" + "@redis.example.com:6379"),
        ("WEAK", "postgresql://admin:" + "pa" + "ss" + "@prod-db.example.com/app"),
        (
            "SUBSTRING",
            "postgresql://admin:" + "passphrase123" + "@prod-db.example.com/app",
        ),
        (
            "REDACTED_REAL",
            "postgresql://admin:" + "redacted-real-secret" + "@prod-db.example.com/app",
        ),
    ],
    ids=["postgres", "mongodb_srv", "rediss", "exact_pass", "substring", "redacted_real"],
)
def test_url_with_password_emits(variable: str, url: str) -> None:
    src = f"{variable} = {url!r}\n"
    findings = DatabaseUrlPasswordRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


@pytest.mark.parametrize(
    "password",
    [
        "password",
        "PASSWORD",
        "changeme",
        "change-me",
        "****",
        "dummy",
        "fake",
        "redacted",
        "REDACTED",
    ],
    ids=[
        "literal_password",
        "uppercase_password",
        "changeme",
        "change_me",
        "redacted_stars",
        "dummy",
        "fake",
        "redacted",
        "uppercase_redacted",
    ],
)
def test_placeholder_password_skipped(password: str) -> None:
    src = "EXAMPLE = 'postgresql://user:" + password + "@host/db'\n"
    assert DatabaseUrlPasswordRule().analyse(make_unit(src), default_ctx()) == []


def test_passwordless_url_skipped():
    src = "URL = 'postgresql://user@host/db'\n"
    assert DatabaseUrlPasswordRule().analyse(make_unit(src), default_ctx()) == []


@pytest.mark.parametrize(
    "url",
    [
        "postgresql://postgres:postgres@localhost:5432/app",
        "mysql://root:root@127.0.0.1/app",
        "redis://Guest:Secret@db:6379",
        "postgres://scott:tiger@0.0.0.0/orcl",
    ],
    ids=["postgres_localhost", "root_loopback", "service_name_mixed_case", "scott_tiger_any_address"],
)
def test_stock_development_pair_on_local_host_skipped(url: str) -> None:
    src = f"URL = {url!r}\n"
    assert DatabaseUrlPasswordRule().analyse(make_unit(src), default_ctx()) == []


@pytest.mark.parametrize(
    "url",
    [
        "postgresql://postgres:postgres" + "@" + "db.example.com/app",
        "postgresql://postgres:" + "Vq7" + "mZ2" + "kP9" + "@localhost/app",
    ],
    ids=["stock_pair_reachable_host", "real_password_local_host"],
)
def test_stock_pair_elsewhere_or_real_password_locally_emits(url: str) -> None:
    src = f"URL = {url!r}\n"
    assert len(DatabaseUrlPasswordRule().analyse(make_unit(src), default_ctx())) == 1
