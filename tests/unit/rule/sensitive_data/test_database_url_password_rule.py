from gruffpy.rule.sensitive_data.database_url_password_rule import DatabaseUrlPasswordRule
from tests.unit.rule.sensitive_data._helpers import default_ctx, make_unit


def test_postgres_with_password_emits():
    url = "postgresql://admin:" + "s3cret!" + "@db.example.com/myapp"
    src = f"DATABASE_URL = {url!r}\n"
    findings = DatabaseUrlPasswordRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_mongodb_with_password_emits():
    url = "mongodb+srv://user:" + "realSecret123" + "@cluster.mongodb.net"
    src = f"MONGO = {url!r}\n"
    findings = DatabaseUrlPasswordRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_placeholder_password_skipped():
    src = "EXAMPLE = 'postgresql://user:password@host/db'\n"
    assert DatabaseUrlPasswordRule().analyse(make_unit(src), default_ctx()) == []


def test_passwordless_url_skipped():
    src = "URL = 'postgresql://user@host/db'\n"
    assert DatabaseUrlPasswordRule().analyse(make_unit(src), default_ctx()) == []


def test_redis_with_password_emits():
    url = "rediss://default:" + "reallyL0ngP4ss!" + "@redis.example.com:6379"
    src = f"REDIS = {url!r}\n"
    findings = DatabaseUrlPasswordRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
