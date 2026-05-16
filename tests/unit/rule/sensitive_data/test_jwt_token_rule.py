from gruff.rule.sensitive_data.jwt_token_rule import JwtTokenRule
from tests.unit.rule.sensitive_data._helpers import default_ctx, make_unit

_JWT_HEADER = "eyJhbGciOiJIUzI1" + "NiIsInR5cCI6IkpXVCJ9"
_JWT_PAYLOAD = "eyJzdWIiOiIxMjM0" + "NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ"
_JWT_SIGNATURE = "abcdef0123456789" + "abcdef0123456789" + "abcdef"
_YAML_JWT_PAYLOAD = "eyJzdWIiOiIxMjM0" + "NTY3ODkwIn0"
_YAML_JWT_SIGNATURE = "abcdef123456" + "abcdef"


def test_jwt_in_source_emits():
    src = f"TOKEN = '{_JWT_HEADER}.{_JWT_PAYLOAD}.{_JWT_SIGNATURE}'\n"
    findings = JwtTokenRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_non_jwt_token_not_flagged():
    src = "TOKEN = 'short-token'\n"
    assert JwtTokenRule().analyse(make_unit(src), default_ctx()) == []


def test_jwt_in_yaml_emits():
    src = f"token: {_JWT_HEADER}.{_YAML_JWT_PAYLOAD}.{_YAML_JWT_SIGNATURE}\n"
    findings = JwtTokenRule().analyse(make_unit(src, "config.yaml", "text"), default_ctx())
    assert len(findings) == 1
