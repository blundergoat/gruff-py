from gruff.rule.sensitive_data.jwt_token_rule import JwtTokenRule
from tests.unit.rule.sensitive_data._helpers import default_ctx, make_unit


def test_jwt_in_source_emits():
    src = (
        "TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ."
        "abcdef0123456789abcdef0123456789abcdef'\n"
    )
    findings = JwtTokenRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_non_jwt_token_not_flagged():
    src = "TOKEN = 'short-token'\n"
    assert JwtTokenRule().analyse(make_unit(src), default_ctx()) == []


def test_jwt_in_yaml_emits():
    src = (
        "token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdef123456abcdef\n"
    )
    findings = JwtTokenRule().analyse(make_unit(src, "config.yaml", "text"), default_ctx())
    assert len(findings) == 1
