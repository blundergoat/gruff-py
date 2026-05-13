from gruff.rule.sensitive_data.aws_access_key_rule import AwsAccessKeyRule
from tests.unit.rule.sensitive_data._helpers import default_ctx, make_unit


def test_akia_emits():
    src = "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n"
    findings = AwsAccessKeyRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert "AKIA...MPLE" in findings[0].metadata["preview"]


def test_asia_session_token_emits():
    src = "key = 'ASIAIOSFODNN7EXAMPLE'\n"
    findings = AwsAccessKeyRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_too_short_skipped():
    src = "key = 'AKIA123'\n"
    assert AwsAccessKeyRule().analyse(make_unit(src), default_ctx()) == []


def test_finding_in_json_text_file():
    src = '{"awsKey": "AKIAIOSFODNN7EXAMPLE"}\n'
    findings = AwsAccessKeyRule().analyse(
        make_unit(src, "config.json", source_type="text"), default_ctx()
    )
    assert len(findings) == 1


def test_line_number_resolved():
    src = "first\nsecond\nthird AKIAIOSFODNN7EXAMPLE\n"
    findings = AwsAccessKeyRule().analyse(make_unit(src), default_ctx())
    assert findings[0].line == 3
