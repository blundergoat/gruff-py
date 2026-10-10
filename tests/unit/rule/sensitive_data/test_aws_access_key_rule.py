"""Exercise AWS access-key findings across Python and plain-text sources.

The suite protects ``AKIA`` and ``ASIA`` detection, documentation placeholders, source locations,
and the fixed preview users see instead of credential-derived text.
"""

from gruffpy.rule.sensitive_data.aws_access_key_rule import AwsAccessKeyRule
from tests.unit.rule.sensitive_data._helpers import default_ctx, make_unit

_AKIA_KEY = "AKIA" + "1234567890ABCDEF"
_ASIA_KEY = "ASIA" + "1234567890ABCDEF"


def test_akia_emits():
    src = f"AWS_KEY = '{_AKIA_KEY}'\n"
    findings = AwsAccessKeyRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["preview"] == "[redacted:aws-access-key]"


def test_asia_session_token_emits():
    src = f"key = '{_ASIA_KEY}'\n"
    findings = AwsAccessKeyRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_documentation_example_key_is_a_documented_sample():
    # FAMILY-CONTRACT section 5, amended 2026-09-26 (M10 D33): AWS's documented example key is a vendor-documented
    # sample, so no port reports it. The value is assembled at run time.
    src = "AWS_KEY = '" + "AKIA" + "IOSFODNN7" + "EXAMPLE" + "'\n"
    findings = AwsAccessKeyRule().analyse(make_unit(src), default_ctx())
    assert findings == []


def test_documentation_example_session_key_reports():
    src = "key = '" + "ASIA" + "IOSFODNN7" + "EXAMPLE" + "'\n"
    findings = AwsAccessKeyRule().analyse(make_unit(src), default_ctx())
    assert [finding.line for finding in findings] == [1]


def test_a_body_that_is_entirely_x_is_read_as_masked():
    # FAMILY-CONTRACT.md section 5 reads a body that is entirely X as naming no credential, while a real key that
    # merely contains a run of X still reports, because hiding it would hide a live credential.
    masked = "X" * 16
    src = "long_key = '" + "AKIA" + masked + "'\nsession_key = '" + "ASIA" + masked + "'\npartly_masked = '" + "AKIA" + "IOSFODNN" + "X" * 8 + "'\n"
    findings = AwsAccessKeyRule().analyse(make_unit(src), default_ctx())
    assert [finding.line for finding in findings] == [3]


def test_too_short_skipped():
    src = "key = 'AKIA123'\n"
    assert AwsAccessKeyRule().analyse(make_unit(src), default_ctx()) == []


def test_finding_in_json_text_file():
    src = f'{{"awsKey": "{_AKIA_KEY}"}}\n'
    findings = AwsAccessKeyRule().analyse(make_unit(src, "config.json", source_type="text"), default_ctx())
    assert len(findings) == 1


def test_line_number_resolved():
    src = f"first\nsecond\nthird {_AKIA_KEY}\n"
    findings = AwsAccessKeyRule().analyse(make_unit(src), default_ctx())
    assert findings[0].line == 3
