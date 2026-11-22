"""Exercise AWS access-key findings across Python and plain-text sources.

The suite protects ``AKIA`` and ``ASIA`` detection, documentation placeholders, source locations,
and the fixed preview users see instead of credential-derived text.
"""

from gruffpy.rule.registry import RuleRegistry
from gruffpy.rule.sensitive_data.aws_access_key_rule import AwsAccessKeyRule
from tests.unit.rule.sensitive_data._helpers import default_ctx, make_unit

_AKIA_KEY = "AKIA" + "1234567890ABCDEF"
_ASIA_KEY = "ASIA" + "1234567890ABCDEF"


def test_akia_emits():
    """Report one finding, with the fixed AWS preview, for an access key with the AKIA prefix.

    Returns:
        None. Successful completion means the assertions passed.
    """
    src = f"AWS_KEY = '{_AKIA_KEY}'\n"
    findings = AwsAccessKeyRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["preview"] == "[redacted:aws-access-key]"


def test_asia_session_token_emits():
    """Report one finding for a session key with the ASIA prefix.

    Returns:
        None. Successful completion means the assertions passed.
    """
    src = f"key = '{_ASIA_KEY}'\n"
    findings = AwsAccessKeyRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_redacted_keys_on_one_line_keep_distinct_locations() -> None:
    """Keep both findings through registry deduplication when their values share a redacted preview.

    Returns:
        None. Checks both one-based locations and the shared redacted preview.
    """
    source = f"values = [{_AKIA_KEY!r}, {_ASIA_KEY!r}]\n"
    all_findings = RuleRegistry.defaults().analyse([make_unit(source)], default_ctx())
    findings = [finding for finding in all_findings if finding.rule_id == AwsAccessKeyRule.ID]

    assert [(finding.line, finding.column) for finding in findings] == [
        (1, source.index(_AKIA_KEY) + 1),
        (1, source.index(_ASIA_KEY) + 1),
    ]
    assert {finding.metadata["preview"] for finding in findings} == {"[redacted:aws-access-key]"}


def test_documentation_example_key_is_a_documented_sample():
    """Report nothing for AWS's documented example access key.

    Returns:
        None. Successful completion means the assertions passed.
    """
    # FAMILY-CONTRACT section 5 treats AWS's documented example key as a vendor sample, so it produces no finding.
    src = "AWS_KEY = '" + "AKIA" + "IOSFODNN7" + "EXAMPLE" + "'\n"
    findings = AwsAccessKeyRule().analyse(make_unit(src), default_ctx())
    assert findings == []


def test_documentation_example_session_key_reports():
    """Report the documented example body once, on line 1, when it carries the ASIA prefix.

    Returns:
        None. Successful completion means the assertions passed.
    """
    src = "key = '" + "ASIA" + "IOSFODNN7" + "EXAMPLE" + "'\n"
    findings = AwsAccessKeyRule().analyse(make_unit(src), default_ctx())
    assert [finding.line for finding in findings] == [1]


def test_a_body_that_is_entirely_x_is_read_as_masked():
    """Report only the partly masked key on line 3, and neither key whose body is entirely X.

    Returns:
        None. Successful completion means the assertions passed.
    """
    # FAMILY-CONTRACT.md section 5 reads a body that is entirely X as naming no credential, while a real key that
    # merely contains a run of X still reports, because hiding it would hide a live credential.
    masked = "X" * 16
    src = "long_key = '" + "AKIA" + masked + "'\nsession_key = '" + "ASIA" + masked + "'\npartly_masked = '" + "AKIA" + "IOSFODNN" + "X" * 8 + "'\n"
    findings = AwsAccessKeyRule().analyse(make_unit(src), default_ctx())
    assert [finding.line for finding in findings] == [3]


def test_too_short_skipped():
    """Report nothing for an AKIA prefix with too short a body.

    Returns:
        None. Successful completion means the assertions passed.
    """
    src = "key = 'AKIA123'\n"
    assert AwsAccessKeyRule().analyse(make_unit(src), default_ctx()) == []


def test_finding_in_json_text_file():
    """Report one finding for an access key inside a JSON text file.

    Returns:
        None. Successful completion means the assertions passed.
    """
    src = f'{{"awsKey": "{_AKIA_KEY}"}}\n'
    findings = AwsAccessKeyRule().analyse(make_unit(src, "config.json", source_type="text"), default_ctx())
    assert len(findings) == 1


def test_line_number_resolved():
    """Place the first finding on line 3, where the key sits.

    Returns:
        None. Successful completion means the assertions passed.
    """
    src = f"first\nsecond\nthird {_AKIA_KEY}\n"
    findings = AwsAccessKeyRule().analyse(make_unit(src), default_ctx())
    assert findings[0].line == 3
