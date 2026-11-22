"""Exercise secret-like literal values found in committed ``.env`` files.

The suite keeps placeholders, runtime substitutions, and non-environment files quiet. Real-looking
values produce a finding whose user-visible preview contains no value-derived text.
"""

import pytest

from gruffpy.rule.sensitive_data.hardcoded_env_value_rule import HardcodedEnvValueRule
from tests.unit.rule.sensitive_data._helpers import default_ctx, make_unit

_ENV_SECRET = "aB3xF7p1Q9zR4" + "yT8vW2sN5kL6" + "mP0qH1"


def test_env_with_high_entropy_secret_emits():
    """Report one finding, with the fixed preview, for a .env file holding a high-entropy API_KEY value and DEBUG=true.

    Returns:
        None after verifying the finding count and fixed preview.
    """
    src = f"API_KEY={_ENV_SECRET}\nDEBUG=true\n"
    findings = HardcodedEnvValueRule().analyse(make_unit(src, ".env", "text"), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["preview"] == "[redacted]"


def test_env_placeholder_skipped():
    """Report nothing for placeholder values in a .env file.

    Returns:
        None after verifying that the placeholder assignments produce no findings.
    """
    src = "SECRET=changeme\nTOKEN=your_secret_here\n"
    assert HardcodedEnvValueRule().analyse(make_unit(src, ".env", "text"), default_ctx()) == []


def test_env_variable_substitution_skipped():
    """Report nothing for a .env value that substitutes another variable.

    Returns:
        None after verifying that the variable reference produces no findings.
    """
    src = "API_KEY=${REAL_KEY_FROM_VAULT}\n"
    assert HardcodedEnvValueRule().analyse(make_unit(src, ".env", "text"), default_ctx()) == []


def test_non_env_file_skipped():
    """Report nothing for the same secret-shaped value in a Python file.

    Returns:
        None after verifying that the Python file produces no findings.
    """
    src = f"API_KEY={_ENV_SECRET}\n"
    assert HardcodedEnvValueRule().analyse(make_unit(src, "config.py"), default_ctx()) == []


def test_non_secret_key_skipped():
    """Report nothing for .env keys whose names do not suggest a secret.

    Returns:
        None after verifying that the non-secret settings produce no findings.
    """
    src = "DEBUG=true\nLOG_LEVEL=info\n"
    assert HardcodedEnvValueRule().analyse(make_unit(src, ".env", "text"), default_ctx()) == []


@pytest.mark.parametrize(
    "source",
    [
        "AWS_SECRET_ACCESS_KEY=\n",
        "AWS_SECRET_ACCESS_KEY=\nAWS_DEFAULT_REGION=ap-southeast-2\n",
        "AWS_SECRET_ACCESS_KEY=\n\n# Twilio voice agent settings\n",
        "TWILIO_AUTH_TOKEN=\nVOICE_AGENT_PUBLIC_TWIML_BASE_URL=\n",
        "TWILIO_AUTH_TOKEN=   \r\nVOICE_AGENT_PUBLIC_TWIML_BASE_URL=https://voice.example.test\r\n",
    ],
    ids=["end-of-file", "region-on-next-line", "comment-after-blank-line", "empty-key-on-next-line", "crlf-next-line"],
)
def test_empty_value_never_reads_the_next_line(source: str) -> None:
    """Keep empty or whitespace-only secret values quiet regardless of the following line.

    Args:
        source: Env file whose secret-named key has an empty or whitespace-only value.

    Returns:
        None after verifying that the source produces no findings.
    """
    assert HardcodedEnvValueRule().analyse(make_unit(source, ".env", "text"), default_ctx()) == []


@pytest.mark.parametrize(
    "value",
    ["your-key-here", "YOUR_STRIPE_API_KEY", "<your-api-token>", "REPLACE_ME", "Replace-Me", "xxxxxxxxxxxxxxxx", "Example"],
    ids=["your-key-here", "your-prefix", "angle-brackets", "replace-me-upper", "replace-me-mixed", "repeated-character", "example"],
)
def test_placeholder_value_is_skipped(value: str) -> None:
    """Report no findings for the listed placeholder spellings in a .env file.

    Args:
        value: Placeholder written where the secret belongs.

    Returns:
        None after verifying that the placeholder value produces no findings.
    """
    src = f"API_KEY={value}\n"
    assert HardcodedEnvValueRule().analyse(make_unit(src, ".env", "text"), default_ctx()) == []


@pytest.mark.parametrize(
    "filename",
    [".env.example", ".env.sample", ".env.template", ".env.dist", ".env.local.example"],
    ids=["example", "sample", "template", "dist", "local-example"],
)
def test_template_sample_value_is_skipped(filename: str) -> None:
    """Skip a long sample value in a template, which lists secret-shaped keys by design.

    Args:
        filename: Template filename the sample value sits in.

    Returns:
        None after verifying that the template sample produces no findings.
    """
    src = "STRIPE_SECRET_KEY=sk_test_stripe_secret_key_goes_here\n"
    assert HardcodedEnvValueRule().analyse(make_unit(src, f"deploy/{filename}", "text"), default_ctx()) == []


@pytest.mark.parametrize("value", [_ENV_SECRET, f"your{_ENV_SECRET}"], ids=["generated", "unseparated-your-prefix"])
def test_template_with_generated_credential_still_emits(value: str) -> None:
    """Report one API_KEY finding for a credential-shaped value in .env.example.

    Args:
        value: Synthetic credential with or without an unseparated ``your`` prefix.

    Returns:
        None after verifying that the template produces the API_KEY finding.
    """
    src = f"API_KEY={value}\n"
    findings = HardcodedEnvValueRule().analyse(make_unit(src, ".env.example", "text"), default_ctx())
    assert [finding.metadata["key"] for finding in findings] == ["API_KEY"]


def test_sample_value_outside_a_template_still_emits():
    """Report a STRIPE_SECRET_KEY finding for the sample-looking value in .env.

    Returns:
        None after verifying that the sample-looking value produces the STRIPE_SECRET_KEY finding.
    """
    src = "STRIPE_SECRET_KEY=sk_test_stripe_secret_key_goes_here\n"
    findings = HardcodedEnvValueRule().analyse(make_unit(src, ".env", "text"), default_ctx())
    assert [finding.metadata["key"] for finding in findings] == ["STRIPE_SECRET_KEY"]
