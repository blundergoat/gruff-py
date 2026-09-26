"""Exercise secret-like literal values found in committed ``.env`` files.

The suite keeps placeholders, runtime substitutions, and non-environment files quiet. Real-looking
values produce a finding whose user-visible preview contains no value-derived text.
"""

import pytest

from gruffpy.rule.sensitive_data.hardcoded_env_value_rule import HardcodedEnvValueRule
from tests.unit.rule.sensitive_data._helpers import default_ctx, make_unit

_ENV_SECRET = "aB3xF7p1Q9zR4" + "yT8vW2sN5kL6" + "mP0qH1"


def test_env_with_high_entropy_secret_emits():
    src = f"API_KEY={_ENV_SECRET}\nDEBUG=true\n"
    findings = HardcodedEnvValueRule().analyse(make_unit(src, ".env", "text"), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["preview"] == "[redacted]"


def test_env_placeholder_skipped():
    src = "SECRET=changeme\nTOKEN=your_secret_here\n"
    assert HardcodedEnvValueRule().analyse(make_unit(src, ".env", "text"), default_ctx()) == []


def test_env_variable_substitution_skipped():
    src = "API_KEY=${REAL_KEY_FROM_VAULT}\n"
    assert HardcodedEnvValueRule().analyse(make_unit(src, ".env", "text"), default_ctx()) == []


def test_non_env_file_skipped():
    src = f"API_KEY={_ENV_SECRET}\n"
    # Same content but in a .py file - rule should skip.
    assert HardcodedEnvValueRule().analyse(make_unit(src, "config.py"), default_ctx()) == []


def test_non_secret_key_skipped():
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
    """Keep an empty right-hand side quiet, the downstream brief's ``AWS_SECRET_ACCESS_KEY=`` shape.

    Args:
        source: Env file whose secret-named key has nothing after the equals sign.
    """
    assert HardcodedEnvValueRule().analyse(make_unit(source, ".env", "text"), default_ctx()) == []


@pytest.mark.parametrize(
    "value",
    ["your-key-here", "YOUR_STRIPE_API_KEY", "<your-api-token>", "REPLACE_ME", "Replace-Me", "xxxxxxxxxxxxxxxx", "Example"],
    ids=["your-key-here", "your-prefix", "angle-brackets", "replace-me-upper", "replace-me-mixed", "repeated-character", "example"],
)
def test_placeholder_value_is_skipped(value: str) -> None:
    """Treat widened placeholder spellings as stand-ins in any env file.

    Args:
        value: Placeholder written where the secret belongs.
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
    """
    src = "STRIPE_SECRET_KEY=sk_test_stripe_secret_key_goes_here\n"
    assert HardcodedEnvValueRule().analyse(make_unit(src, f"deploy/{filename}", "text"), default_ctx()) == []


def test_template_with_generated_credential_still_emits():
    """Report a credential-shaped value committed to a template, which leaks as surely as one in ``.env``."""
    src = f"API_KEY={_ENV_SECRET}\n"
    findings = HardcodedEnvValueRule().analyse(make_unit(src, ".env.example", "text"), default_ctx())
    assert [finding.metadata["key"] for finding in findings] == ["API_KEY"]


def test_sample_value_outside_a_template_still_emits():
    """Hold ``.env`` itself to the length and entropy gates, where a sample-looking value may be live."""
    src = "STRIPE_SECRET_KEY=sk_test_stripe_secret_key_goes_here\n"
    findings = HardcodedEnvValueRule().analyse(make_unit(src, ".env", "text"), default_ctx())
    assert [finding.metadata["key"] for finding in findings] == ["STRIPE_SECRET_KEY"]
