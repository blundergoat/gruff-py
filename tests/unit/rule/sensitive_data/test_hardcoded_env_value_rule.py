from gruff.rule.sensitive_data.hardcoded_env_value_rule import HardcodedEnvValueRule
from tests.unit.rule.sensitive_data._helpers import default_ctx, make_unit

_ENV_SECRET = "aB3xF7p1Q9zR4" + "yT8vW2sN5kL6" + "mP0qH1"


def test_env_with_high_entropy_secret_emits():
    src = f"API_KEY={_ENV_SECRET}\nDEBUG=true\n"
    findings = HardcodedEnvValueRule().analyse(make_unit(src, ".env", "text"), default_ctx())
    assert len(findings) == 1


def test_env_placeholder_skipped():
    src = "SECRET=changeme\nTOKEN=your_secret_here\n"
    assert HardcodedEnvValueRule().analyse(make_unit(src, ".env", "text"), default_ctx()) == []


def test_env_variable_substitution_skipped():
    src = "API_KEY=${REAL_KEY_FROM_VAULT}\n"
    assert HardcodedEnvValueRule().analyse(make_unit(src, ".env", "text"), default_ctx()) == []


def test_non_env_file_skipped():
    src = f"API_KEY={_ENV_SECRET}\n"
    # Same content but in a .py file — rule should skip.
    assert HardcodedEnvValueRule().analyse(make_unit(src, "config.py"), default_ctx()) == []


def test_non_secret_key_skipped():
    src = "DEBUG=true\nLOG_LEVEL=info\n"
    assert HardcodedEnvValueRule().analyse(make_unit(src, ".env", "text"), default_ctx()) == []
