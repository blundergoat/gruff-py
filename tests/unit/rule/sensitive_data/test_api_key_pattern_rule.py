from gruff.rule.sensitive_data.api_key_pattern_rule import ApiKeyPatternRule
from tests.unit.rule.sensitive_data._helpers import default_ctx, make_unit

_STRIPE_KEY = "sk_live_" + "abcdefghijklmno" + "pqrstuvwxyz123456"
_GITHUB_TOKEN = "ghp_" + "abcdefghijklmno" + "pqrstuvwxyzABCDEFGHIJ"
_OPENAI_KEY = "sk-" + "abcdefghijklmno" + "pqrstuvwxyz012345"


def test_stripe_live_key_emits():
    src = f"key = {_STRIPE_KEY!r}\n"
    findings = ApiKeyPatternRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["vendor"] == "stripe"


def test_github_personal_token_emits():
    src = f"GH_TOKEN = {_GITHUB_TOKEN!r}\n"
    findings = ApiKeyPatternRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["vendor"] == "github"


def test_slack_bot_token_emits():
    src = "SLACK_TOKEN = 'xoxb-12345678-abcdef-mySlackToken'\n"
    findings = ApiKeyPatternRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["vendor"] == "slack"


def test_openai_key_emits():
    src = f"OPENAI_API_KEY = {_OPENAI_KEY!r}\n"
    findings = ApiKeyPatternRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["vendor"] == "openai"


def test_unrelated_string_skipped():
    src = "key = 'just-a-regular-config-string-here'\n"
    assert ApiKeyPatternRule().analyse(make_unit(src), default_ctx()) == []
