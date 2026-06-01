from gruffpy.rule.registry import RuleRegistry
from gruffpy.rule.sensitive_data.api_key_pattern_rule import ApiKeyPatternRule
from tests.unit.rule.sensitive_data._helpers import default_ctx, make_unit

_STRIPE_KEY = "sk_live_" + "abcdefghijklmno" + "pqrstuvwxyz123456"
_GITHUB_TOKEN = "ghp_" + "abcdefghijklmno" + "pqrstuvwxyzABCDEFGHIJ"
_OPENAI_KEY = "sk-" + "abcdefghijklmno" + "pqrstuvwxyz012345"
_OPENAI_PROJECT_KEY = "sk-proj-" + "abcDEF1234567890_abcDEF1234567890"
_ANTHROPIC_KEY = "sk-ant-" + "abcDEF1234567890_abcDEF1234567890"
_GITLAB_TOKEN = "glpat-" + "abcDEF1234567890_abcDEF"
_NPM_TOKEN = "npm_" + "abcDEF1234567890abcDEF1234567890"
_GOOGLE_API_KEY = "AIza" + "SyA1b2C3d4E5" + "f6G7h8I9j0K1" + "l2M3n4O5p6Q"
_GITHUB_FINE_GRAINED = "github_pat_" + "A" * 22 + "_" + "B" * 35
_SLACK_WEBHOOK = (
    "https://hooks.slack.com/services/"
    + "T12345678"
    + "/"
    + "B12345678"
    + "/"
    + "abcdefghijklm"
    + "nopqrstuvwxyz"
)


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
    token = "xoxb-" + "12345678" + "-abcdef-" + "mySlackToken"
    src = f"SLACK_TOKEN = {token!r}\n"
    findings = ApiKeyPatternRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["vendor"] == "slack"


def test_openai_key_emits():
    src = f"OPENAI_API_KEY = {_OPENAI_KEY!r}\n"
    findings = ApiKeyPatternRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["vendor"] == "openai"


def test_openai_project_key_emits():
    src = f"OPENAI_API_KEY = {_OPENAI_PROJECT_KEY!r}\n"
    findings = ApiKeyPatternRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["vendor"] == "openai"


def test_anthropic_key_emits():
    src = f"ANTHROPIC_API_KEY = {_ANTHROPIC_KEY!r}\n"
    findings = ApiKeyPatternRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["vendor"] == "anthropic"


def test_gitlab_token_emits():
    src = f"GITLAB_TOKEN = {_GITLAB_TOKEN!r}\n"
    findings = ApiKeyPatternRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["vendor"] == "gitlab"


def test_npm_token_emits():
    src = f"NPM_TOKEN = {_NPM_TOKEN!r}\n"
    findings = ApiKeyPatternRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["vendor"] == "npm"


def test_google_api_key_emits():
    src = f"GOOGLE_API_KEY = {_GOOGLE_API_KEY!r}\n"
    findings = ApiKeyPatternRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["vendor"] == "google"


def test_github_fine_grained_token_emits():
    src = f"GITHUB_TOKEN = {_GITHUB_FINE_GRAINED!r}\n"
    findings = ApiKeyPatternRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["vendor"] == "github"


def test_slack_webhook_emits():
    src = f"SLACK_WEBHOOK = {_SLACK_WEBHOOK!r}\n"
    findings = ApiKeyPatternRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["vendor"] == "slack"


def test_provider_metadata_and_message_do_not_leak_raw_key():
    src = f"GOOGLE_API_KEY = {_GOOGLE_API_KEY!r}\n"
    findings = ApiKeyPatternRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1

    finding = findings[0]
    assert _GOOGLE_API_KEY not in finding.message
    assert _GOOGLE_API_KEY not in str(finding.metadata)
    assert finding.metadata == {
        "preview": "AIza...5p6Q (redacted, 39 chars)",
        "vendor": "google",
    }


def test_provider_api_key_is_not_duplicated_by_high_entropy_rule():
    src = f"GOOGLE_API_KEY = {_GOOGLE_API_KEY!r}\n"

    findings = RuleRegistry.defaults().analyse([make_unit(src)], default_ctx())
    rule_ids = [finding.rule_id for finding in findings]

    assert rule_ids.count("sensitive-data.api-key-pattern") == 1
    assert "sensitive-data.high-entropy-string" not in rule_ids


def test_unrelated_string_skipped():
    src = "key = 'just-a-regular-config-string-here'\n"
    assert ApiKeyPatternRule().analyse(make_unit(src), default_ctx()) == []


def test_provider_documentation_placeholder_skipped():
    src = "GOOGLE_API_KEY = 'AIza" + "EXAMPLEKEY" + "PLACEHOLDER" + "123456789012345'\n"
    assert ApiKeyPatternRule().analyse(make_unit(src), default_ctx()) == []
