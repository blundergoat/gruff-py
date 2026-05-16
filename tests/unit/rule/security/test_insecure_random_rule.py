from gruffpy.rule.security.insecure_random_rule import InsecureRandomRule
from tests.unit.rule.security._helpers import default_ctx, make_unit


def test_random_for_token_emits():
    src = "import random\ntoken = random.randint(0, 1_000_000)\n"
    findings = InsecureRandomRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_random_in_password_function_emits():
    src = "import random\ndef generate_password():\n    return random.choice('abcdef')\n"
    findings = InsecureRandomRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_random_for_game_skipped():
    src = "import random\ndice = random.randint(1, 6)\n"
    assert InsecureRandomRule().analyse(make_unit(src), default_ctx()) == []


def test_secrets_module_not_flagged():
    src = "import secrets\ntoken = secrets.token_hex(32)\n"
    assert InsecureRandomRule().analyse(make_unit(src), default_ctx()) == []
