from gruffpy.rule.security.insecure_random_rule import InsecureRandomRule
from tests.unit.rule.security._helpers import default_ctx, make_unit


def test_random_for_token_emits():
    """Report one finding for ``random.randint`` assigned to ``token``."""
    src = "import random\ntoken = random.randint(0, 1_000_000)\n"
    findings = InsecureRandomRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_random_in_password_function_emits():
    """Report one finding for ``random.choice`` inside a password-generating function."""
    src = "import random\ndef generate_password():\n    return random.choice('abcdef')\n"
    findings = InsecureRandomRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_random_for_game_skipped():
    """Report nothing for ``random.randint`` assigned to ``dice``."""
    src = "import random\ndice = random.randint(1, 6)\n"
    assert InsecureRandomRule().analyse(make_unit(src), default_ctx()) == []


def test_secrets_module_not_flagged():
    """Report nothing for ``secrets.token_hex``."""
    src = "import secrets\ntoken = secrets.token_hex(32)\n"
    assert InsecureRandomRule().analyse(make_unit(src), default_ctx()) == []
