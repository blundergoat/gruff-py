from gruff.rule.security.weak_crypto_rule import WeakCryptoRule
from tests.unit.rule.security._helpers import default_ctx, make_unit


def test_md5_on_password_emits():
    src = "import hashlib\npassword_hash = hashlib.md5(password.encode())\n"
    findings = WeakCryptoRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["algorithm"] == "md5"


def test_sha1_in_security_function_emits():
    src = "import hashlib\ndef sign_token(payload):\n    return hashlib.sha1(payload).hexdigest()\n"
    findings = WeakCryptoRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_md5_for_cache_key_skipped():
    src = "import hashlib\ncache_key = hashlib.md5(content).hexdigest()\n"
    assert WeakCryptoRule().analyse(make_unit(src), default_ctx()) == []


def test_sha256_not_flagged():
    src = "import hashlib\nsignature = hashlib.sha256(payload).hexdigest()\n"
    assert WeakCryptoRule().analyse(make_unit(src), default_ctx()) == []
