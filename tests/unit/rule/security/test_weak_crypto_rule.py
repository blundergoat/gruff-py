"""User-visible decisions for weak and fast password-hash findings.

Scanner users see warnings for security-sensitive MD5/SHA1 and fast password
hashes. These tests pin the standard-library non-security opt-out without
letting false-like or dynamic values hide findings or alter password policy.
"""

import pytest

from gruffpy.rule.security.weak_crypto_rule import WeakCryptoRule
from tests.unit.rule.security._helpers import default_ctx, make_unit

_WEAK_HASH_CALL_SHAPES = (
    ("import hashlib", "hashlib.md5"),
    ("from hashlib import sha1", "sha1"),
)

_USEDFORSECURITY_ARGUMENT_CASES = (
    ("", "", 1),
    (", usedforsecurity=False", "", 0),
    (", usedforsecurity=True", "", 1),
    (", usedforsecurity=0", "", 1),
    (", usedforsecurity=None", "", 1),
    (", usedforsecurity=security_use_flag", "security_use_flag = False\n", 1),
)


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


def test_sha256_signature_not_flagged():
    src = "import hashlib\nsignature = hashlib.sha256(payload).hexdigest()\n"
    assert WeakCryptoRule().analyse(make_unit(src), default_ctx()) == []


def test_sha256_on_password_emits_with_kdf_metadata():
    src = "import hashlib\npassword_hash = hashlib.sha256(password.encode()).hexdigest()\n"
    findings = WeakCryptoRule().analyse(make_unit(src), default_ctx())

    assert len(findings) == 1
    assert findings[0].metadata["algorithm"] == "sha256"
    assert findings[0].metadata["sourceLabel"] == "password-material"
    assert findings[0].metadata["sinkLabel"] == "fast-hash"


def test_sha512_in_password_function_emits():
    src = (
        "import hashlib\ndef hash_password(value):\n    return hashlib.sha512(value).hexdigest()\n"
    )
    findings = WeakCryptoRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_sha256_for_generic_content_skipped():
    src = "import hashlib\ncontent_digest = hashlib.sha256(file_bytes).hexdigest()\n"
    assert WeakCryptoRule().analyse(make_unit(src), default_ctx()) == []


@pytest.mark.parametrize(
    ("hash_import", "hash_call_target"),
    _WEAK_HASH_CALL_SHAPES,
    ids=("hashlib-md5", "direct-sha1"),
)
@pytest.mark.parametrize(
    ("usedforsecurity_argument", "case_setup", "expected_finding_count"),
    _USEDFORSECURITY_ARGUMENT_CASES,
    ids=("absent", "false", "true", "zero", "none", "variable"),
)
def test_usedforsecurity_weak_hash_matrix(
    hash_import: str,
    hash_call_target: str,
    usedforsecurity_argument: str,
    case_setup: str,
    expected_finding_count: int,
) -> None:
    """Show weak-hash findings unless the user supplies literal false.

    Args:
        hash_import: Qualified or direct hashlib import written by the user.
        hash_call_target: MD5/SHA1 call target reached by candidate selection.
        usedforsecurity_argument: Keyword suffix; empty means the user omitted it.
        case_setup: Optional dynamic flag setup; empty means no setup is needed.
        expected_finding_count: Zero only for the literal-false opt-out.
    """
    source = (
        f"{hash_import}\n"
        f"{case_setup}"
        f"password_hash = {hash_call_target}(password{usedforsecurity_argument}).hexdigest()\n"
    )
    findings = WeakCryptoRule().analyse(make_unit(source), default_ctx())
    assert len(findings) == expected_finding_count


def test_usedforsecurity_false_keeps_fast_password_hash_finding() -> None:
    """Keep warning when a user stores a password with fast SHA-256."""
    source = (
        "import hashlib\n"
        "password_hash = hashlib.sha256("
        "password, usedforsecurity=False).hexdigest()\n"
    )
    findings = WeakCryptoRule().analyse(make_unit(source), default_ctx())

    assert len(findings) == 1
    assert findings[0].metadata["algorithm"] == "sha256"
    assert findings[0].metadata["sourceLabel"] == "password-material"
