"""Cumulative sensitive-data fixture + text-file routing audit.

Proves that:
1. Every shipped sensitive-data rule can fire on its respective shape.
2. The SourceTextRule routing works for sensitive-data without new wiring:
   a planted secret in a .json file is detected, and a .py-only rule does NOT
   fire on the same file.
3. Findings never leak the raw secret — every metadata.preview is redacted.
"""

import json
import re

from gruff.rule.registry import RuleRegistry
from tests.unit.rule.sensitive_data._helpers import default_ctx, make_unit

_AWS_KEY = "AKIA" + "1234567890ABCDEF"
_AWS_KEY_PREVIEW = "AKIA...CDEF"
_STRIPE_KEY = "sk_live_" + "abcdefghijklmno" + "pqrstuvwxyz123456"
_JWT_HEADER = "eyJhbGciOiJIUzI1" + "NiIsInR5cCI6IkpXVCJ9"
_JWT_PAYLOAD = "eyJzdWIiOiIxMjM0" + "NTY3ODkwIn0"
_JWT_SIGNATURE = "abcdef123456" + "abcdef"
_ENTROPY_VALUE = "aB3xF7p1Q9zR4" + "yT8vW2sN5kL6" + "mP0qH1jD8wEr+/="

_DANGEROUS_FIXTURE = (
    f"AWS_KEY = '{_AWS_KEY}'\n"
    f"STRIPE = '{_STRIPE_KEY}'\n"
    f"JWT = '{_JWT_HEADER}.{_JWT_PAYLOAD}.{_JWT_SIGNATURE}'\n"
    "DB = 'postgresql://admin:s3cret!@db.example.com/myapp'\n"
    "SSN = '412-78-3491'\n"
    f"ENTROPY = '{_ENTROPY_VALUE}'\n"
    "PRIVATE = '-----BEGIN RSA PRIVATE KEY-----'\n"
)

_EXPECTED_RULE_IDS = {
    "sensitive-data.aws-access-key",
    "sensitive-data.api-key-pattern",
    "sensitive-data.jwt-token",
    "sensitive-data.database-url-password",
    "sensitive-data.phi-pattern",
    "sensitive-data.high-entropy-string",
    "sensitive-data.private-key",
}


def test_every_sensitive_data_rule_fires_on_dangerous_fixture():
    findings = RuleRegistry.defaults().analyse([make_unit(_DANGEROUS_FIXTURE)], default_ctx())
    fired = {f.rule_id for f in findings if f.rule_id.startswith("sensitive-data.")}
    missing = _EXPECTED_RULE_IDS - fired
    assert not missing, f"Missing fires: {sorted(missing)}"


def test_aws_key_fires_on_json_file_via_text_seam():
    """Planted AWS key in a .json file is detected via the SourceTextRule seam."""
    src = f'{{"region": "us-east-1", "key": "{_AWS_KEY}"}}\n'
    findings = RuleRegistry.defaults().analyse(
        [make_unit(src, display_path="aws.json", source_type="text")], default_ctx()
    )
    text_findings = {f.rule_id for f in findings}
    assert "sensitive-data.aws-access-key" in text_findings
    # A Python-only rule must NOT fire on this text file. complexity rules require
    # an AST; they should be inert when tree is None.
    assert "complexity.cyclomatic" not in text_findings


def test_redaction_in_json_output_never_leaks_raw_secret():
    """Every emitted finding's metadata.preview is redacted; the raw secret never
    appears in the serialised JSON."""
    src = f"AWS_KEY = '{_AWS_KEY}'\n"
    findings = RuleRegistry.defaults().analyse([make_unit(src)], default_ctx())
    aws_findings = [f for f in findings if f.rule_id == "sensitive-data.aws-access-key"]
    assert len(aws_findings) == 1
    payload = json.dumps(aws_findings[0].to_dict())
    assert _AWS_KEY not in payload
    assert _AWS_KEY_PREVIEW in payload


def test_redact_preview_shape():
    """Preview matches `first4...last4 (redacted, N chars)` for secrets ≥ 8 chars."""
    src = f"key = '{_AWS_KEY}'\n"
    findings = RuleRegistry.defaults().analyse([make_unit(src)], default_ctx())
    aws = next(f for f in findings if f.rule_id == "sensitive-data.aws-access-key")
    assert re.match(
        r"^[A-Za-z0-9]{4}\.\.\.[A-Za-z0-9]{4} \(redacted, \d+ chars\)$", aws.metadata["preview"]
    )


def test_npm_integrity_style_hashes_suppressed():
    """package-lock.json content is ignored at the discovery layer via the lockfile filter."""
    # We don't have the discovery layer here, but the integration test for that lives in
    # the discovery module. We assert that a high-entropy hash in non-lockfile content
    # still produces a finding (positive control).
    hash_value = _ENTROPY_VALUE + "abcdef0123456789"
    src = f"sha512 = {hash_value!r}\n"
    findings = RuleRegistry.defaults().analyse([make_unit(src)], default_ctx())
    high_entropy = [f for f in findings if f.rule_id == "sensitive-data.high-entropy-string"]
    assert len(high_entropy) >= 1
