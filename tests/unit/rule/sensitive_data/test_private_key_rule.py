from gruffpy.rule.sensitive_data.private_key_rule import PrivateKeyRule
from tests.unit.rule.sensitive_data._helpers import default_ctx, make_unit


def test_rsa_header_emits():
    src = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n"
    findings = PrivateKeyRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_openssh_header_emits():
    src = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk=\n-----END OPENSSH PRIVATE KEY-----\n"
    )
    findings = PrivateKeyRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_ec_header_emits():
    src = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQ...\n"
    findings = PrivateKeyRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_public_key_not_flagged():
    src = "-----BEGIN PUBLIC KEY-----\nMIIBIj...\n-----END PUBLIC KEY-----\n"
    assert PrivateKeyRule().analyse(make_unit(src), default_ctx()) == []
