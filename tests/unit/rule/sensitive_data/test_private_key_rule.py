from gruffpy.rule.sensitive_data.private_key_rule import PrivateKeyRule
from tests.unit.rule.sensitive_data._helpers import default_ctx, make_unit


def test_rsa_header_emits():
    header = "-----BEGIN RSA " + "PRIVATE KEY-----"
    footer = "-----END RSA " + "PRIVATE KEY-----"
    src = f"{header}\nMIIE...\n{footer}\n"
    findings = PrivateKeyRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_openssh_header_emits():
    header = "-----BEGIN OPENSSH " + "PRIVATE KEY-----"
    footer = "-----END OPENSSH " + "PRIVATE KEY-----"
    src = f"{header}\nb3BlbnNzaC1rZXk=\n{footer}\n"
    findings = PrivateKeyRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_ec_header_emits():
    header = "-----BEGIN EC " + "PRIVATE KEY-----"
    src = f"{header}\nMHcCAQ...\n"
    findings = PrivateKeyRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_public_key_not_flagged():
    src = "-----BEGIN PUBLIC KEY-----\nMIIBIj...\n-----END PUBLIC KEY-----\n"
    assert PrivateKeyRule().analyse(make_unit(src), default_ctx()) == []
