from gruffpy.rule.security.insecure_tls_protocol_rule import InsecureTlsProtocolRule
from tests.unit.rule.security._helpers import default_ctx, make_unit


def test_ssl_protocol_tlsv1_emits():
    src = "import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)\n"
    findings = InsecureTlsProtocolRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["target"] == "ssl.PROTOCOL_TLSv1"


def test_ssl_protocol_tlsv1_1_emits():
    src = "import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)\n"
    findings = InsecureTlsProtocolRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["target"] == "ssl.PROTOCOL_TLSv1_1"


def test_ssl_protocol_sslv2_emits():
    src = "import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_SSLv2)\n"
    findings = InsecureTlsProtocolRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_ssl_protocol_sslv3_emits():
    src = "import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_SSLv3)\n"
    findings = InsecureTlsProtocolRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_ssl_protocol_sslv23_emits():
    src = "import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)\n"
    findings = InsecureTlsProtocolRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_ssl_protocol_tlsv1_2_safe_skipped():
    src = "import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)\n"
    assert InsecureTlsProtocolRule().analyse(make_unit(src), default_ctx()) == []


def test_ssl_protocol_tls_client_safe_skipped():
    src = "import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n"
    assert InsecureTlsProtocolRule().analyse(make_unit(src), default_ctx()) == []


def test_unrelated_attr_with_protocol_name_skipped():
    """A class attribute named PROTOCOL_TLSv1 on a non-ssl receiver shouldn't fire."""
    src = "class X:\n    PROTOCOL_TLSv1 = 'safe-internal'\nfoo.PROTOCOL_TLSv1\n"
    assert InsecureTlsProtocolRule().analyse(make_unit(src), default_ctx()) == []


def test_carries_security_metadata():
    src = "import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)\n"
    finding = InsecureTlsProtocolRule().analyse(make_unit(src), default_ctx())[0]
    assert finding.metadata["sinkLabel"] == "tls-handshake"
    assert finding.metadata["sourceLabel"] == "tls-protocol-constant"


def test_docstring_mention_does_not_fire():
    """Source-needle fast-path may match a docstring, but the AST walk must not."""
    src = '"""Note: avoid ssl.PROTOCOL_TLSv1 in new code."""\n'
    assert InsecureTlsProtocolRule().analyse(make_unit(src), default_ctx()) == []
