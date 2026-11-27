from gruffpy.rule.security.insecure_tls_protocol_rule import InsecureTlsProtocolRule
from tests.unit.rule.security._helpers import default_ctx, make_unit


def test_ssl_protocol_tlsv1_emits():
    """Report one finding, with target ssl.PROTOCOL_TLSv1, for an SSLContext built with that constant.

    Returns:
        None. Checks the finding count and target metadata for the TLSv1 context.
    """
    src = "import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)\n"
    findings = InsecureTlsProtocolRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["target"] == "ssl.PROTOCOL_TLSv1"


def test_ssl_protocol_tlsv1_1_emits():
    """Report one finding, with target ssl.PROTOCOL_TLSv1_1, for an SSLContext built with that constant.

    Returns:
        None. Checks the finding count and target metadata for the TLSv1.1 context.
    """
    src = "import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)\n"
    findings = InsecureTlsProtocolRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["target"] == "ssl.PROTOCOL_TLSv1_1"


def test_ssl_protocol_sslv2_emits():
    """Report one finding for an SSLContext built with PROTOCOL_SSLv2.

    Returns:
        None. Asserts that the SSLv2 context produces one finding.
    """
    src = "import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_SSLv2)\n"
    findings = InsecureTlsProtocolRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_ssl_protocol_sslv3_emits():
    """Report one finding for an SSLContext built with PROTOCOL_SSLv3.

    Returns:
        None. Asserts that the SSLv3 context produces one finding.
    """
    src = "import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_SSLv3)\n"
    findings = InsecureTlsProtocolRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_ssl_protocol_sslv23_emits():
    """Report one finding for an SSLContext built with PROTOCOL_SSLv23.

    Returns:
        None. Asserts that the PROTOCOL_SSLv23 context produces one finding.
    """
    src = "import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)\n"
    findings = InsecureTlsProtocolRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_ssl_protocol_tlsv1_2_safe_skipped():
    """Report nothing for an SSLContext built with PROTOCOL_TLSv1_2.

    Returns:
        None. Asserts that the TLSv1.2 context produces no findings.
    """
    src = "import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)\n"
    assert InsecureTlsProtocolRule().analyse(make_unit(src), default_ctx()) == []


def test_ssl_protocol_tls_client_safe_skipped():
    """Report nothing for an SSLContext built with PROTOCOL_TLS_CLIENT.

    Returns:
        None. Asserts that the PROTOCOL_TLS_CLIENT context produces no findings.
    """
    src = "import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n"
    assert InsecureTlsProtocolRule().analyse(make_unit(src), default_ctx()) == []


def test_unrelated_attr_with_protocol_name_skipped():
    """An attribute named PROTOCOL_TLSv1 on a non-ssl receiver shouldn't fire.

    Returns:
        None. Asserts that the protocol attribute on an unrelated receiver produces no findings.
    """
    src = "class X:\n    PROTOCOL_TLSv1 = 'safe-internal'\nfoo.PROTOCOL_TLSv1\n"
    assert InsecureTlsProtocolRule().analyse(make_unit(src), default_ctx()) == []


def test_carries_security_metadata():
    """Label the PROTOCOL_TLSv1 finding with the tls-handshake sink and tls-protocol-constant source.

    Returns:
        None. Checks both security labels on the first finding from the TLSv1 context.
    """
    src = "import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)\n"
    finding = InsecureTlsProtocolRule().analyse(make_unit(src), default_ctx())[0]
    assert finding.metadata["sinkLabel"] == "tls-handshake"
    assert finding.metadata["sourceLabel"] == "tls-protocol-constant"


def test_docstring_mention_does_not_fire():
    """Source-needle fast-path may match a docstring, but the AST walk must not.

    Returns:
        None. Asserts that mentioning the protocol only in a module docstring produces no findings.
    """
    src = '"""Note: avoid ssl.PROTOCOL_TLSv1 in new code."""\n'
    assert InsecureTlsProtocolRule().analyse(make_unit(src), default_ctx()) == []
