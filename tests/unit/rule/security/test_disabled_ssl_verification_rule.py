from gruffpy.rule.security.disabled_ssl_verification_rule import DisabledSslVerificationRule
from tests.unit.rule.security._helpers import default_ctx, make_unit


def test_requests_verify_false_emits():
    """Report one finding for ``requests.get`` with ``verify=False``."""
    src = "import requests\nrequests.get('https://x', verify=False)\n"
    findings = DisabledSslVerificationRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_requests_verify_true_skipped():
    """Report nothing for ``requests.get`` with ``verify=True``."""
    src = "import requests\nrequests.get('https://x', verify=True)\n"
    assert DisabledSslVerificationRule().analyse(make_unit(src), default_ctx()) == []


def test_requests_no_verify_kw_skipped():
    """Report nothing for ``requests.get`` without a ``verify`` argument."""
    src = "import requests\nrequests.get('https://x')\n"
    assert DisabledSslVerificationRule().analyse(make_unit(src), default_ctx()) == []


def test_create_unverified_context_emits():
    """Report one finding for ``ssl._create_unverified_context()``."""
    src = "import ssl\nctx = ssl._create_unverified_context()\n"
    findings = DisabledSslVerificationRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_urllib3_disable_warnings_emits():
    """Report one finding for ``urllib3.disable_warnings()``."""
    src = "import urllib3\nurllib3.disable_warnings()\n"
    findings = DisabledSslVerificationRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_requests_post_verify_zero_emits():
    """Report one finding for ``requests.post`` with ``verify=0``."""
    src = "import requests\nrequests.post('https://x', verify=0)\n"
    findings = DisabledSslVerificationRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_requests_verify_false_same_scope_alias_emits():
    """Report one finding when ``verify`` takes a same-scope alias of ``False``.

    The finding carries the ``literal-false-origin`` source and ``tls-verification`` sink labels.
    """
    src = "import requests\nverify = False\nrequests.get('https://x', verify=verify)\n"
    findings = DisabledSslVerificationRule().analyse(make_unit(src), default_ctx())

    assert len(findings) == 1
    assert findings[0].metadata["sourceLabel"] == "literal-false-origin"
    assert findings[0].metadata["sinkLabel"] == "tls-verification"


def test_requests_verify_zero_same_scope_alias_emits():
    """Report one finding when ``verify`` takes a same-scope alias of ``0``."""
    src = "import requests\nverify_cert = 0\nrequests.post('https://x', verify=verify_cert)\n"
    findings = DisabledSslVerificationRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_requests_verify_dynamic_alias_skipped():
    """Report nothing when ``verify`` takes an alias of a config value."""
    src = "import requests\nverify = config.verify_tls\nrequests.get('https://x', verify=verify)\n"
    assert DisabledSslVerificationRule().analyse(make_unit(src), default_ctx()) == []


def test_requests_verify_reassigned_alias_skipped():
    """Report nothing when the ``False`` alias is reassigned to a config value before the call."""
    src = "import requests\nverify = False\nverify = config.verify_tls\nrequests.get('https://x', verify=verify)\n"
    assert DisabledSslVerificationRule().analyse(make_unit(src), default_ctx()) == []


def test_requests_verify_outer_scope_alias_skipped_inside_function():
    """Report nothing when a function passes a module-level ``False`` alias as ``verify``."""
    src = "import requests\nverify = False\ndef fetch(url):\n    requests.get(url, verify=verify)\n"
    assert DisabledSslVerificationRule().analyse(make_unit(src), default_ctx()) == []
