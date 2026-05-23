from gruffpy.rule.security.cors_wildcard_with_credentials_rule import (
    CorsWildcardWithCredentialsRule,
)
from tests.unit.rule.security._helpers import default_ctx, make_unit


def test_cors_wildcard_string_with_credentials_emits():
    src = "from flask_cors import CORS\nCORS(app, supports_credentials=True, origins='*')\n"
    findings = CorsWildcardWithCredentialsRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_cors_wildcard_list_with_credentials_emits():
    src = "from flask_cors import CORS\nCORS(app, supports_credentials=True, origins=['*'])\n"
    findings = CorsWildcardWithCredentialsRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_cors_missing_origins_with_credentials_emits():
    """Flask-CORS defaults to wildcard origins when not specified."""
    src = "from flask_cors import CORS\nCORS(app, supports_credentials=True)\n"
    findings = CorsWildcardWithCredentialsRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_cors_specific_origin_with_credentials_skipped():
    src = (
        "from flask_cors import CORS\n"
        "CORS(app, supports_credentials=True, origins=['https://app.example.com'])\n"
    )
    assert CorsWildcardWithCredentialsRule().analyse(make_unit(src), default_ctx()) == []


def test_cors_wildcard_without_credentials_skipped():
    """Wildcard origin without credentials is the normal public-API CORS shape."""
    src = "from flask_cors import CORS\nCORS(app, origins='*')\n"
    assert CorsWildcardWithCredentialsRule().analyse(make_unit(src), default_ctx()) == []


def test_cors_credentials_false_skipped():
    src = "from flask_cors import CORS\nCORS(app, supports_credentials=False, origins='*')\n"
    assert CorsWildcardWithCredentialsRule().analyse(make_unit(src), default_ctx()) == []


def test_cors_wildcard_in_list_with_other_origins_emits():
    """If ['*', 'https://x'] is passed, the wildcard wins — fire."""
    src = (
        "from flask_cors import CORS\n"
        "CORS(app, supports_credentials=True, origins=['*', 'https://x'])\n"
    )
    findings = CorsWildcardWithCredentialsRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_dotted_cors_call_emits():
    src = "import flask_cors\nflask_cors.CORS(app, supports_credentials=True, origins='*')\n"
    findings = CorsWildcardWithCredentialsRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_unrelated_cors_named_call_with_no_supports_creds_skipped():
    """A CORS-named call without supports_credentials kwarg does not fire."""
    src = "from other_lib import CORS\nCORS(app, origins='*')\n"
    assert CorsWildcardWithCredentialsRule().analyse(make_unit(src), default_ctx()) == []


def test_carries_security_metadata():
    src = "from flask_cors import CORS\nCORS(app, supports_credentials=True, origins='*')\n"
    finding = CorsWildcardWithCredentialsRule().analyse(make_unit(src), default_ctx())[0]
    assert finding.metadata["sinkLabel"] == "cors-policy"
    assert finding.metadata["sourceLabel"] == "cross-origin-request"
    assert finding.metadata["shape"] == "flask-cors"
