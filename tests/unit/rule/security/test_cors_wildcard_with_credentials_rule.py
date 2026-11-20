from gruffpy.rule.security.cors_wildcard_with_credentials_rule import (
    CorsWildcardWithCredentialsRule,
)
from tests.unit.rule.security._helpers import default_ctx, make_unit


def test_cors_wildcard_string_with_credentials_emits():
    """Report one finding for a Flask-CORS call that allows credentials with the wildcard origin string.

    Returns:
        None after checking for one finding when the credentialed call uses a wildcard origin string.
    """
    src = "from flask_cors import CORS\nCORS(app, supports_credentials=True, origins='*')\n"
    findings = CorsWildcardWithCredentialsRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_cors_wildcard_list_with_credentials_emits():
    """Report one finding for a Flask-CORS call that allows credentials with a wildcard-only origin list.

    Returns:
        None after checking for one finding when the credentialed call uses a wildcard-only origin list.
    """
    src = "from flask_cors import CORS\nCORS(app, supports_credentials=True, origins=['*'])\n"
    findings = CorsWildcardWithCredentialsRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_cors_missing_origins_with_credentials_emits():
    """Report one finding when a credentialed Flask-CORS call omits origins.

    Returns:
        None after checking for one finding when the credentialed call omits origins.
    """
    src = "from flask_cors import CORS\nCORS(app, supports_credentials=True)\n"
    findings = CorsWildcardWithCredentialsRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_cors_specific_origin_with_credentials_skipped():
    """Report nothing for a credentialed Flask-CORS call limited to one named origin.

    Returns:
        None after checking that a credentialed call restricted to one origin yields no findings.
    """
    src = "from flask_cors import CORS\nCORS(app, supports_credentials=True, origins=['https://app.example.com'])\n"
    assert CorsWildcardWithCredentialsRule().analyse(make_unit(src), default_ctx()) == []


def test_cors_wildcard_without_credentials_skipped():
    """Report nothing for a wildcard Flask-CORS call that omits the credentials option.

    Returns:
        None after checking that a wildcard call with the credentials option omitted yields no findings.
    """
    src = "from flask_cors import CORS\nCORS(app, origins='*')\n"
    assert CorsWildcardWithCredentialsRule().analyse(make_unit(src), default_ctx()) == []


def test_cors_credentials_false_skipped():
    """Report nothing for a wildcard Flask-CORS call with credentials turned off.

    Returns:
        None after checking that a wildcard call with credentials explicitly disabled yields no findings.
    """
    src = "from flask_cors import CORS\nCORS(app, supports_credentials=False, origins='*')\n"
    assert CorsWildcardWithCredentialsRule().analyse(make_unit(src), default_ctx()) == []


def test_cors_wildcard_in_list_with_other_origins_emits():
    """Report one finding when a credentialed Flask-CORS origin list mixes a wildcard with a named origin.

    Returns:
        None after checking for one finding when a credentialed origin list contains both a wildcard and a named origin.
    """
    src = "from flask_cors import CORS\nCORS(app, supports_credentials=True, origins=['*', 'https://x'])\n"
    findings = CorsWildcardWithCredentialsRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_dotted_cors_call_emits():
    """Report one finding for a credentialed wildcard call made as flask_cors.CORS.

    Returns:
        None after checking for one finding from a credentialed wildcard call to flask_cors.CORS.
    """
    src = "import flask_cors\nflask_cors.CORS(app, supports_credentials=True, origins='*')\n"
    findings = CorsWildcardWithCredentialsRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_unrelated_cors_named_call_with_no_supports_creds_skipped():
    """A CORS-named call without supports_credentials kwarg does not fire.

    Returns:
        None after checking that a wildcard CORS call from another library yields no findings when it omits supports_credentials.
    """
    src = "from other_lib import CORS\nCORS(app, origins='*')\n"
    assert CorsWildcardWithCredentialsRule().analyse(make_unit(src), default_ctx()) == []


def test_carries_security_metadata():
    """Label the credentialed wildcard finding with the cors-policy sink, cross-origin-request source and flask-cors shape.

    Returns:
        None after checking the first finding's sink label, source label and shape.
    """
    src = "from flask_cors import CORS\nCORS(app, supports_credentials=True, origins='*')\n"
    finding = CorsWildcardWithCredentialsRule().analyse(make_unit(src), default_ctx())[0]
    assert finding.metadata["sinkLabel"] == "cors-policy"
    assert finding.metadata["sourceLabel"] == "cross-origin-request"
    assert finding.metadata["shape"] == "flask-cors"
