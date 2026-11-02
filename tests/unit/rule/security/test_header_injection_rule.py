from gruffpy.rule.security.header_injection_rule import HeaderInjectionRule
from tests.unit.rule.security._helpers import default_ctx, make_unit


def test_flask_dynamic_header_key_emits():
    """Report one finding for a Flask view that sets a response header named by a request argument."""
    src = (
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.route('/x')\n"
        "def view():\n"
        "    response = make_response('hi')\n"
        "    response.headers[request.args['name']] = 'value'\n"
        "    return response\n"
    )
    findings = HeaderInjectionRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_flask_literal_header_key_skipped():
    """Report nothing for a Flask view that sets a literal header name."""
    src = (
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "@app.route('/x')\n"
        "def view():\n"
        "    response = make_response('hi')\n"
        "    response.headers['X-Custom'] = 'value'\n"
        "    return response\n"
    )
    assert HeaderInjectionRule().analyse(make_unit(src), default_ctx()) == []


def test_no_framework_import_skipped():
    """Report nothing for a dynamic header name in a file without a framework import."""
    src = "response.headers[user_input] = 'x'\n"
    assert HeaderInjectionRule().analyse(make_unit(src), default_ctx()) == []
