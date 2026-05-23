from gruffpy.rule.security.ssrf_rule import SsrfRule
from tests.unit.rule.security._helpers import default_ctx, make_unit


def test_requests_get_tainted_url_emits():
    src = (
        "import requests\n"
        "from flask import request\n"
        "def fetch():\n"
        "    url = request.args['url']\n"
        "    requests.get(url)\n"
    )
    findings = SsrfRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_requests_post_fstring_url_emits():
    src = (
        "import requests\n"
        "from flask import request\n"
        "def fetch():\n"
        "    user = request.args['user']\n"
        "    requests.post(f'https://api.example.com/u/{user}')\n"
    )
    findings = SsrfRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_requests_get_literal_url_skipped():
    src = (
        "import requests\n"
        "from flask import request\n"
        "def fetch():\n"
        "    requests.get('https://api.example.com/healthcheck')\n"
    )
    assert SsrfRule().analyse(make_unit(src), default_ctx()) == []


def test_requests_request_method_then_tainted_url_emits():
    src = (
        "import requests\n"
        "from flask import request\n"
        "def fetch():\n"
        "    url = request.args['url']\n"
        "    requests.request('GET', url)\n"
    )
    findings = SsrfRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_urlopen_tainted_url_emits():
    src = (
        "from urllib.request import urlopen\n"
        "from flask import request\n"
        "def fetch():\n"
        "    url = request.args['url']\n"
        "    urlopen(url)\n"
    )
    findings = SsrfRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_httpx_get_tainted_url_emits():
    src = (
        "import httpx\n"
        "from flask import request\n"
        "def fetch():\n"
        "    url = request.args['url']\n"
        "    httpx.get(url)\n"
    )
    findings = SsrfRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_unknown_wrapper_call_breaks_taint():
    """The conservative posture: passing taint through an unknown call sanitises it."""
    src = (
        "import requests\n"
        "from flask import request\n"
        "def fetch():\n"
        "    raw = request.args['url']\n"
        "    safe = build_url(raw)\n"
        "    requests.get(safe)\n"
    )
    assert SsrfRule().analyse(make_unit(src), default_ctx()) == []


def test_reassigned_url_breaks_taint():
    src = (
        "import requests\n"
        "from flask import request\n"
        "def fetch():\n"
        "    url = request.args['url']\n"
        "    url = 'https://api.example.com/static'\n"
        "    requests.get(url)\n"
    )
    assert SsrfRule().analyse(make_unit(src), default_ctx()) == []


def test_branch_join_conservative_kills_taint():
    src = (
        "import requests\n"
        "from flask import request\n"
        "def fetch(flag):\n"
        "    url = request.args['url']\n"
        "    if flag:\n"
        "        url = 'https://api.example.com/static'\n"
        "    requests.get(url)\n"
    )
    assert SsrfRule().analyse(make_unit(src), default_ctx()) == []


def test_no_http_client_imported_skipped():
    """The framework gate prevents firing on .get() in unrelated files."""
    src = (
        "from flask import request\n"
        "def view():\n"
        "    payload = request.args['p']\n"
        "    cache.get(payload)\n"
    )
    assert SsrfRule().analyse(make_unit(src), default_ctx()) == []


def test_carries_security_metadata():
    src = (
        "import requests\n"
        "from flask import request\n"
        "def fetch():\n"
        "    requests.get(request.args['url'])\n"
    )
    finding = SsrfRule().analyse(make_unit(src), default_ctx())[0]
    assert finding.metadata["sinkLabel"] == "http-client"
    assert finding.metadata["sourceLabel"] == "user-controlled-url"


def test_fastapi_query_parameter_taints_arg():
    src = (
        "import requests\n"
        "from fastapi import FastAPI, Query\n"
        "app = FastAPI()\n"
        "@app.get('/')\n"
        "def proxy(url: str = Query(...)):\n"
        "    requests.get(url)\n"
    )
    findings = SsrfRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
