from gruffpy.rule.security.hardcoded_bind_all_interfaces_rule import (
    HardcodedBindAllInterfacesRule,
)
from tests.unit.rule.security._helpers import default_ctx, make_unit


def test_flask_run_host_wildcard_emits():
    src = "from flask import Flask\napp = Flask(__name__)\napp.run(host='0.0.0.0')\n"
    findings = HardcodedBindAllInterfacesRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["address"] == "0.0.0.0"


def test_uvicorn_run_host_wildcard_emits():
    src = "import uvicorn\nuvicorn.run('app:api', host='0.0.0.0', port=8000)\n"
    findings = HardcodedBindAllInterfacesRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_run_host_loopback_skipped():
    src = "from flask import Flask\napp = Flask(__name__)\napp.run(host='127.0.0.1')\n"
    assert HardcodedBindAllInterfacesRule().analyse(make_unit(src), default_ctx()) == []


def test_run_host_localhost_skipped():
    src = "from flask import Flask\napp = Flask(__name__)\napp.run(host='localhost')\n"
    assert HardcodedBindAllInterfacesRule().analyse(make_unit(src), default_ctx()) == []


def test_run_no_host_kwarg_skipped():
    src = "from flask import Flask\napp = Flask(__name__)\napp.run(port=5000)\n"
    assert HardcodedBindAllInterfacesRule().analyse(make_unit(src), default_ctx()) == []


def test_socket_bind_wildcard_tuple_emits():
    src = (
        "import socket\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "s.bind(('0.0.0.0', 8080))\n"
    )
    findings = HardcodedBindAllInterfacesRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_socket_bind_loopback_tuple_skipped():
    src = "import socket\ns = socket.socket()\ns.bind(('127.0.0.1', 8080))\n"
    assert HardcodedBindAllInterfacesRule().analyse(make_unit(src), default_ctx()) == []


def test_ipv6_wildcard_emits():
    src = "import socket\ns = socket.socket()\ns.bind(('::', 8080))\n"
    findings = HardcodedBindAllInterfacesRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["address"] == "::"


def test_run_host_dynamic_skipped():
    """Non-literal host kwarg is skipped - we cannot prove unsafety."""
    src = (
        "import os\nfrom flask import Flask\napp = Flask(__name__)\n"
        "app.run(host=os.getenv('HOST'))\n"
    )
    assert HardcodedBindAllInterfacesRule().analyse(make_unit(src), default_ctx()) == []


def test_carries_security_metadata():
    src = "from flask import Flask\napp = Flask(__name__)\napp.run(host='0.0.0.0')\n"
    finding = HardcodedBindAllInterfacesRule().analyse(make_unit(src), default_ctx())[0]
    assert finding.metadata["sinkLabel"] == "bind-address"
    assert finding.metadata["sourceLabel"] == "network-listener"
