"""Cumulative security-pillar fixture + safe-equivalent regression set."""

from gruffpy.rule.registry import RuleRegistry
from tests.unit.rule.security._helpers import default_ctx, make_unit

_DANGEROUS_FIXTURE = """import hashlib
import jinja2
import os
import paramiko
import pickle
import random
import requests
import socket
import ssl
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import yaml

from contextlib import suppress
from django.db.models.expressions import RawSQL
from django.utils.safestring import mark_safe
from flask import Flask, request
from flask_cors import CORS


SECRET_KEY = "do-not-ship-this"
app = Flask(__name__)
CORS(app, supports_credentials=True, origins="*")


@app.route("/echo")
def echo():
    eval(request.args["code"])
    cmd = request.args["cmd"]
    subprocess.run(f"rm {cmd}", shell=True)
    os.system(f"echo {cmd}")
    body = request.json
    pickle.loads(body)
    yaml.unsafe_load(body)
    response = make_response("hi")
    response.headers[request.args["h"]] = "x"
    Foo(**request.json)
    cursor.execute(f"SELECT * FROM t WHERE id = {request.args['id']}")
    password_hash = hashlib.md5(request.args["password"].encode()).hexdigest()
    token = random.randint(0, 99999999)
    requests.get(request.args["url"], verify=False)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    tree = ET.parse(request.args["doc"])
    env = jinja2.Environment(loader=loader)
    rendered = mark_safe(request.args["html"])
    raw = Model.objects.raw(f"SELECT * FROM t WHERE x={request.args['x']}")
    expr = RawSQL(f"SUM(x) WHERE id = {request.args['id']}", [])
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    sock = socket.socket()
    sock.bind(("0.0.0.0", 9000))
    tmp = tempfile.mktemp()
    payload = open(request.args["file"]).read()
    with suppress(Exception):
        risky()
    try:
        risky()
    except Exception:
        pass
    return response


app.run(host="0.0.0.0", debug=True)
"""

_EXPECTED_RULE_IDS = {
    "security.cors-wildcard-with-credentials",
    "security.dangerous-function-call",
    "security.disabled-ssl-verification",
    "security.django-mark-safe",
    "security.django-raw-sql",
    "security.error-suppression",
    "security.extract-compact-user-input",
    "security.flask-debug-enabled",
    "security.hardcoded-bind-all-interfaces",
    "security.hardcoded-framework-secret-key",
    "security.header-injection",
    "security.insecure-random",
    "security.insecure-temp-file",
    "security.insecure-tls-protocol",
    "security.jinja2-autoescape-off",
    "security.paramiko-no-host-key-check",
    "security.path-traversal",
    "security.shell-injection",
    "security.silent-except",
    "security.sql-concatenation",
    "security.ssrf",
    "security.unsafe-pickle",
    "security.unsafe-yaml-load",
    "security.weak-crypto",
    "security.xxe",
}


def test_every_dangerous_rule_fires():
    findings = RuleRegistry.defaults().analyse([make_unit(_DANGEROUS_FIXTURE)], default_ctx())
    rule_ids = {f.rule_id for f in findings}
    missing = _EXPECTED_RULE_IDS - rule_ids
    assert not missing, f"Missing fires: {sorted(missing)}"


_SAFE_FIXTURE = '''import hashlib
import requests
import secrets
import subprocess
import yaml


def process(items):
    """Safe equivalents - every line is the recommended alternative."""
    requests.get("https://api.example.com", verify=True)
    yaml.safe_load(items["yaml"])
    cursor.execute("SELECT * FROM t WHERE id = ?", (items["id"],))
    digest = hashlib.sha256(items["content"]).hexdigest()
    token = secrets.token_hex(32)
    subprocess.run(["ls", "-la"])
    try:
        risky()
    except KeyError:
        handle_missing()
    return digest, token
'''


def test_safe_equivalents_emit_no_security_findings():
    findings = RuleRegistry.defaults().analyse([make_unit(_SAFE_FIXTURE)], default_ctx())
    security_findings = [f for f in findings if f.rule_id.startswith("security.")]
    assert security_findings == [], (
        f"Safe fixture should not trigger security rules: "
        f"{[(f.rule_id, f.message) for f in security_findings]}"
    )


def test_security_registry_has_expected_rule_count():
    ids = {
        rule.definition().id
        for rule in RuleRegistry.defaults().all()
        if rule.definition().id.startswith("security.")
    }
    assert len(ids) == 31
    assert _EXPECTED_RULE_IDS.issubset(ids)
    # `security.variable-import` is intentionally absent from the dangerous
    # fixture above because the fixture's `eval` covers the import surface.
    assert "security.variable-import" in ids
