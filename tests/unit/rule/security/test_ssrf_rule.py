"""Receiver and URL-argument contract for ``security.ssrf``.

Scanner users should see SSRF only for the direct HTTP-client calls documented
by the rule. The positive matrix pins every supported receiver and positional
or ``url=`` form; negatives keep application methods, literal URLs, and killed
taint quiet so agents are not told to rewrite unrelated code.
"""

import pytest

from gruffpy.finding.finding import Finding
from gruffpy.rule.security.ssrf_rule import SsrfRule
from tests.unit.rule.security._helpers import default_ctx, make_unit

_SUPPORTED_POSITIONAL_SINKS = (
    pytest.param(
        "import requests", "requests.get(target_url)", "requests.get", id="requests-get-positional"
    ),
    pytest.param(
        "import requests",
        "requests.post(target_url)",
        "requests.post",
        id="requests-post-positional",
    ),
    pytest.param(
        "import requests", "requests.put(target_url)", "requests.put", id="requests-put-positional"
    ),
    pytest.param(
        "import requests",
        "requests.patch(target_url)",
        "requests.patch",
        id="requests-patch-positional",
    ),
    pytest.param(
        "import requests",
        "requests.delete(target_url)",
        "requests.delete",
        id="requests-delete-positional",
    ),
    pytest.param(
        "import requests",
        "requests.head(target_url)",
        "requests.head",
        id="requests-head-positional",
    ),
    pytest.param(
        "import requests",
        "requests.options(target_url)",
        "requests.options",
        id="requests-options-positional",
    ),
    pytest.param(
        "import requests",
        'requests.request("GET", target_url)',
        "requests.request",
        id="requests-request-positional",
    ),
    pytest.param("import httpx", "httpx.get(target_url)", "httpx.get", id="httpx-get-positional"),
    pytest.param(
        "import httpx", "httpx.post(target_url)", "httpx.post", id="httpx-post-positional"
    ),
    pytest.param("import httpx", "httpx.put(target_url)", "httpx.put", id="httpx-put-positional"),
    pytest.param(
        "import httpx", "httpx.patch(target_url)", "httpx.patch", id="httpx-patch-positional"
    ),
    pytest.param(
        "import httpx", "httpx.delete(target_url)", "httpx.delete", id="httpx-delete-positional"
    ),
    pytest.param(
        "import httpx", "httpx.head(target_url)", "httpx.head", id="httpx-head-positional"
    ),
    pytest.param(
        "import httpx", "httpx.options(target_url)", "httpx.options", id="httpx-options-positional"
    ),
    pytest.param(
        "import httpx",
        'httpx.request("GET", target_url)',
        "httpx.request",
        id="httpx-request-positional",
    ),
    pytest.param(
        "import urllib.request",
        "urllib.request.urlopen(target_url)",
        "urllib.request.urlopen",
        id="urllib-request-urlopen-positional",
    ),
    pytest.param(
        "from urllib.request import urlopen",
        "urlopen(target_url)",
        "urlopen",
        id="bare-urlopen-positional",
    ),
)

_SUPPORTED_KEYWORD_SINKS = (
    pytest.param(
        "import requests",
        "requests.get(url=target_url)",
        "requests.get",
        id="requests-get-keyword-url",
    ),
    pytest.param(
        "import requests",
        "requests.post(url=target_url)",
        "requests.post",
        id="requests-post-keyword-url",
    ),
    pytest.param(
        "import requests",
        "requests.put(url=target_url)",
        "requests.put",
        id="requests-put-keyword-url",
    ),
    pytest.param(
        "import requests",
        "requests.patch(url=target_url)",
        "requests.patch",
        id="requests-patch-keyword-url",
    ),
    pytest.param(
        "import requests",
        "requests.delete(url=target_url)",
        "requests.delete",
        id="requests-delete-keyword-url",
    ),
    pytest.param(
        "import requests",
        "requests.head(url=target_url)",
        "requests.head",
        id="requests-head-keyword-url",
    ),
    pytest.param(
        "import requests",
        "requests.options(url=target_url)",
        "requests.options",
        id="requests-options-keyword-url",
    ),
    pytest.param(
        "import requests",
        'requests.request(method="GET", url=target_url)',
        "requests.request",
        id="requests-request-keyword-url",
    ),
    pytest.param(
        "import httpx", "httpx.get(url=target_url)", "httpx.get", id="httpx-get-keyword-url"
    ),
    pytest.param(
        "import httpx", "httpx.post(url=target_url)", "httpx.post", id="httpx-post-keyword-url"
    ),
    pytest.param(
        "import httpx", "httpx.put(url=target_url)", "httpx.put", id="httpx-put-keyword-url"
    ),
    pytest.param(
        "import httpx", "httpx.patch(url=target_url)", "httpx.patch", id="httpx-patch-keyword-url"
    ),
    pytest.param(
        "import httpx",
        "httpx.delete(url=target_url)",
        "httpx.delete",
        id="httpx-delete-keyword-url",
    ),
    pytest.param(
        "import httpx", "httpx.head(url=target_url)", "httpx.head", id="httpx-head-keyword-url"
    ),
    pytest.param(
        "import httpx",
        "httpx.options(url=target_url)",
        "httpx.options",
        id="httpx-options-keyword-url",
    ),
    pytest.param(
        "import httpx",
        'httpx.request(method="GET", url=target_url)',
        "httpx.request",
        id="httpx-request-keyword-url",
    ),
    pytest.param(
        "import urllib.request",
        "urllib.request.urlopen(url=target_url)",
        "urllib.request.urlopen",
        id="urllib-request-urlopen-keyword-url",
    ),
    pytest.param(
        "from urllib.request import urlopen",
        "urlopen(url=target_url)",
        "urlopen",
        id="bare-urlopen-keyword-url",
    ),
)

_SUPPORTED_SINKS = _SUPPORTED_POSITIONAL_SINKS + _SUPPORTED_KEYWORD_SINKS


def _ssrf_findings_for_supported_call(
    http_client_import: str,
    http_client_call: str,
    target_url_assignment: str,
) -> list[Finding]:
    """Run the rule for one documented HTTP call in a small user endpoint.

    Args:
        http_client_import: Direct import required by the supported call shape.
        http_client_call: HTTP call statement the scanner user wrote.
        target_url_assignment: Source lines that make the URL tainted, fixed, or killed.

    Returns:
        SSRF findings the user would receive for the call.
    """
    source = (
        f"{http_client_import}\n"
        "from flask import request\n"
        "def fetch():\n"
        f"    {target_url_assignment}\n"
        f"    {http_client_call}\n"
    )
    return SsrfRule().analyse(make_unit(source), default_ctx())


@pytest.mark.parametrize(
    ("http_client_import", "http_client_call", "expected_target"),
    _SUPPORTED_POSITIONAL_SINKS,
)
def test_supported_sink_matrix_positional_url_emits(
    http_client_import: str,
    http_client_call: str,
    expected_target: str,
) -> None:
    """Show one SSRF finding for every documented positional URL call.

    Args:
        http_client_import: Direct import required by the supported call shape.
        http_client_call: HTTP call statement the scanner user wrote.
        expected_target: Stable target label the finding should display.
    """
    findings = _ssrf_findings_for_supported_call(
        http_client_import,
        http_client_call,
        'target_url = request.args["url"]',
    )
    assert [finding.metadata["target"] for finding in findings] == [expected_target]


@pytest.mark.parametrize(
    ("http_client_import", "http_client_call", "expected_target"),
    _SUPPORTED_KEYWORD_SINKS,
)
def test_supported_sink_matrix_keyword_url_emits(
    http_client_import: str,
    http_client_call: str,
    expected_target: str,
) -> None:
    """Show one SSRF finding for every documented ``url=`` call.

    Args:
        http_client_import: Direct import required by the supported call shape.
        http_client_call: HTTP call statement the scanner user wrote.
        expected_target: Stable target label the finding should display.
    """
    findings = _ssrf_findings_for_supported_call(
        http_client_import,
        http_client_call,
        'target_url = request.args["url"]',
    )
    assert [finding.metadata["target"] for finding in findings] == [expected_target]


@pytest.mark.parametrize(
    ("http_client_import", "http_client_call", "expected_target"),
    _SUPPORTED_SINKS,
)
def test_supported_sink_matrix_literal_url_stays_quiet(
    http_client_import: str,
    http_client_call: str,
    expected_target: str,
) -> None:
    """Keep every documented HTTP call quiet when its URL is fixed.

    Args:
        http_client_import: Direct import required by the supported call shape.
        http_client_call: HTTP call statement the scanner user wrote.
        expected_target: Matrix label retained to make each quiet case identifiable.
    """
    del expected_target
    findings = _ssrf_findings_for_supported_call(
        http_client_import,
        http_client_call,
        'target_url = "https://api.example.com/healthcheck"',
    )
    assert findings == []


@pytest.mark.parametrize(
    ("http_client_import", "http_client_call", "expected_target"),
    _SUPPORTED_SINKS,
)
def test_supported_sink_matrix_killed_taint_stays_quiet(
    http_client_import: str,
    http_client_call: str,
    expected_target: str,
) -> None:
    """Keep every documented HTTP call quiet after the user replaces taint.

    Args:
        http_client_import: Direct import required by the supported call shape.
        http_client_call: HTTP call statement the scanner user wrote.
        expected_target: Matrix label retained to make each quiet case identifiable.
    """
    del expected_target
    findings = _ssrf_findings_for_supported_call(
        http_client_import,
        http_client_call,
        'target_url = request.args["url"]\n    target_url = "https://api.example.com/static"',
    )
    assert findings == []


@pytest.mark.parametrize(
    ("receiver_setup", "receiver_call"),
    (
        pytest.param("cache = {}", "cache.get(target_url)", id="cache-get"),
        pytest.param("mapping = {}", "mapping.get(target_url)", id="mapping-get"),
        pytest.param("client = LocalClient()", "client.get(target_url)", id="client-get"),
        pytest.param(
            "application = LocalClient()",
            'application.request("GET", target_url)',
            id="application-request",
        ),
    ),
    ids=("cache-get", "mapping-get", "client-get", "application-request"),
)
def test_unrelated_receiver_with_http_import_stays_quiet(
    receiver_setup: str,
    receiver_call: str,
) -> None:
    """Do not label application-owned ``get`` or ``request`` calls as SSRF.

    Args:
        receiver_setup: Local object setup that proves the receiver is application-owned.
        receiver_call: Unrelated method call receiving user-controlled data.
    """
    source = (
        "import requests\n"
        "from flask import request\n"
        "class LocalClient:\n"
        "    def get(self, value): return value\n"
        "    def request(self, method, value): return method, value\n"
        "def inspect_receiver():\n"
        "    target_url = request.args['url']\n"
        f"    {receiver_setup}\n"
        f"    {receiver_call}\n"
    )
    assert SsrfRule().analyse(make_unit(source), default_ctx()) == []


def test_bare_get_is_not_supported_http_sink() -> None:
    """Keep a bare application ``get(...)`` call out of the HTTP-client matrix."""
    source = (
        "import requests\n"
        "from flask import request\n"
        "def inspect_receiver():\n"
        "    target_url = request.args['url']\n"
        "    get(target_url)\n"
    )
    assert SsrfRule().analyse(make_unit(source), default_ctx()) == []


@pytest.mark.parametrize(
    ("receiver_name", "receiver_call"),
    (
        pytest.param("requests", "requests.get(target_url)", id="requests"),
        pytest.param("httpx", "httpx.get(target_url)", id="httpx"),
    ),
)
def test_application_owned_http_module_name_without_import_stays_quiet(
    receiver_name: str,
    receiver_call: str,
) -> None:
    """A familiar receiver spelling alone is not proof of an HTTP-client sink.

    Args:
        receiver_name: Application variable that resembles a supported module.
        receiver_call: Same-shaped application method receiving tainted data.
    """
    source = (
        "from flask import request\n"
        "class LocalClient:\n"
        "    def get(self, value): return value\n"
        f"{receiver_name} = LocalClient()\n"
        "def fetch():\n"
        "    target_url = request.args['url']\n"
        f"    {receiver_call}\n"
    )

    assert SsrfRule().analyse(make_unit(source), default_ctx()) == []


@pytest.mark.parametrize("receiver_name", ("requests", "httpx"))
def test_rebound_http_module_import_stays_quiet(receiver_name: str) -> None:
    """A module assignment invalidates earlier HTTP-client import evidence.

    Args:
        receiver_name: Supported module root replaced by an application object.
    """
    source = (
        f"import {receiver_name}\n"
        "from flask import request\n"
        "class LocalClient:\n"
        "    def get(self, value): return value\n"
        f"{receiver_name} = LocalClient()\n"
        "def fetch():\n"
        "    target_url = request.args['url']\n"
        f"    {receiver_name}.get(target_url)\n"
    )

    assert SsrfRule().analyse(make_unit(source), default_ctx()) == []


@pytest.mark.parametrize("receiver_name", ("requests", "httpx"))
def test_function_parameter_shadowing_http_module_stays_quiet(receiver_name: str) -> None:
    """A local parameter is not the otherwise imported HTTP-client module.

    Args:
        receiver_name: Supported module root reused as a callback parameter.
    """
    source = (
        f"import {receiver_name}\n"
        "from flask import request\n"
        f"def fetch({receiver_name}):\n"
        "    target_url = request.args['url']\n"
        f"    {receiver_name}.get(target_url)\n"
    )

    assert SsrfRule().analyse(make_unit(source), default_ctx()) == []


def test_module_import_after_function_definition_still_proves_receiver() -> None:
    """A global import is resolved when the previously defined endpoint runs."""
    source = (
        "from flask import request\n"
        "def fetch():\n"
        "    target_url = request.args['url']\n"
        "    requests.get(target_url)\n"
        "import requests\n"
    )

    findings = SsrfRule().analyse(make_unit(source), default_ctx())

    assert [finding.metadata["target"] for finding in findings] == ["requests.get"]


@pytest.mark.parametrize(
    "import_block",
    (
        "import requests.adapters\n",
        "import requests\nimport requests.adapters\n",
        "import requests.adapters\nimport requests\n",
    ),
    ids=(
        "submodule-only",
        "package-then-submodule",
        "submodule-then-package",
    ),
)
def test_submodule_import_still_proves_the_http_client(import_block: str) -> None:
    """A submodule import binds the same package root, so the sink stays visible.

    ``import requests.adapters`` binds ``requests`` exactly as ``import requests``
    does, and configuring an adapter alongside the package is ordinary usage. If
    either spelling is read as a shadowing binding the rule goes silent on a real
    tainted sink.

    Args:
        import_block: Supported package or submodule import ordering under test.
    """
    source = (
        f"{import_block}"
        "from flask import request\n"
        "def fetch():\n"
        "    target_url = request.args['url']\n"
        "    requests.get(target_url)\n"
    )

    findings = SsrfRule().analyse(make_unit(source), default_ctx())

    assert [finding.metadata["target"] for finding in findings] == ["requests.get"]


def test_unrelated_module_sharing_a_client_name_prefix_stays_quiet() -> None:
    """``requests_oauthlib`` is a different distribution, not the supported client."""
    source = (
        "import requests_oauthlib\n"
        "from flask import request\n"
        "def fetch():\n"
        "    target_url = request.args['url']\n"
        "    requests.get(target_url)\n"
    )

    assert SsrfRule().analyse(make_unit(source), default_ctx()) == []


def test_parent_package_import_alone_does_not_prove_qualified_urlopen() -> None:
    """``import urllib`` does not bind ``urllib.request``, so the sink stays unproven."""
    source = (
        "import urllib\n"
        "from flask import request\n"
        "def fetch():\n"
        "    target_url = request.args['url']\n"
        "    urllib.request.urlopen(target_url)\n"
    )

    assert SsrfRule().analyse(make_unit(source), default_ctx()) == []


@pytest.mark.parametrize(
    ("source", "expected_target"),
    (
        pytest.param(
            "from flask import request\n"
            "class LocalClient:\n"
            "    def get(self, url): return url\n"
            "requests = LocalClient()\n"
            "def fetch():\n"
            "    target_url = request.args['url']\n"
            "    requests.get(target_url)\n"
            "import requests\n",
            "requests.get",
            id="requests-shadow-then-import",
        ),
        pytest.param(
            "from flask import request\n"
            "class LocalClient:\n"
            "    def get(self, url): return url\n"
            "httpx = LocalClient()\n"
            "def fetch():\n"
            "    target_url = request.args['url']\n"
            "    httpx.get(target_url)\n"
            "import httpx\n",
            "httpx.get",
            id="httpx-shadow-then-import",
        ),
        pytest.param(
            "from flask import request\n"
            "def urlopen(url): return url\n"
            "def fetch():\n"
            "    target_url = request.args['url']\n"
            "    urlopen(target_url)\n"
            "from urllib.request import urlopen\n",
            "urlopen",
            id="bare-urlopen-shadow-then-import",
        ),
        pytest.param(
            "from flask import request\n"
            "urllib = object()\n"
            "def fetch():\n"
            "    target_url = request.args['url']\n"
            "    urllib.request.urlopen(target_url)\n"
            "import urllib.request\n",
            "urllib.request.urlopen",
            id="qualified-urlopen-shadow-then-import",
        ),
    ),
    ids=(
        "requests-shadow-then-import",
        "httpx-shadow-then-import",
        "bare-urlopen-shadow-then-import",
        "qualified-urlopen-shadow-then-import",
    ),
)
def test_restoring_module_import_after_shadow_proves_receiver(
    source: str,
    expected_target: str,
) -> None:
    """Trust the last module-scope binding a called function actually sees.

    The whole module executes before the endpoint runs, so a canonical import
    that follows an earlier shadow restores the documented client.

    Args:
        source: Module shadow, then the endpoint, then the canonical import.
        expected_target: Documented client spelling reported to the user.
    """
    findings = SsrfRule().analyse(make_unit(source), default_ctx())

    assert [finding.metadata["target"] for finding in findings] == [expected_target]


@pytest.mark.parametrize(
    "source",
    (
        pytest.param(
            "from flask import request\n"
            "import requests\n"
            "class LocalClient:\n"
            "    def get(self, url): return url\n"
            "requests = LocalClient()\n"
            "def fetch():\n"
            "    target_url = request.args['url']\n"
            "    requests.get(target_url)\n",
            id="requests-import-then-shadow",
        ),
        pytest.param(
            "from flask import request\n"
            "import httpx\n"
            "class LocalClient:\n"
            "    def get(self, url): return url\n"
            "httpx = LocalClient()\n"
            "def fetch():\n"
            "    target_url = request.args['url']\n"
            "    httpx.get(target_url)\n",
            id="httpx-import-then-shadow",
        ),
        pytest.param(
            "from flask import request\n"
            "from urllib.request import urlopen\n"
            "def urlopen(url): return url\n"
            "def fetch():\n"
            "    target_url = request.args['url']\n"
            "    urlopen(target_url)\n",
            id="bare-urlopen-import-then-shadow",
        ),
        pytest.param(
            "from flask import request\n"
            "import urllib.request\n"
            "urllib = object()\n"
            "def fetch():\n"
            "    target_url = request.args['url']\n"
            "    urllib.request.urlopen(target_url)\n",
            id="qualified-urlopen-import-then-shadow",
        ),
    ),
    ids=(
        "requests-import-then-shadow",
        "httpx-import-then-shadow",
        "bare-urlopen-import-then-shadow",
        "qualified-urlopen-import-then-shadow",
    ),
)
def test_module_shadow_after_import_keeps_call_quiet(source: str) -> None:
    """Keep application receivers quiet when the shadow is the last binding.

    Args:
        source: Canonical import replaced by an application binding before use.
    """
    assert SsrfRule().analyse(make_unit(source), default_ctx()) == []


def test_application_owned_urllib_receiver_without_import_stays_quiet() -> None:
    """A same-shaped application namespace is not `urllib.request`."""
    source = (
        "from flask import request\n"
        "class RequestClient:\n"
        "    def urlopen(self, value): return value\n"
        "class LocalClient:\n"
        "    request = RequestClient()\n"
        "urllib = LocalClient()\n"
        "def fetch():\n"
        "    target_url = request.args['url']\n"
        "    urllib.request.urlopen(target_url)\n"
    )

    assert SsrfRule().analyse(make_unit(source), default_ctx()) == []


def test_rebound_direct_urlopen_import_stays_quiet() -> None:
    """A local replacement invalidates an earlier bare `urlopen` import."""
    source = (
        "from urllib.request import urlopen\n"
        "from flask import request\n"
        "def identity(value): return value\n"
        "urlopen = identity\n"
        "def fetch():\n"
        "    target_url = request.args['url']\n"
        "    urlopen(target_url)\n"
    )

    assert SsrfRule().analyse(make_unit(source), default_ctx()) == []


@pytest.mark.parametrize(
    ("client_import", "replacement", "client_call"),
    (
        pytest.param(
            "import requests",
            "requests.get = identity",
            "requests.get(target_url)",
        ),
        pytest.param(
            "import httpx",
            "httpx.get = identity",
            "httpx.get(target_url)",
        ),
        pytest.param(
            "import urllib.request",
            "urllib.request.urlopen = identity",
            "urllib.request.urlopen(target_url)",
        ),
    ),
    ids=("requests-method", "httpx-method", "urllib-method"),
)
def test_rebound_http_client_method_stays_quiet(
    client_import: str,
    replacement: str,
    client_call: str,
) -> None:
    """A method overwrite invalidates otherwise genuine module-import proof.

    Args:
        client_import: Direct import that initially establishes client trust.
        replacement: Attribute assignment replacing the supported sink.
        client_call: Same-shaped call after the replacement.
    """
    source = (
        f"{client_import}\n"
        "from flask import request\n"
        "def identity(value): return value\n"
        f"{replacement}\n"
        "def fetch():\n"
        "    target_url = request.args['url']\n"
        f"    {client_call}\n"
    )

    assert SsrfRule().analyse(make_unit(source), default_ctx()) == []


@pytest.mark.parametrize(
    "source",
    (
        pytest.param(
            "import requests\n"
            "from flask import request\n"
            "def identity(value): return value\n"
            "def fetch():\n"
            "    target_url = request.args['url']\n"
            "    requests.get(target_url)\n"
            "    requests.get = identity\n",
        ),
        pytest.param(
            "import requests\n"
            "from flask import request\n"
            "def identity(value): return value\n"
            "def fetch():\n"
            "    target_url = request.args['url']\n"
            "    requests.get(target_url); requests.get = identity\n",
        ),
        pytest.param(
            "import requests\n"
            "from flask import request\n"
            "target_url = request.args['url']\n"
            "requests.get(target_url)\n"
            "requests = object()\n",
        ),
        pytest.param(
            "import requests\n"
            "from flask import request\n"
            "class Fetch:\n"
            "    target_url = request.args['url']\n"
            "    requests.get(target_url)\n"
            "    requests = object()\n",
        ),
        pytest.param(
            "import requests\n"
            "from flask import request\n"
            "def fetch():\n"
            "    global requests\n"
            "    target_url = request.args['url']\n"
            "    requests.get(target_url)\n"
            "    requests = object()\n",
        ),
    ),
    ids=(
        "function-attribute-after-call",
        "same-line-function-attribute-after-call",
        "module-name-after-call",
        "class-name-after-call",
        "global-name-after-call",
    ),
)
def test_later_non_retroactive_rebinding_keeps_earlier_supported_call(
    source: str,
) -> None:
    """Honor execution order for stores that cannot change an earlier call.

    Args:
        source: Direct client call followed by a non-retroactive replacement.
    """
    findings = SsrfRule().analyse(make_unit(source), default_ctx())

    assert [finding.metadata["target"] for finding in findings] == ["requests.get"]


@pytest.mark.parametrize(
    "source",
    (
        pytest.param(
            "import requests\n"
            "from flask import request\n"
            "def fetch():\n"
            "    target_url = request.args['url']\n"
            "    requests.get(target_url)\n"
            "    requests = object()\n",
            id="name-assignment",
        ),
        pytest.param(
            "import requests\n"
            "from flask import request\n"
            "def fetch():\n"
            "    target_url = request.args['url']\n"
            "    requests.get(target_url)\n"
            "    import requests\n",
            id="local-import",
        ),
    ),
)
def test_later_function_local_binding_still_shadows_earlier_spelling(
    source: str,
) -> None:
    """Retain Python's retroactive local-name semantics inside a function.

    Args:
        source: Function whose later local binding invalidates earlier spelling.
    """
    assert SsrfRule().analyse(make_unit(source), default_ctx()) == []


@pytest.mark.parametrize(
    "source",
    (
        pytest.param(
            "import requests as r\n"
            "from flask import request\n"
            "def fetch():\n"
            "    target_url = request.args['url']\n"
            "    r.get(target_url)\n",
            id="requests-alias",
        ),
        pytest.param(
            "import requests\n"
            "from flask import request\n"
            "def fetch():\n"
            "    target_url = request.args['url']\n"
            "    requests.Session().get(target_url)\n",
            id="requests-session",
        ),
        pytest.param(
            "import httpx\n"
            "from flask import request\n"
            "def fetch():\n"
            "    target_url = request.args['url']\n"
            "    httpx.Client().get(target_url)\n",
            id="httpx-client",
        ),
        pytest.param(
            "import requests\n"
            "from flask import request\n"
            "def fetch_url(url):\n"
            "    return requests.get(url)\n"
            "def fetch():\n"
            "    target_url = request.args['url']\n"
            "    fetch_url(target_url)\n",
            id="wrapper-function",
        ),
        pytest.param(
            "import urllib3\n"
            "from flask import request\n"
            "def fetch():\n"
            "    target_url = request.args['url']\n"
            "    pool = urllib3.PoolManager()\n"
            "    pool.request('GET', target_url)\n",
            id="urllib3-pool",
        ),
        pytest.param(
            "from requests import get\n"
            "from flask import request\n"
            "def fetch():\n"
            "    target_url = request.args['url']\n"
            "    get(target_url)\n",
            id="bare-requests-get",
        ),
        pytest.param(
            "from urllib.request import urlopen as open_url\n"
            "from flask import request\n"
            "def fetch():\n"
            "    target_url = request.args['url']\n"
            "    open_url(target_url)\n",
            id="urlopen-alias",
        ),
    ),
    ids=(
        "requests-alias",
        "requests-session",
        "httpx-client",
        "wrapper-function",
        "urllib3-pool",
        "bare-requests-get",
        "urlopen-alias",
    ),
)
def test_deferred_http_client_shapes_stay_quiet(source: str) -> None:
    """Keep aliases, client instances, wrappers, and urllib3 out of findings.

    Args:
        source: User endpoint containing one deliberately unsupported sink shape.
    """
    assert SsrfRule().analyse(make_unit(source), default_ctx()) == []


def test_requests_get_tainted_url_emits():
    """Warn when a Flask URL reaches the common ``requests.get`` sink."""
    src = (
        "import requests\n"
        "from flask import request\n"
        "def fetch():\n"
        "    url = request.args['url']\n"
        "    requests.get(url)\n"
    )
    findings = SsrfRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_requests_get_request_accessor_integration_emits() -> None:
    """Warn when a user sends a Flask query accessor directly to ``requests``."""
    source = (
        "import requests\n"
        "from flask import request\n"
        "def fetch():\n"
        "    requests.get(request.args.get('url'))\n"
    )
    findings = SsrfRule().analyse(make_unit(source), default_ctx())
    assert len(findings) == 1


def test_requests_post_fstring_url_emits():
    """Warn when user input is interpolated into a ``requests.post`` URL."""
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
    """Keep a fixed health-check URL out of the user's SSRF findings."""
    src = (
        "import requests\n"
        "from flask import request\n"
        "def fetch():\n"
        "    requests.get('https://api.example.com/healthcheck')\n"
    )
    assert SsrfRule().analyse(make_unit(src), default_ctx()) == []


def test_requests_request_method_then_tainted_url_emits():
    """Warn when ``requests.request`` receives a tainted positional URL."""
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
    """Warn when a directly imported ``urlopen`` receives a tainted URL."""
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
    """Warn when a Flask URL reaches the common ``httpx.get`` sink."""
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
    """Keep unknown wrappers quiet under ADR-017's conservative posture."""
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
    """Keep a request quiet after the user replaces its tainted URL."""
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
    """Keep branch-ambiguous URLs quiet under the conservative join policy."""
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
    """Keep an unrelated cache lookup quiet when no HTTP client is used."""
    src = (
        "from flask import request\n"
        "def view():\n"
        "    payload = request.args['p']\n"
        "    cache.get(payload)\n"
    )
    assert SsrfRule().analyse(make_unit(src), default_ctx()) == []


def test_carries_security_metadata():
    """Keep the source and sink labels stable for downstream report users."""
    src = (
        "import requests\n"
        "from flask import request\n"
        "def fetch():\n"
        "    requests.get(request.args['url'])\n"
    )
    finding = SsrfRule().analyse(make_unit(src), default_ctx())[0]
    assert finding.metadata["sinkLabel"] == "http-client"
    assert finding.metadata["sourceLabel"] == "user-controlled-url"


def test_module_qualified_request_taints_arg():
    """Warn when the module-qualified Flask proxy reaches ``requests.get``."""
    src = (
        "import requests\nimport flask\ndef fetch():\n    requests.get(flask.request.args['url'])\n"
    )
    findings = SsrfRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_application_object_request_attribute_stays_quiet():
    """Keep an application object's request-shaped attribute out of SSRF findings."""
    src = "import requests\ndef fetch(other):\n    requests.get(other.request.args['url'])\n"
    assert SsrfRule().analyse(make_unit(src), default_ctx()) == []


def test_fastapi_query_parameter_taints_arg():
    """Warn when a FastAPI query parameter reaches ``requests.get``."""
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
