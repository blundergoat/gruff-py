"""User-source propagation tests for the intra-procedural taint helper.

Security rules consult this helper after parsing a user's web endpoint.
These tests pin the finite request vocabulary, bounded accessor calls,
sanitiser precedence, reassignment kills, branch joins, and scope resets.
Generic collection methods stay untainted so findings remain actionable.
"""

import ast

import pytest

from gruffpy.rule.security._security_taint_helper import TaintAnalyser

_REQUEST_ACCESSOR_SOURCE_EXPRESSIONS = (
    pytest.param("request.args.get('url')", id="flask-args-get"),
    pytest.param("request.form.get('url')", id="flask-form-get"),
    pytest.param("request.values.get('url')", id="flask-values-get"),
    pytest.param("request.get_json()", id="flask-get-json"),
    pytest.param("request.GET.get('url')", id="django-get-get"),
    pytest.param("request.GET.getlist('url')", id="django-get-getlist"),
    pytest.param("request.POST.get('url')", id="django-post-get"),
    pytest.param("request.POST.getlist('url')", id="django-post-getlist"),
    pytest.param("request.data.get('url')", id="drf-data-get"),
    pytest.param("request.query_params.get('url')", id="starlette-query-params-get"),
)

_ACCESSOR_COLLISION_EXPRESSIONS = (
    pytest.param("mapping.get('url')", id="mapping-get"),
    pytest.param("cache.get('url')", id="cache-get"),
    pytest.param("object.data.get('url')", id="object-data-get"),
    pytest.param("request.args.pop('url')", id="tainted-receiver-pop"),
)


def _find_call(tree: ast.AST, target_name: str) -> ast.Call:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and ast.unparse(node.func).endswith(target_name):
            return node
    raise AssertionError(f"call ending with {target_name} not found")


def _analyse(src: str, sanitisers: frozenset[str] = frozenset()) -> tuple[ast.AST, "TaintAnalyser"]:
    tree = ast.parse(src)
    analyser = TaintAnalyser(sanitisers=sanitisers)
    return tree, analyser


def test_request_attr_is_a_source():
    src = "from flask import request\ndef view():\n    sink(request.json)\n"
    tree, analyser = _analyse(src)
    taint_map = analyser.analyse_tree(tree)
    sink = _find_call(tree, "sink")
    assert taint_map.is_tainted(sink.args[0])


def test_assignment_propagates_taint():
    src = "from flask import request\ndef view():\n    x = request.json\n    sink(x)\n"
    tree, analyser = _analyse(src)
    taint_map = analyser.analyse_tree(tree)
    sink = _find_call(tree, "sink")
    assert taint_map.is_tainted(sink.args[0])


def test_subscript_of_tainted_is_tainted():
    src = "from flask import request\ndef view():\n    body = request.json\n    sink(body['url'])\n"
    tree, analyser = _analyse(src)
    taint_map = analyser.analyse_tree(tree)
    sink = _find_call(tree, "sink")
    assert taint_map.is_tainted(sink.args[0])


def test_attribute_of_tainted_is_tainted():
    src = "from flask import request\ndef view():\n    user = request.json\n    sink(user.name)\n"
    tree, analyser = _analyse(src)
    taint_map = analyser.analyse_tree(tree)
    sink = _find_call(tree, "sink")
    assert taint_map.is_tainted(sink.args[0])


def test_fstring_with_tainted_is_tainted():
    src = (
        "from flask import request\n"
        "def view():\n"
        "    x = request.args['q']\n"
        "    sink(f'http://example.com/{x}')\n"
    )
    tree, analyser = _analyse(src)
    taint_map = analyser.analyse_tree(tree)
    sink = _find_call(tree, "sink")
    assert taint_map.is_tainted(sink.args[0])


def test_string_concat_with_tainted_is_tainted():
    src = (
        "from flask import request\n"
        "def view():\n"
        "    x = request.args['q']\n"
        "    sink('prefix' + x)\n"
    )
    tree, analyser = _analyse(src)
    taint_map = analyser.analyse_tree(tree)
    sink = _find_call(tree, "sink")
    assert taint_map.is_tainted(sink.args[0])


def test_percent_format_with_tainted_is_tainted():
    src = (
        "from flask import request\n"
        "def view():\n"
        "    x = request.args['q']\n"
        "    sink('hello %s' % x)\n"
    )
    tree, analyser = _analyse(src)
    taint_map = analyser.analyse_tree(tree)
    sink = _find_call(tree, "sink")
    assert taint_map.is_tainted(sink.args[0])


def test_format_call_with_tainted_arg_is_tainted():
    src = (
        "from flask import request\n"
        "def view():\n"
        "    x = request.args['q']\n"
        "    sink('hello {}'.format(x))\n"
    )
    tree, analyser = _analyse(src)
    taint_map = analyser.analyse_tree(tree)
    sink = _find_call(tree, "sink")
    assert taint_map.is_tainted(sink.args[0])


def test_unknown_call_returns_untainted():
    src = (
        "from flask import request\n"
        "def view():\n"
        "    x = request.args['q']\n"
        "    y = unknown_helper(x)\n"
        "    sink(y)\n"
    )
    tree, analyser = _analyse(src)
    taint_map = analyser.analyse_tree(tree)
    sink = _find_call(tree, "sink")
    assert not taint_map.is_tainted(sink.args[0])


def test_sanitiser_in_allowlist_returns_untainted():
    src = (
        "from flask import request\n"
        "def view():\n"
        "    x = request.args['q']\n"
        "    sink(secure_filename(x))\n"
    )
    tree, analyser = _analyse(src, sanitisers=frozenset({"secure_filename"}))
    taint_map = analyser.analyse_tree(tree)
    sink = _find_call(tree, "sink")
    assert not taint_map.is_tainted(sink.args[0])


def test_reassignment_to_literal_kills_taint():
    src = (
        "from flask import request\n"
        "def view():\n"
        "    x = request.args['q']\n"
        "    x = 'literal'\n"
        "    sink(x)\n"
    )
    tree, analyser = _analyse(src)
    taint_map = analyser.analyse_tree(tree)
    sink = _find_call(tree, "sink")
    assert not taint_map.is_tainted(sink.args[0])


def test_branch_join_is_conservative():
    src = (
        "from flask import request\n"
        "def view(flag):\n"
        "    x = request.args['q']\n"
        "    if flag:\n"
        "        x = 'literal'\n"
        "    sink(x)\n"
    )
    tree, analyser = _analyse(src)
    taint_map = analyser.analyse_tree(tree)
    sink = _find_call(tree, "sink")
    assert not taint_map.is_tainted(sink.args[0])


def test_branch_where_both_keep_tainted_remains_tainted():
    src = (
        "from flask import request\n"
        "def view(flag):\n"
        "    x = request.args['q']\n"
        "    if flag:\n"
        "        x = request.args['p']\n"
        "    sink(x)\n"
    )
    tree, analyser = _analyse(src)
    taint_map = analyser.analyse_tree(tree)
    sink = _find_call(tree, "sink")
    assert taint_map.is_tainted(sink.args[0])


def test_nested_function_resets_scope():
    src = (
        "from flask import request\n"
        "def outer():\n"
        "    x = request.args['q']\n"
        "    def inner():\n"
        "        sink(x)\n"  # different scope: x is not a known taint here
        "    inner()\n"
    )
    tree, analyser = _analyse(src)
    taint_map = analyser.analyse_tree(tree)
    sink = _find_call(tree, "sink")
    assert not taint_map.is_tainted(sink.args[0])


def test_fastapi_query_default_marks_parameter_as_source():
    src = (
        "from fastapi import FastAPI, Query\n"
        "app = FastAPI()\n"
        "@app.get('/')\n"
        "def search(q: str = Query(None)):\n"
        "    sink(q)\n"
    )
    tree, analyser = _analyse(src)
    taint_map = analyser.analyse_tree(tree)
    sink = _find_call(tree, "sink")
    assert taint_map.is_tainted(sink.args[0])


def test_module_scope_request_attr_propagates():
    src = "from flask import request\nx = request.json\nsink(x)\n"
    tree, analyser = _analyse(src)
    taint_map = analyser.analyse_tree(tree)
    sink = _find_call(tree, "sink")
    assert taint_map.is_tainted(sink.args[0])


def test_self_request_attr_recognised_as_source():
    """A `self.request.json`-style access (Django CBV idiom) is a source."""
    src = "class View:\n    def get(self):\n        sink(self.request.json)\n"
    tree, analyser = _analyse(src)
    taint_map = analyser.analyse_tree(tree)
    sink = _find_call(tree, "sink")
    assert taint_map.is_tainted(sink.args[0])


def test_unrelated_request_attribute_is_not_a_framework_source() -> None:
    """Keep an application object's request-shaped attribute outside the source set."""
    source = "def view(other):\n    sink(other.request.json)\n"
    tree, analyser = _analyse(source)
    taint_map = analyser.analyse_tree(tree)
    sink = _find_call(tree, "sink")

    assert not taint_map.is_tainted(sink.args[0])


@pytest.mark.parametrize("request_value_expression", _REQUEST_ACCESSOR_SOURCE_EXPRESSIONS)
def test_request_accessor_framework_shape_is_tainted(request_value_expression: str) -> None:
    """Keep each supported framework accessor visible to security rules.

    Args:
        request_value_expression: Request expression a user passed toward a sink.
    """
    source = f"def view():\n    sink({request_value_expression})\n"
    tree, analyser = _analyse(source)
    taint_map = analyser.analyse_tree(tree)
    sink = _find_call(tree, "sink")
    assert taint_map.is_tainted(sink.args[0])


def test_request_accessor_assigned_get_json_container_preserves_taint() -> None:
    """Keep JSON request data tainted when a user reads a key after assignment."""
    source = (
        "from flask import request\n"
        "def view():\n"
        "    payload = request.get_json()\n"
        "    sink(payload.get('url'))\n"
    )
    tree, analyser = _analyse(source)
    taint_map = analyser.analyse_tree(tree)
    sink = _find_call(tree, "sink")
    assert taint_map.is_tainted(sink.args[0])


@pytest.mark.parametrize("unrelated_accessor_expression", _ACCESSOR_COLLISION_EXPRESSIONS)
def test_request_accessor_collision_stays_untainted(
    unrelated_accessor_expression: str,
) -> None:
    """Keep generic accessors and unsupported methods out of user findings.

    Args:
        unrelated_accessor_expression: Collection call that must not become a source.
    """
    source = (
        f"def view(mapping, cache, object, request):\n    sink({unrelated_accessor_expression})\n"
    )
    tree, analyser = _analyse(source)
    taint_map = analyser.analyse_tree(tree)
    sink = _find_call(tree, "sink")
    assert not taint_map.is_tainted(sink.args[0])


def test_request_accessor_sanitiser_precedence_returns_untainted() -> None:
    """Let a consumer-approved accessor sanitiser override request propagation."""
    source = "from flask import request\ndef view():\n    sink(request.args.get('file'))\n"
    tree, default_analyser = _analyse(source)
    sink = _find_call(tree, "sink")
    unsanitised_taint_map = default_analyser.analyse_tree(tree)
    assert unsanitised_taint_map.is_tainted(sink.args[0])

    sanitising_analyser = TaintAnalyser(sanitisers=frozenset({"get"}))
    sanitised_taint_map = sanitising_analyser.analyse_tree(tree)
    assert not sanitised_taint_map.is_tainted(sink.args[0])
