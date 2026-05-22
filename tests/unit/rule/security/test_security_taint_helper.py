"""Unit tests for the intra-procedural taint-lite helper.

The tests exercise each lever in ADR-017: source recognition, sanitiser
short-circuit, propagation shapes, reassignment kill, conservative branch
joins, nested-function reset.
"""

import ast

from gruffpy.rule.security._security_taint_helper import TaintAnalyser


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
    src = (
        "from flask import request\n"
        "def view():\n"
        "    sink(request.json)\n"
    )
    tree, analyser = _analyse(src)
    taint_map = analyser.analyse_tree(tree)
    sink = _find_call(tree, "sink")
    assert taint_map.is_tainted(sink.args[0])


def test_assignment_propagates_taint():
    src = (
        "from flask import request\n"
        "def view():\n"
        "    x = request.json\n"
        "    sink(x)\n"
    )
    tree, analyser = _analyse(src)
    taint_map = analyser.analyse_tree(tree)
    sink = _find_call(tree, "sink")
    assert taint_map.is_tainted(sink.args[0])


def test_subscript_of_tainted_is_tainted():
    src = (
        "from flask import request\n"
        "def view():\n"
        "    body = request.json\n"
        "    sink(body['url'])\n"
    )
    tree, analyser = _analyse(src)
    taint_map = analyser.analyse_tree(tree)
    sink = _find_call(tree, "sink")
    assert taint_map.is_tainted(sink.args[0])


def test_attribute_of_tainted_is_tainted():
    src = (
        "from flask import request\n"
        "def view():\n"
        "    user = request.json\n"
        "    sink(user.name)\n"
    )
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
    src = (
        "from flask import request\n"
        "x = request.json\n"
        "sink(x)\n"
    )
    tree, analyser = _analyse(src)
    taint_map = analyser.analyse_tree(tree)
    sink = _find_call(tree, "sink")
    assert taint_map.is_tainted(sink.args[0])


def test_self_request_attr_recognised_as_source():
    """A `self.request.json`-style access (Django CBV idiom) is a source."""
    src = (
        "class View:\n"
        "    def get(self):\n"
        "        sink(self.request.json)\n"
    )
    tree, analyser = _analyse(src)
    taint_map = analyser.analyse_tree(tree)
    sink = _find_call(tree, "sink")
    assert taint_map.is_tainted(sink.args[0])
