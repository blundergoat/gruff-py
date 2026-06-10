"""Unit tests for shared security AST node helpers."""

import ast

from gruffpy.rule.security._security_node_helper import (
    fixed_string_fragments,
    is_fixed_string_expression,
    module_string_constants,
)


def _expr(source: str) -> ast.expr:
    tree = ast.parse(f"VALUE = {source}\n")
    assign = tree.body[0]
    assert isinstance(assign, ast.Assign)
    return assign.value


def test_module_string_constants_collects_single_assignment_all_caps_strings() -> None:
    tree = ast.parse('PLUGIN_PACKAGE = "plugins.core"\nOTHER = "x"\n')

    assert module_string_constants(tree) == {
        "PLUGIN_PACKAGE": "plugins.core",
        "OTHER": "x",
    }


def test_module_string_constants_rejects_rebound_or_dynamic_names() -> None:
    tree = ast.parse(
        'PLUGIN_PACKAGE = "plugins.core"\n'
        'PLUGIN_PACKAGE = "plugins.other"\n'
        "DYNAMIC = input()\n"
        'lowercase = "ignored"\n'
    )

    assert module_string_constants(tree) == {}


def test_module_string_constants_rejects_global_rebinds() -> None:
    tree = ast.parse(
        'PLUGIN_PACKAGE = "plugins.core"\n'
        "def configure():\n"
        "    global PLUGIN_PACKAGE\n"
        '    PLUGIN_PACKAGE = "plugins.other"\n'
    )

    assert module_string_constants(tree) == {}


def test_module_string_constants_rejects_conditional_module_scope_rebinds() -> None:
    tree = ast.parse('QUERY = "SELECT * FROM users"\nif OVERRIDE:\n    QUERY = load_override()\n')

    assert module_string_constants(tree) == {}


def test_module_string_constants_rejects_try_import_fallback_rebinds() -> None:
    tree = ast.parse(
        'BACKEND = "json"\n'
        "try:\n"
        "    import yaml\n"
        '    BACKEND = "yaml"\n'
        "except ImportError:\n"
        "    pass\n"
    )

    assert module_string_constants(tree) == {}


def test_module_string_constants_keeps_constants_despite_function_local_shadows() -> None:
    tree = ast.parse(
        'PLUGIN_PACKAGE = "plugins.core"\n'
        "def helper():\n"
        '    PLUGIN_PACKAGE = "local-only"\n'
        "    return PLUGIN_PACKAGE\n"
    )

    assert module_string_constants(tree) == {"PLUGIN_PACKAGE": "plugins.core"}


def test_fixed_string_expression_accepts_literals_constants_concat_and_fstrings() -> None:
    constants = {"PLUGIN_PACKAGE": "plugins.core"}

    assert is_fixed_string_expression(_expr('"plugins.core"'), constants)
    assert is_fixed_string_expression(_expr('PLUGIN_PACKAGE + ".loader"'), constants)
    assert is_fixed_string_expression(_expr('f"{PLUGIN_PACKAGE}.loader"'), constants)


def test_fixed_string_expression_rejects_runtime_material() -> None:
    constants = {"PLUGIN_PACKAGE": "plugins.core"}

    assert not is_fixed_string_expression(_expr('plugin_package + ".loader"'), constants)
    assert not is_fixed_string_expression(_expr('f"{PLUGIN_PACKAGE!r}.loader"'), constants)
    assert not is_fixed_string_expression(_expr('f"{PLUGIN_PACKAGE:>12}.loader"'), constants)


def test_fixed_string_fragments_preserves_runtime_context() -> None:
    constants = {"TABLE_PREFIX": "shop"}

    assert fixed_string_fragments(
        _expr('f"SELECT * FROM {TABLE_PREFIX}_orders WHERE id = {oid}"'), constants
    ) == (
        "SELECT * FROM ",
        "shop",
        "_orders WHERE id = ",
    )
