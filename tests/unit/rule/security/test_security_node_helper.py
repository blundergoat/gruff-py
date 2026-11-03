"""Unit tests for shared security AST node helpers."""

import ast

from gruffpy.rule.security._security_node_helper import (
    is_fixed_string_expression,
    module_string_constants,
)


def _expr(source: str) -> ast.expr:
    """Parse ``VALUE = source`` and return the assigned expression.

    Args:
        source: Expression source placed on the right of the assignment.

    Returns:
        The right-hand expression node.

    Raises:
        AssertionError: The parsed statement is not an assignment.
    """
    tree = ast.parse(f"VALUE = {source}\n")
    assign = tree.body[0]
    assert isinstance(assign, ast.Assign)
    return assign.value


def test_module_string_constants_collects_single_assignment_all_caps_strings() -> None:
    """Collect every all-caps string constant that a module assigns once."""
    tree = ast.parse('PLUGIN_PACKAGE = "plugins.core"\nOTHER = "x"\n')

    assert module_string_constants(tree) == {
        "PLUGIN_PACKAGE": "plugins.core",
        "OTHER": "x",
    }


def test_module_string_constants_rejects_rebound_or_dynamic_names() -> None:
    """Collect nothing from a rebound constant, a call result or a lowercase name."""
    tree = ast.parse('PLUGIN_PACKAGE = "plugins.core"\nPLUGIN_PACKAGE = "plugins.other"\nDYNAMIC = input()\nlowercase = "ignored"\n')

    assert module_string_constants(tree) == {}


def test_module_string_constants_rejects_global_rebinds() -> None:
    """Collect nothing when a function rebinds the constant through ``global``."""
    tree = ast.parse('PLUGIN_PACKAGE = "plugins.core"\ndef configure():\n    global PLUGIN_PACKAGE\n    PLUGIN_PACKAGE = "plugins.other"\n')

    assert module_string_constants(tree) == {}


def test_module_string_constants_rejects_conditional_module_scope_rebinds() -> None:
    """Collect nothing when a module-level ``if`` block rebinds the constant."""
    tree = ast.parse('QUERY = "SELECT * FROM users"\nif OVERRIDE:\n    QUERY = load_override()\n')

    assert module_string_constants(tree) == {}


def test_module_string_constants_rejects_try_import_fallback_rebinds() -> None:
    """Collect nothing when a module-level ``try`` body rebinds the constant after an import."""
    tree = ast.parse('BACKEND = "json"\ntry:\n    import yaml\n    BACKEND = "yaml"\nexcept ImportError:\n    pass\n')

    assert module_string_constants(tree) == {}


def test_module_string_constants_keeps_constants_despite_function_local_shadows() -> None:
    """Keep a module constant when a function assigns a local of the same name."""
    tree = ast.parse('PLUGIN_PACKAGE = "plugins.core"\ndef helper():\n    PLUGIN_PACKAGE = "local-only"\n    return PLUGIN_PACKAGE\n')

    assert module_string_constants(tree) == {"PLUGIN_PACKAGE": "plugins.core"}


def test_fixed_string_expression_accepts_literals_constants_concat_and_fstrings() -> None:
    """Accept a string literal, a constant concatenation and an f-string of a constant as fixed strings."""
    constants = {"PLUGIN_PACKAGE": "plugins.core"}

    assert is_fixed_string_expression(_expr('"plugins.core"'), constants)
    assert is_fixed_string_expression(_expr('PLUGIN_PACKAGE + ".loader"'), constants)
    assert is_fixed_string_expression(_expr('f"{PLUGIN_PACKAGE}.loader"'), constants)


def test_fixed_string_expression_rejects_runtime_material() -> None:
    """Reject a concatenation with a lowercase name, and f-strings with a conversion or a format spec, as fixed strings."""
    constants = {"PLUGIN_PACKAGE": "plugins.core"}

    assert not is_fixed_string_expression(_expr('plugin_package + ".loader"'), constants)
    assert not is_fixed_string_expression(_expr('f"{PLUGIN_PACKAGE!r}.loader"'), constants)
    assert not is_fixed_string_expression(_expr('f"{PLUGIN_PACKAGE:>12}.loader"'), constants)
