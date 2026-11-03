from gruffpy.rule.security.variable_import_rule import VariableImportRule
from tests.unit.rule.security._helpers import default_ctx, make_unit


def test_importlib_dynamic_emits():
    """Report one finding for ``importlib.import_module`` on a request-derived name."""
    src = "import importlib\nname = request.args['mod']\nimportlib.import_module(name)\n"
    findings = VariableImportRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_importlib_literal_skipped():
    """Report nothing for ``importlib.import_module`` on a literal."""
    src = "import importlib\nimportlib.import_module('os')\n"
    assert VariableImportRule().analyse(make_unit(src), default_ctx()) == []


def test_import_module_bare_emits():
    """Report one finding for a directly imported ``import_module`` on a variable."""
    src = "from importlib import import_module\nimport_module(name)\n"
    findings = VariableImportRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_module_constant_concat_skipped():
    """Report nothing for an import name built by concatenating a module string constant and a literal."""
    src = 'import importlib\nPLUGIN_PACKAGE = "plugins.core"\nimportlib.import_module(PLUGIN_PACKAGE + ".loader")\n'
    assert VariableImportRule().analyse(make_unit(src), default_ctx()) == []


def test_module_constant_fstring_skipped():
    """Report nothing for an import name built as an f-string of a module string constant."""
    src = 'from importlib import import_module\nPLUGIN_PACKAGE = "plugins.core"\nimport_module(f"{PLUGIN_PACKAGE}.loader")\n'
    assert VariableImportRule().analyse(make_unit(src), default_ctx()) == []


def test_function_parameter_concat_still_emits():
    """Report one finding for an import name built from a function parameter."""
    src = 'from importlib import import_module\ndef load(pkg):\n    import_module(pkg + ".loader")\n'
    findings = VariableImportRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_non_literal_all_caps_assignment_still_emits():
    """Report one finding when the all-caps module name is assigned ``input()``."""
    src = "from importlib import import_module\nPLUGIN_PACKAGE = input()\nimport_module(PLUGIN_PACKAGE)\n"
    findings = VariableImportRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_reassigned_module_constant_still_emits():
    """Report one finding when the all-caps constant is assigned twice at module level."""
    src = (
        "from importlib import import_module\n"
        'PLUGIN_PACKAGE = "plugins.core"\n'
        'PLUGIN_PACKAGE = "plugins.other"\n'
        'import_module(PLUGIN_PACKAGE + ".loader")\n'
    )
    findings = VariableImportRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_global_rebound_module_constant_still_emits():
    """Report one finding when a function rebinds the constant through ``global``."""
    src = (
        "from importlib import import_module\n"
        'PLUGIN_PACKAGE = "plugins.core"\n'
        "def configure():\n"
        "    global PLUGIN_PACKAGE\n"
        '    PLUGIN_PACKAGE = "plugins.other"\n'
        'import_module(PLUGIN_PACKAGE + ".loader")\n'
    )
    findings = VariableImportRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_lowercase_constant_boundary_still_emits():
    """Report one finding when the module-level string uses a lowercase name."""
    src = 'from importlib import import_module\nplugin_package = "plugins.core"\nimport_module(plugin_package + ".loader")\n'
    findings = VariableImportRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_conditionally_rebound_module_constant_still_emits():
    """Report one finding when a module-level ``if`` block may rebind the constant."""
    src = (
        "from importlib import import_module\n"
        'PLUGIN_PACKAGE = "plugins.core"\n'
        "if OVERRIDE:\n"
        "    PLUGIN_PACKAGE = load_override()\n"
        'import_module(PLUGIN_PACKAGE + ".loader")\n'
    )
    findings = VariableImportRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
