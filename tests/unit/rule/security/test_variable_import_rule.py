from gruffpy.rule.security.variable_import_rule import VariableImportRule
from tests.unit.rule.security._helpers import default_ctx, make_unit


def test_importlib_dynamic_emits():
    src = "import importlib\nname = request.args['mod']\nimportlib.import_module(name)\n"
    findings = VariableImportRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_importlib_literal_skipped():
    src = "import importlib\nimportlib.import_module('os')\n"
    assert VariableImportRule().analyse(make_unit(src), default_ctx()) == []


def test_import_module_bare_emits():
    src = "from importlib import import_module\nimport_module(name)\n"
    findings = VariableImportRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_module_constant_concat_skipped():
    src = (
        "import importlib\n"
        'PLUGIN_PACKAGE = "plugins.core"\n'
        'importlib.import_module(PLUGIN_PACKAGE + ".loader")\n'
    )
    assert VariableImportRule().analyse(make_unit(src), default_ctx()) == []


def test_module_constant_fstring_skipped():
    src = (
        "from importlib import import_module\n"
        'PLUGIN_PACKAGE = "plugins.core"\n'
        'import_module(f"{PLUGIN_PACKAGE}.loader")\n'
    )
    assert VariableImportRule().analyse(make_unit(src), default_ctx()) == []


def test_function_parameter_concat_still_emits():
    src = (
        'from importlib import import_module\ndef load(pkg):\n    import_module(pkg + ".loader")\n'
    )
    findings = VariableImportRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_non_literal_all_caps_assignment_still_emits():
    src = (
        "from importlib import import_module\n"
        "PLUGIN_PACKAGE = input()\n"
        "import_module(PLUGIN_PACKAGE)\n"
    )
    findings = VariableImportRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_reassigned_module_constant_still_emits():
    src = (
        "from importlib import import_module\n"
        'PLUGIN_PACKAGE = "plugins.core"\n'
        'PLUGIN_PACKAGE = "plugins.other"\n'
        'import_module(PLUGIN_PACKAGE + ".loader")\n'
    )
    findings = VariableImportRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_global_rebound_module_constant_still_emits():
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
    src = (
        "from importlib import import_module\n"
        'plugin_package = "plugins.core"\n'
        'import_module(plugin_package + ".loader")\n'
    )
    findings = VariableImportRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_conditionally_rebound_module_constant_still_emits():
    src = (
        "from importlib import import_module\n"
        'PLUGIN_PACKAGE = "plugins.core"\n'
        "if OVERRIDE:\n"
        "    PLUGIN_PACKAGE = load_override()\n"
        'import_module(PLUGIN_PACKAGE + ".loader")\n'
    )
    findings = VariableImportRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
