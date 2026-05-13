from gruff.rule.security.variable_import_rule import VariableImportRule
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
