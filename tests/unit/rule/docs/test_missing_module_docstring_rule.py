from gruff.rule.docs.missing_module_docstring_rule import MissingModuleDocstringRule
from tests.unit.rule.docs._helpers import default_ctx, make_unit


def test_module_with_docstring_emits_nothing():
    src = '"""Module docstring."""\n\ndef f():\n    pass\n'
    assert MissingModuleDocstringRule().analyse(make_unit(src), default_ctx()) == []


def test_module_without_docstring_emits_one_finding():
    src = "def f():\n    pass\n"
    findings = MissingModuleDocstringRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].rule_id == "docs.missing-module-docstring"
    assert findings[0].line == 1


def test_empty_module_skipped():
    findings = MissingModuleDocstringRule().analyse(make_unit(""), default_ctx())
    assert findings == []


def test_init_py_reexport_shim_skipped():
    src = "from .x import a\nfrom .y import b\n__all__ = ['a', 'b']\n"
    findings = MissingModuleDocstringRule().analyse(
        make_unit(src, display_path="pkg/__init__.py"), default_ctx()
    )
    assert findings == []


def test_init_py_with_code_not_skipped():
    src = "from .x import a\n\ndef helper():\n    pass\n"
    findings = MissingModuleDocstringRule().analyse(
        make_unit(src, display_path="pkg/__init__.py"), default_ctx()
    )
    assert len(findings) == 1
