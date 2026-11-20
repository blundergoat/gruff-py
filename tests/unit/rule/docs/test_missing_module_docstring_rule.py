from gruffpy.rule.docs.missing_module_docstring_rule import MissingModuleDocstringRule
from tests.unit.rule.docs._helpers import default_ctx, make_unit


def test_module_with_docstring_emits_nothing():
    """Report nothing for a module with a docstring.

    Returns:
        None. Asserts that the documented module produces an empty findings list.
    """
    src = '"""Module docstring."""\n\ndef f():\n    pass\n'
    assert MissingModuleDocstringRule().analyse(make_unit(src), default_ctx()) == []


def test_module_without_docstring_emits_one_finding():
    """Report an undocumented module once at line 1, with a message asking for a top-of-file docstring.

    Returns:
        None. Asserts the count, rule ID, line, and message wording of the missing module docstring finding.
    """
    src = "def f():\n    pass\n"
    findings = MissingModuleDocstringRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].rule_id == "docs.missing-module-docstring"
    assert findings[0].line == 1
    assert "needs a top-of-file docstring" in findings[0].message
    assert "has no top-of-file" not in findings[0].message


def test_test_module_without_docstring_skipped():
    """Report nothing for an undocumented test module.

    Returns:
        None. Asserts that the undocumented test module produces no findings.
    """
    src = "def test_f():\n    pass\n"
    findings = MissingModuleDocstringRule().analyse(make_unit(src, display_path="tests/test_example.py"), default_ctx())
    assert findings == []


def test_empty_module_skipped():
    """Report nothing for an empty module.

    Returns:
        None. Asserts that analysing empty source produces no findings.
    """
    findings = MissingModuleDocstringRule().analyse(make_unit(""), default_ctx())
    assert findings == []


def test_init_py_reexport_shim_skipped():
    """Report nothing for an __init__.py that only re-exports names.

    Returns:
        None. Asserts that the package initializer containing only re-exports produces no findings.
    """
    src = "from .x import a\nfrom .y import b\n__all__ = ['a', 'b']\n"
    findings = MissingModuleDocstringRule().analyse(make_unit(src, display_path="pkg/__init__.py"), default_ctx())
    assert findings == []


def test_init_py_with_code_not_skipped():
    """Report an undocumented __init__.py that defines a function once.

    Returns:
        None. Asserts that the package initializer containing a function definition produces one finding.
    """
    src = "from .x import a\n\ndef helper():\n    pass\n"
    findings = MissingModuleDocstringRule().analyse(make_unit(src, display_path="pkg/__init__.py"), default_ctx())
    assert len(findings) == 1
