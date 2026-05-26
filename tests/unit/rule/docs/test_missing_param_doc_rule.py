from gruffpy.rule.docs.missing_param_doc_rule import MissingParamDocRule
from tests.unit.rule.docs._helpers import default_ctx, make_unit


def test_all_params_documented_emits_nothing():
    src = (
        "def add(x, y):\n"
        '    """Sum two values.\n\n'
        "    Args:\n"
        "        x: first.\n"
        "        y: second.\n"
        '    """\n'
        "    return x + y\n"
    )
    assert MissingParamDocRule().analyse(make_unit(src), default_ctx()) == []


def test_missing_param_emits_per_undocumented():
    src = (
        "def add(x, y, z):\n"
        '    """Sum.\n\n'
        "    Args:\n"
        "        x: first.\n"
        '    """\n'
        "    return x + y + z\n"
    )
    findings = MissingParamDocRule().analyse(make_unit(src), default_ctx())
    assert sorted(f.metadata["parameter"] for f in findings) == ["y", "z"]
    assert all("needs a docstring entry describing parameter" in f.message for f in findings)
    assert all("has no docstring entry" not in f.message for f in findings)


def test_no_param_section_emits_single_consolidated_finding():
    src = 'def add(x, y, z):\n    """Sum three values."""\n    return x + y + z\n'
    findings = MissingParamDocRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["parameters"] == ["x", "y", "z"]
    assert "needs docstring entries describing" in findings[0].message
    assert "has no docstring entries" not in findings[0].message


def test_private_function_skipped():
    src = 'def _f(x):\n    """Does X."""\n    return x\n'
    assert MissingParamDocRule().analyse(make_unit(src), default_ctx()) == []


def test_underscore_params_skipped():
    src = (
        "def f(x, _ignored):\n"
        '    """Doc.\n\n'
        "    Args:\n"
        "        x: a value.\n"
        '    """\n'
        "    return x\n"
    )
    assert MissingParamDocRule().analyse(make_unit(src), default_ctx()) == []


def test_function_without_docstring_skipped():
    src = "def f(x, y):\n    return x\n"
    assert MissingParamDocRule().analyse(make_unit(src), default_ctx()) == []


def test_method_self_excluded():
    src = (
        "class C:\n"
        "    def m(self, x):\n"
        '        """Doc.\n\n'
        "        Args:\n"
        "            x: a value.\n"
        '        """\n'
        "        return x\n"
    )
    assert MissingParamDocRule().analyse(make_unit(src), default_ctx()) == []
