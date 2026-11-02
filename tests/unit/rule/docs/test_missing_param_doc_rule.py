from gruffpy.rule.docs.missing_param_doc_rule import MissingParamDocRule
from tests.unit.rule.docs._helpers import default_ctx, every_callable_ctx, make_unit


def test_all_params_documented_emits_nothing():
    """Report nothing when ``Args`` documents every parameter."""
    src = 'def add(x, y):\n    """Sum two values.\n\n    Args:\n        x: first.\n        y: second.\n    """\n    return x + y\n'
    assert MissingParamDocRule().analyse(make_unit(src), default_ctx()) == []


def test_missing_params_reported_once_naming_each():
    """Report one finding whose metadata and message name both undocumented parameters, ``y`` and ``z``."""
    src = 'def add(x, y, z):\n    """Sum.\n\n    Args:\n        x: first.\n    """\n    return x + y + z\n'
    findings = MissingParamDocRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["parameters"] == ["y", "z"]
    assert findings[0].message == "Function 'add' needs docstring entries describing parameters 'y' and 'z'."


def test_no_param_section_emits_single_consolidated_finding():
    """Report one finding naming all three parameters when the docstring has no parameter section."""
    src = 'def add(x, y, z):\n    """Sum three values."""\n    return x + y + z\n'
    findings = MissingParamDocRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["parameters"] == ["x", "y", "z"]
    assert findings[0].message == "Function 'add' needs docstring entries describing parameters 'x', 'y' and 'z'."


def test_private_function_skipped():
    """Report nothing for a private function's undocumented parameter under default options."""
    src = 'def _f(x):\n    """Does X."""\n    return x\n'
    assert MissingParamDocRule().analyse(make_unit(src), default_ctx()) == []


def test_underscore_params_skipped():
    """Report nothing for an undocumented underscore-prefixed parameter."""
    src = 'def f(x, _ignored):\n    """Doc.\n\n    Args:\n        x: a value.\n    """\n    return x\n'
    assert MissingParamDocRule().analyse(make_unit(src), default_ctx()) == []


def test_function_without_docstring_skipped():
    """Report nothing for a function without a docstring."""
    src = "def f(x, y):\n    return x\n"
    assert MissingParamDocRule().analyse(make_unit(src), default_ctx()) == []


def test_method_self_excluded():
    """Report nothing for a method whose docstring documents every parameter except ``self``."""
    src = 'class C:\n    def m(self, x):\n        """Doc.\n\n        Args:\n            x: a value.\n        """\n        return x\n'
    assert MissingParamDocRule().analyse(make_unit(src), default_ctx()) == []


def test_private_function_reported_with_every_callable():
    """Report a private function's undocumented parameter when ``everyCallable`` is set."""
    src = 'def _f(x):\n    """Does X."""\n    return x\n'
    findings = MissingParamDocRule().analyse(make_unit(src), every_callable_ctx(MissingParamDocRule.ID))
    assert [f.symbol for f in findings] == ["_f"]


def test_entry_without_description_counts_only_without_every_callable():
    """Accept a description-less Google or Sphinx entry by default, but report it when ``everyCallable`` is set."""
    google = 'def f(x, y):\n    """Doc.\n\n    Args:\n        x:\n        y: the second value.\n    """\n    return x\n'
    sphinx = 'def f(x, y):\n    """Doc.\n\n    :param x:\n    :param y: the second value.\n    """\n    return x\n'
    for src in (google, sphinx):
        assert MissingParamDocRule().analyse(make_unit(src), default_ctx()) == []
        findings = MissingParamDocRule().analyse(make_unit(src), every_callable_ctx(MissingParamDocRule.ID))
        assert [f.metadata["parameters"] for f in findings] == [["x"]]
