from gruffpy.rule.docs.stale_param_doc_rule import StaleParamDocRule
from tests.unit.rule.docs._helpers import default_ctx, make_unit


def test_matching_param_emits_nothing():
    """Report nothing when every documented parameter is in the signature."""
    src = 'def f(x):\n    """Doc.\n\n    Args:\n        x: a value.\n    """\n    return x\n'
    assert StaleParamDocRule().analyse(make_unit(src), default_ctx()) == []


def test_stale_param_emits():
    """Report a documented parameter missing from the signature once, naming ``old_param``."""
    src = 'def f(x):\n    """Doc.\n\n    Args:\n        x: a value.\n        old_param: a leftover.\n    """\n    return x\n'
    findings = StaleParamDocRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["parameter"] == "old_param"


def test_no_docstring_skipped():
    """Report nothing for a function without a docstring."""
    src = "def f(x):\n    return x\n"
    assert StaleParamDocRule().analyse(make_unit(src), default_ctx()) == []


def test_renamed_param_emits():
    """Report the old name once when a documented parameter was renamed in the signature."""
    src = 'def f(new_name):\n    """Doc.\n\n    Args:\n        old_name: a value.\n    """\n    return new_name\n'
    findings = StaleParamDocRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["parameter"] == "old_name"


def test_varargs_documented_with_star_does_not_fire():
    """Report nothing for a ``*keys`` entry that documents a varargs parameter."""
    # Docstring parsers preserve the leading `*` literally; signature_param_names
    # returns the bare identifier. The rule must strip the star before matching.
    src = (
        "def f(container, *keys):\n"
        '    """Read a metric.\n\n'
        "    Args:\n"
        "        container: object.\n"
        "        *keys: candidate keys.\n"
        '    """\n'
        "    return container\n"
    )
    assert StaleParamDocRule().analyse(make_unit(src), default_ctx()) == []


def test_kwargs_documented_with_double_star_does_not_fire():
    """Report nothing for a ``**opts`` entry that documents a keyword-arguments parameter."""
    src = 'def f(**opts):\n    """Configure.\n\n    Args:\n        **opts: keyword options.\n    """\n    return opts\n'
    assert StaleParamDocRule().analyse(make_unit(src), default_ctx()) == []
