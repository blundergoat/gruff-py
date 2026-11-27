from gruffpy.rule.docs.stale_param_doc_rule import StaleParamDocRule
from tests.unit.rule.docs._helpers import default_ctx, make_unit


def test_matching_param_emits_nothing():
    """Report nothing when every documented parameter is in the signature.

    Returns:
        None. Checks that the documented x matches the signature and produces no stale-parameter finding.
    """
    src = 'def f(x):\n    """Doc.\n\n    Args:\n        x: a value.\n    """\n    return x\n'
    assert StaleParamDocRule().analyse(make_unit(src), default_ctx()) == []


def test_stale_param_emits():
    """Report a documented parameter missing from the signature once, naming ``old_param``.

    Returns:
        None. Checks that exactly one finding identifies old_param as the stale parameter.
    """
    src = 'def f(x):\n    """Doc.\n\n    Args:\n        x: a value.\n        old_param: a leftover.\n    """\n    return x\n'
    findings = StaleParamDocRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["parameter"] == "old_param"


def test_no_docstring_skipped():
    """Report nothing for a function without a docstring.

    Returns:
        None. Checks that the stale-parameter rule produces no finding for the function without a docstring.
    """
    src = "def f(x):\n    return x\n"
    assert StaleParamDocRule().analyse(make_unit(src), default_ctx()) == []


def test_renamed_param_emits():
    """Report the old name once when a documented parameter was renamed in the signature.

    Returns:
        None. Checks that the single finding records old_name as the stale name.
    """
    src = 'def f(new_name):\n    """Doc.\n\n    Args:\n        old_name: a value.\n    """\n    return new_name\n'
    findings = StaleParamDocRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["parameter"] == "old_name"


def test_varargs_documented_with_star_does_not_fire():
    """Report nothing for a ``*keys`` entry that documents a varargs parameter.

    Returns:
        None. Checks that the documented varargs entry is matched and produces no stale-parameter finding.
    """
    # The parser preserves the leading asterisk, and signature_param_names returns the bare name.
    # Removing the asterisk lets the rule match the valid entry to the signature.
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
    """Report nothing for a ``**opts`` entry that documents a keyword-arguments parameter.

    Returns:
        None. Checks that the double-starred opts entry matches the keyword arguments parameter without a finding.
    """
    src = 'def f(**opts):\n    """Configure.\n\n    Args:\n        **opts: keyword options.\n    """\n    return opts\n'
    assert StaleParamDocRule().analyse(make_unit(src), default_ctx()) == []
