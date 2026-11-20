from gruffpy.rule.test_quality.global_state_mutation_rule import GlobalStateMutationRule
from tests.unit.rule.test_quality._helpers import default_ctx, make_unit


def test_global_in_test_emits():
    """Report one finding for a test that rebinds a module variable through global.

    Returns:
        None. Checks that the rule emits exactly one finding for a fixture that declares x global and then rebinds it.
    """
    src = "x = 0\ndef test_foo():\n    global x\n    x = 1\n    assert x == 1\n"
    findings = GlobalStateMutationRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_no_global_skipped():
    """Report nothing for a test that only assigns a local variable.

    Returns:
        None. Checks that the rule returns no findings when the assignment is local to the test.
    """
    src = "def test_foo():\n    x = 1\n    assert x == 1\n"
    assert GlobalStateMutationRule().analyse(make_unit(src), default_ctx()) == []
