import pytest

from gruffpy.rule.test_quality.trivial_assertion_rule import TrivialAssertionRule
from tests.unit.rule.test_quality._helpers import default_ctx, make_unit


def test_assert_true_emits():
    """Report one finding for a test whose only statement is assert True.

    Returns:
        None. Checks that asserting True alone produces one finding.
    """
    src = "def test_foo():\n    assert True\n"
    findings = TrivialAssertionRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_assert_1_emits():
    """Report one finding for a test whose only statement is assert 1.

    Returns:
        None. Checks that asserting the literal 1 produces one finding.
    """
    src = "def test_foo():\n    assert 1\n"
    findings = TrivialAssertionRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_assert_not_false_emits():
    """Report one finding for a test whose only statement is assert not False.

    Returns:
        None. Checks that asserting the negation of False produces one finding.
    """
    src = "def test_foo():\n    assert not False\n"
    findings = TrivialAssertionRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_assert_compare_constants_emits():
    """Report one finding for a test whose only statement is assert 1 == 1.

    Returns:
        None. Checks that the equality assertion between two literal ones produces one finding.
    """
    src = "def test_foo():\n    assert 1 == 1\n"
    findings = TrivialAssertionRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_assert_actual_computation_skipped():
    """Report nothing for an assertion on a computed value.

    Returns:
        None. Checks that asserting on the result of a function call produces no finding.
    """
    src = "def test_foo():\n    x = compute()\n    assert x == 42\n"
    assert TrivialAssertionRule().analyse(make_unit(src), default_ctx()) == []


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("try:\n        open_session()\n    except ChannelException:\n        pass\n    else:\n        assert False", 0),
        ("try:\n        open_session()\n        assert False\n    except ChannelException:\n        pass", 0),
        ("try:\n        open_session()\n        assert False\n    except Exception:\n        pass", 1),
        ("if mode == 'plain':\n        run_plain()\n    else:\n        assert 0", 1),
        ("if mode == 'plain':\n        assert True", 1),
        ("if True:\n        assert False", 1),
        ("assert False", 1),
    ],
    ids=[
        "missing-exception-else",
        "missing-exception-body",
        "swallowed-failure",
        "unsupported-mode",
        "true-tautology",
        "constant-guard",
        "unconditional",
    ],
)
def test_failure_sentinels_and_tautology_controls(body: str, expected: int) -> None:
    """Check that the rule accepts specific missing-exception guards and flags the broad-handler and constant-assertion controls.

    Args:
        body: Failure guard or constant assertion control.
        expected: Number of trivial-assertion findings.

    Returns:
        None. Asserts the expected number of trivial-assertion findings for each supplied body.
    """
    source = f"def test_guard():\n    {body}\n"
    assert len(TrivialAssertionRule().analyse(make_unit(source), default_ctx())) == expected
