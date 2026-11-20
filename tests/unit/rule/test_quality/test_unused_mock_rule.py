import pytest

from gruffpy.rule.test_quality.unused_mock_rule import UnusedMockRule
from tests.unit.rule.test_quality._helpers import default_ctx, make_unit


def test_unused_mock_emits():
    """Report one finding, listing mock, for a test that creates a mock and never uses it.

    Returns:
        None. Checks that one finding names the unused mock in its metadata.
    """
    src = "from unittest.mock import Mock\ndef test_foo():\n    mock = Mock()\n    assert 1 + 1 == 2\n"
    findings = UnusedMockRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["mocks"] == ["mock"]


def test_used_mock_skipped():
    """Report nothing for a test that checks a call on its mock.

    Returns:
        None. Checks that calling mock.assert_called() produces no unused-mock finding.
    """
    src = "from unittest.mock import Mock\ndef test_foo():\n    mock = Mock()\n    mock.assert_called()\n"
    assert UnusedMockRule().analyse(make_unit(src), default_ctx()) == []


def test_bespoke_fake_not_treated_as_mock():
    """Verify that the rule ignores the unused FakeService instance.

    Returns:
        None. Asserts that the fake fixture produces an empty findings list.
    """
    src = "class FakeService:\n    pass\ndef test_foo():\n    fake = FakeService()\n    assert 1 == 1\n"
    assert UnusedMockRule().analyse(make_unit(src), default_ctx()) == []


@pytest.mark.parametrize(
    "body",
    [
        "    callback = lambda: m()\n    callback()\n",
        "    def callback():\n        return m()\n    callback()\n",
        "    def outer():\n        def inner():\n            return m()\n        return inner()\n    outer()\n",
        "    class Callback:\n        m = str\n        def run(self):\n            return m()\n    Callback().run()\n",
        "    def callback(value=m):\n        return value()\n    callback()\n",
    ],
    ids=["lambda", "function", "deeper-capture", "class-method", "default-argument"],
)
def test_captured_mock_is_used(body: str) -> None:
    """Verify that a closure read or a default parameter value counts as use of the outer mock.

    Args:
        body: Test-body statements that read the outer mock binding.

    Returns:
        None. Checks that each read of the outer mock produces no unused-mock finding.
    """
    source = "from unittest.mock import Mock\ndef test_callback():\n    m = Mock()\n" + body
    assert UnusedMockRule().analyse(make_unit(source), default_ctx()) == []


@pytest.mark.parametrize(
    "body",
    [
        "    callback = lambda m: m()\n    callback(str)\n",
        "    def callback():\n        m = str\n        return m()\n    callback()\n",
        "    def callback():\n        global m\n        return m()\n    callback()\n",
        "    def callback():\n        nonlocal m\n        m = str\n    callback()\n",
        "    def callback():\n        return [m() for m in (str,)]\n    callback()\n",
    ],
    ids=["parameter", "local", "global", "nonlocal-write-only", "comprehension"],
)
def test_shadow_or_write_does_not_use_outer_mock(body: str) -> None:
    """Keep reporting the mock when a nested scope never reads its binding.

    Args:
        body: Test-body statements that read a different binding or only write to the outer mock binding.

    Returns:
        None. Checks that one finding identifies the unread outer mock.
    """
    source = "from unittest.mock import Mock\ndef test_callback():\n    m = Mock()\n" + body
    findings = UnusedMockRule().analyse(make_unit(source), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["mocks"] == ["m"]


def test_invalid_nonlocal_keeps_direct_scan() -> None:
    """Keep an AST-parseable but compiler-invalid unit from crashing the rule.

    Returns:
        None. Checks that the direct scan still reports m when the invalid nonlocal prevents closure analysis.
    """
    source = "from unittest.mock import Mock\ndef test_callback():\n    nonlocal missing\n    m = Mock()\n    callback = lambda: m()\n"
    findings = UnusedMockRule().analyse(make_unit(source), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["mocks"] == ["m"]


@pytest.mark.parametrize(
    "body",
    [
        "    m += 1\n",
        "    def callback():\n        nonlocal m\n        m += 1\n    callback()\n",
    ],
    ids=["direct", "captured"],
)
def test_augmented_assignment_reads_mock(body: str) -> None:
    """Treat read-modify-write operations as use of the mock binding.

    Args:
        body: Direct or nested augmented assignment that reads the mock.

    Returns:
        None. Checks that direct and nested augmented assignment both leave the mock unreported.
    """
    source = "from unittest.mock import MagicMock\ndef test_callback():\n    m = MagicMock()\n" + body
    assert UnusedMockRule().analyse(make_unit(source), default_ctx()) == []
