from gruff.rule.test_quality.unused_mock_rule import UnusedMockRule
from tests.unit.rule.test_quality._helpers import default_ctx, make_unit


def test_unused_mock_emits():
    src = (
        "from unittest.mock import Mock\n"
        "def test_foo():\n"
        "    mock = Mock()\n"
        "    assert 1 + 1 == 2\n"
    )
    findings = UnusedMockRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["mocks"] == ["mock"]


def test_used_mock_skipped():
    src = (
        "from unittest.mock import Mock\n"
        "def test_foo():\n"
        "    mock = Mock()\n"
        "    mock.assert_called()\n"
    )
    assert UnusedMockRule().analyse(make_unit(src), default_ctx()) == []


def test_bespoke_fake_not_treated_as_mock():
    """Mock-recognition is bounded to documented mock factories — bespoke fakes are fine."""
    src = (
        "class FakeService:\n    pass\n"
        "def test_foo():\n"
        "    fake = FakeService()\n"
        "    assert 1 == 1\n"
    )
    assert UnusedMockRule().analyse(make_unit(src), default_ctx()) == []
