from gruff.rule.test_quality.skipped_without_reason_rule import SkippedWithoutReasonRule
from tests.unit.rule.test_quality._helpers import default_ctx, make_unit


def test_skip_without_reason_emits():
    src = "import pytest\n@pytest.mark.skip\ndef test_foo():\n    assert True\n"
    findings = SkippedWithoutReasonRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_skip_with_reason_kwarg_skipped():
    src = (
        "import pytest\n"
        "@pytest.mark.skip(reason='flaky on Windows')\n"
        "def test_foo():\n"
        "    assert True\n"
    )
    assert SkippedWithoutReasonRule().analyse(make_unit(src), default_ctx()) == []


def test_skip_with_empty_reason_emits():
    src = "import pytest\n@pytest.mark.skip(reason='')\ndef test_foo():\n    assert True\n"
    findings = SkippedWithoutReasonRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_no_skip_decorator_skipped():
    src = "def test_foo():\n    assert True\n"
    assert SkippedWithoutReasonRule().analyse(make_unit(src), default_ctx()) == []
