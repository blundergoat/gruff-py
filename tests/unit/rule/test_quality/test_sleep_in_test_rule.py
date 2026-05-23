from gruffpy.rule.test_quality.sleep_in_test_rule import SleepInTestRule
from tests.unit.rule.test_quality._helpers import default_ctx, make_unit


def test_time_sleep_emits():
    src = "import time\ndef test_foo():\n    time.sleep(1)\n    assert True\n"
    findings = SleepInTestRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_asyncio_sleep_emits():
    src = "import asyncio\nasync def test_foo():\n    await asyncio.sleep(1)\n    assert True\n"
    findings = SleepInTestRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_no_sleep_skipped():
    src = "def test_foo():\n    assert True\n"
    assert SleepInTestRule().analyse(make_unit(src), default_ctx()) == []


def test_sleep_in_non_test_skipped():
    src = "import time\ndef helper():\n    time.sleep(1)\n"
    assert SleepInTestRule().analyse(make_unit(src), default_ctx()) == []
