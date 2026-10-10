import pytest

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


@pytest.mark.parametrize(
    ("imports", "body", "expected"),
    [
        ("import asyncio", "await asyncio.sleep(0)", 0),
        ("import asyncio as aio", "await aio.sleep(0)", 0),
        ("from asyncio import sleep", "await sleep(0)", 0),
        ("import asyncio", "await asyncio.sleep(1)", 1),
        ("import time", "time.sleep(0)", 1),
        ("import asyncio", "asyncio = custom_clock\n    await asyncio.sleep(0)", 1),
    ],
    ids=["scheduler-yield", "aliased-module", "imported-sleep", "fixed-delay", "blocking-yield", "shadowed-module"],
)
def test_scheduler_yields_and_real_wait_controls(imports: str, body: str, expected: int) -> None:
    """Distinguish zero-delay asyncio scheduling from timed or blocking waits.

    Args:
        imports: Imports identifying the sleep implementation.
        body: Awaited yield or a wait that must remain reportable.
        expected: Number of sleep findings.

    Returns:
        None.
    """
    source = f"{imports}\nasync def test_yield():\n    {body}\n"
    assert len(SleepInTestRule().analyse(make_unit(source), default_ctx())) == expected
