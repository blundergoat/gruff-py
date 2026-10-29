"""``test-quality.test-longer-than-sut`` compares code lines on both sides, so documentation never tips the ratio."""

from gruffpy.rule.test_quality.test_longer_than_sut_rule import TestLongerThanSutRule
from tests.unit.rule.test_quality._helpers import default_ctx, make_unit

SUBJECT_LINES = 6  # just over the rule's five-line trivial-subject skip
SHORT_SUBJECT_LINES = 3  # under that skip
LONG_TEST_LINES = 2 * SUBJECT_LINES + 1  # just over the default 2.0 ratio
SHORT_TEST_LINES = 2 * SUBJECT_LINES - 1  # just under it


def _module(subject_code: int, test_code: int, subject_doc: str = "", test_doc: str = "") -> str:
    """Return a module with a ``compute`` subject and its ``test_compute`` test, each holding the given code lines."""
    subject_body = "\n".join(f"    step_{i} = value + {i}" for i in range(subject_code - 2))
    test_body = "\n".join(f"    result_{i} = compute({i})" for i in range(test_code - 2))
    return (
        f"def compute(value):\n{subject_doc}{subject_body}\n    return value\n\n\n"
        f"def test_compute():\n{test_doc}{test_body}\n    assert compute(1) == 1\n"
    )


def _docstring(lines: int) -> str:
    notes = "\n".join(f"    Note {i} explains the behaviour." for i in range(lines))
    return f'    """Explain the code below.\n\n{notes}\n    """\n'


def test_test_more_than_twice_its_subject_in_code_lines_is_reported():
    findings = TestLongerThanSutRule().analyse(make_unit(_module(SUBJECT_LINES, LONG_TEST_LINES)), default_ctx())
    measured = [(finding.metadata["testLines"], finding.metadata["sutLines"]) for finding in findings]
    assert measured == [(LONG_TEST_LINES, SUBJECT_LINES)]


def test_documenting_a_short_subject_does_not_create_a_finding():
    module = _module(SHORT_SUBJECT_LINES, LONG_TEST_LINES, subject_doc=_docstring(6))
    assert TestLongerThanSutRule().analyse(make_unit(module), default_ctx()) == []


def test_documenting_a_test_does_not_tip_the_ratio():
    comments = "".join(f"    # Step {i}.\n" for i in range(10))
    module = _module(SUBJECT_LINES, SHORT_TEST_LINES, test_doc=_docstring(10) + comments)
    assert TestLongerThanSutRule().analyse(make_unit(module), default_ctx()) == []
