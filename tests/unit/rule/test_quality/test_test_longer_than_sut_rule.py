"""``test-quality.test-longer-than-sut`` compares code lines on both sides, so documentation never tips the ratio."""

from gruffpy.rule.test_quality.test_longer_than_sut_rule import TestLongerThanSutRule
from tests.unit.rule.test_quality._helpers import default_ctx, make_unit

SUBJECT_LINES = 6  # just over the rule's five-line trivial-subject skip
SHORT_SUBJECT_LINES = 3  # under that skip
LONG_TEST_LINES = 2 * SUBJECT_LINES + 1  # just over the default 2.0 ratio
SHORT_TEST_LINES = 2 * SUBJECT_LINES - 1  # just under it


def _module(subject_code: int, test_code: int, subject_doc: str = "", test_doc: str = "") -> str:
    """Return a module with a ``compute`` subject and its ``test_compute`` test, each holding the given code lines.

    Args:
        subject_code: Code lines in ``compute``, counting its ``def`` line and its ``return``.
        test_code: Code lines in ``test_compute``, counting its ``def`` line and its ``assert``.
        subject_doc: Indented documentation placed after the subject's ``def`` line; empty by default.
        test_doc: Indented documentation placed after the test's ``def`` line; empty by default.
    """
    subject_body = "\n".join(f"    step_{i} = value + {i}" for i in range(subject_code - 2))
    test_body = "\n".join(f"    result_{i} = compute({i})" for i in range(test_code - 2))
    return (
        f"def compute(value):\n{subject_doc}{subject_body}\n    return value\n\n\n"
        f"def test_compute():\n{test_doc}{test_body}\n    assert compute(1) == 1\n"
    )


def _docstring(lines: int) -> str:
    """Return an indented docstring holding a summary, a blank line and *lines* note lines.

    Args:
        lines: Number of note lines.

    Returns:
        Docstring text ending in a newline, ready to place after a ``def`` line.
    """
    notes = "\n".join(f"    Note {i} explains the behaviour." for i in range(lines))
    return f'    """Explain the code below.\n\n{notes}\n    """\n'


def test_test_more_than_twice_its_subject_in_code_lines_is_reported():
    """Report a 13-code-line test of a 6-code-line subject, recording both counts."""
    findings = TestLongerThanSutRule().analyse(make_unit(_module(SUBJECT_LINES, LONG_TEST_LINES)), default_ctx())
    measured = [(finding.metadata["testLines"], finding.metadata["sutLines"]) for finding in findings]
    assert measured == [(LONG_TEST_LINES, SUBJECT_LINES)]


def test_documenting_a_short_subject_does_not_create_a_finding():
    """Report nothing for a 3-code-line subject with a six-note docstring and its 13-code-line test."""
    module = _module(SHORT_SUBJECT_LINES, LONG_TEST_LINES, subject_doc=_docstring(6))
    assert TestLongerThanSutRule().analyse(make_unit(module), default_ctx()) == []


def test_documenting_a_test_does_not_tip_the_ratio():
    """Report nothing for an 11-code-line test of a 6-code-line subject, even with a ten-note docstring and ten comments."""
    comments = "".join(f"    # Step {i}.\n" for i in range(10))
    module = _module(SUBJECT_LINES, SHORT_TEST_LINES, test_doc=_docstring(10) + comments)
    assert TestLongerThanSutRule().analyse(make_unit(module), default_ctx()) == []
