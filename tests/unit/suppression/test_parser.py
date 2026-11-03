from unittest.mock import Mock

import pytest

import gruffpy.suppression.parser as suppression_parser
from gruffpy.suppression.parser import parse_suppressions


def test_disable_same_line_suppression() -> None:
    """Disable the named rule on its own line from a trailing ``gruff: disable`` comment, with no diagnostic."""
    parsed = parse_suppressions("import os  # gruff: disable=waste.unused-import\n")

    assert parsed.disabled_on_line(1) == frozenset({"waste.unused-import"})
    assert parsed.diagnostics == ()


def test_disable_next_targets_next_physical_line_only() -> None:
    """Disable the named rule only on the physical line after a ``gruff: disable-next`` comment."""
    parsed = parse_suppressions("# gruff: disable-next=security.dangerous-function-call\neval('payload')\neval('payload')\n")

    assert parsed.disabled_on_line(1) == frozenset()
    assert parsed.disabled_on_line(2) == frozenset({"security.dangerous-function-call"})
    assert parsed.disabled_on_line(3) == frozenset()


def test_disable_file_is_file_local() -> None:
    """Record the rule a ``gruff: disable-file`` comment names as disabled for the whole file."""
    parsed = parse_suppressions("# gruff: disable-file=size.file-length\nx = 1\n")

    assert parsed.file_disabled_rule_ids == frozenset({"size.file-length"})


def test_marker_free_source_skips_python_tokenization(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep irrelevant non-Python sources out of the suppression tokenizer.

    Args:
        monkeypatch: Replaces the tokenizer so any accidental call fails the test.
    """
    reject_tokenization = Mock(side_effect=AssertionError("tokenized marker-free source"))

    monkeypatch.setattr(suppression_parser, "_comment_tokens", reject_tokenization)

    parsed = parse_suppressions('{"payload": "marker-free non-Python source"}')

    assert parsed == suppression_parser.ParsedSuppressions()
    reject_tokenization.assert_not_called()


def test_marker_prefilter_preserves_case_insensitive_syntax() -> None:
    """Keep mixed-case public suppression syntax eligible for tokenization."""
    parsed = parse_suppressions("# GrUfF: disable-file=size.file-length\nx = 1\n")

    assert parsed.file_disabled_rule_ids == frozenset({"size.file-length"})


def test_multiple_ids_and_whitespace_variants() -> None:
    """Read both comma-separated rule ids despite spaces after the colon and comma and on both sides of the equals sign."""
    parsed = parse_suppressions("# gruff:   disable = size.file-length, security.dangerous-function-call \n")

    assert parsed.disabled_on_line(1) == frozenset({"size.file-length", "security.dangerous-function-call"})


def test_string_literals_are_not_parsed_as_suppression_comments() -> None:
    """Ignore suppression syntax inside a string literal, recording no file, line or next-line suppression."""
    parsed = parse_suppressions('text = "# gruff: disable-file=size.file-length"\n')

    assert parsed.file_disabled_rule_ids == frozenset()
    assert parsed.line_disabled_rule_ids == {}
    assert parsed.next_line_disabled_rule_ids == {}


def test_malformed_suppression_produces_diagnostic_and_no_suppression() -> None:
    """Report a ``suppression-parse-error`` on line 1 for a directive with no rule ids, and leave line 1 unsuppressed."""
    parsed = parse_suppressions("# gruff: disable=\n")

    assert parsed.disabled_on_line(1) == frozenset()
    assert len(parsed.diagnostics) == 1
    assert parsed.diagnostics[0].type == "suppression-parse-error"
    assert parsed.diagnostics[0].line == 1


def test_unknown_rule_id_produces_diagnostic_and_does_not_suppress() -> None:
    """Report an unknown rule id as ``suppression-unknown-rule`` while still disabling the known id beside it."""
    parsed = parse_suppressions(
        "# gruff: disable=unknown.rule, size.file-length\n",
        known_rule_ids=frozenset({"size.file-length"}),
    )

    assert parsed.disabled_on_line(1) == frozenset({"size.file-length"})
    assert len(parsed.diagnostics) == 1
    assert parsed.diagnostics[0].type == "suppression-unknown-rule"
    assert parsed.diagnostics[0].rule_id == "unknown.rule"


def test_unknown_directive_produces_diagnostic() -> None:
    """Report an unknown directive as a ``suppression-parse-error`` and leave line 1 unsuppressed."""
    parsed = parse_suppressions("# gruff: disable-block=size.file-length\n")

    assert parsed.disabled_on_line(1) == frozenset()
    assert len(parsed.diagnostics) == 1
    assert parsed.diagnostics[0].type == "suppression-parse-error"
