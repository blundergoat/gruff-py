"""Verify shared sensitive-data matching, entropy, and preview behavior.

These tests protect line resolution and the fixed marker shown in user output while raw match text
remains available only to rules for classification and placeholder checks.
"""

from gruffpy.rule.sensitive_data._secret_scanner_helper import (
    compile_pattern,
    fixed_preview,
    iter_matches,
    shannon_entropy,
)


def test_fixed_preview_contains_no_secret_derived_payload():
    assert fixed_preview() == "[redacted]"


def test_entropy_zero_on_empty():
    assert shannon_entropy("") == 0.0


def test_entropy_zero_on_single_char_string():
    assert shannon_entropy("aaaaa") == 0.0


def test_entropy_higher_for_random_string():
    structured = shannon_entropy("aaaaaaaa")
    random_like = shannon_entropy("aB3xF7p1")
    assert random_like > structured


def test_iter_matches_resolves_lines():
    pattern = compile_pattern(r"SECRET")
    source = "line 1\nline 2 SECRET\nline 3\nSECRET again\n"
    matches = list(iter_matches(pattern, source))
    assert len(matches) == 2
    assert [m.line for m in matches] == [2, 4]


def test_iter_matches_returns_raw_match_text():
    pattern = compile_pattern(r"AKIA[A-Z0-9]{16}")
    source = "key = AKIAIOSFODNN7EXAMPLE\n"
    matches = list(iter_matches(pattern, source))
    assert len(matches) == 1
    assert matches[0].raw == "AKIAIOSFODNN7EXAMPLE"
