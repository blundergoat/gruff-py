"""Shared helpers for sensitive-data pillar rules.

- Regex compilation utilities (case-sensitive by default; sensitive-data
  patterns rely on character classes that should NOT be loosened).
- Shannon entropy over byte/character distributions.
- Preview redaction in the canonical ``first 4 + ... + last 4 (redacted, N chars)``
  shape so findings never leak the raw secret.
- Line resolution: map a string offset into a 1-based line number.
"""

import math
import re
from collections.abc import Iterator
from dataclasses import dataclass

# Strings shorter than this are too small to redact meaningfully and too
# common in benign text (IDs, short tokens). Sensitive-data rules typically
# specify their own min lengths via the regex.
MIN_REDACTABLE_LEN = 8


@dataclass(frozen=True, slots=True)
class SecretMatch:
    """One match of a sensitive-data pattern inside a source file."""

    raw: str
    start_offset: int
    end_offset: int
    line: int


def compile_pattern(pattern: str, *, ignore_case: bool = False) -> re.Pattern[str]:
    """Compile *pattern* with the project's default flags.

    All sensitive-data rules use raw compiled patterns; this helper exists so
    case-sensitivity is an explicit decision per rule rather than copy-pasted.

    Args:
        pattern: Regular expression source to compile.
        ignore_case: Whether matching should ignore character case.

    Returns:
        Compiled regular expression configured for multiline scanning.
    """
    flags = re.MULTILINE
    if ignore_case:
        flags |= re.IGNORECASE
    return re.compile(pattern, flags)


def iter_matches(pattern: re.Pattern[str], source: str) -> Iterator[SecretMatch]:
    """Yield :class:`SecretMatch` for every non-overlapping pattern match in *source*.

    The match's ``line`` is the 1-based line number of the first character.

    Args:
        pattern: Compiled sensitive-data pattern to scan with.
        source: Source text to inspect.

    Returns:
        Iterator of secret matches with offsets and line numbers.
    """
    line_offsets = _line_offsets(source)
    for match in pattern.finditer(source):
        yield SecretMatch(
            raw=match.group(0),
            start_offset=match.start(),
            end_offset=match.end(),
            line=_offset_to_line(line_offsets, match.start()),
        )


def shannon_entropy(text: str) -> float:
    """Return the per-character Shannon entropy of *text* in bits.

    Used by the high-entropy-string and hardcoded-env-value rules.
    Empty strings return 0.0.

    Args:
        text: Candidate secret text to measure.

    Returns:
        Shannon entropy in bits per character.
    """
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def redact_preview(secret: str) -> str:
    """Return a redacted preview of *secret* safe for logs and findings.

    Shape: ``first4...last4 (redacted, N chars)``. Shorter secrets get a
    single asterisk per character so the structure is still recognisable
    without leaking content.

    Args:
        secret: Raw secret-like value that must not be exposed directly.

    Returns:
        Redacted preview preserving only length and limited edge context.
    """
    length = len(secret)
    if length < MIN_REDACTABLE_LEN:
        return f"{'*' * length} (redacted, {length} chars)"
    return f"{secret[:4]}...{secret[-4:]} (redacted, {length} chars)"


def _line_offsets(source: str) -> list[int]:
    """Return the byte offset of the start of each line in *source* (0-based)."""
    offsets = [0]
    for i, char in enumerate(source):
        if char == "\n":
            offsets.append(i + 1)
    return offsets


def _offset_to_line(line_offsets: list[int], offset: int) -> int:
    """Binary-search *offset* into *line_offsets* and return the 1-based line."""
    lo, hi = 0, len(line_offsets)
    while lo < hi:
        mid = (lo + hi) // 2
        if line_offsets[mid] <= offset:
            lo = mid + 1
        else:
            hi = mid
    return lo  # `lo` is the first line whose start is *past* offset → that's our 1-based line.
