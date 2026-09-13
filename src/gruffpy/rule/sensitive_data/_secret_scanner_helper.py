"""Shared helpers for sensitive-data pillar rules.

- Regex compilation utilities (case-sensitive by default; sensitive-data
  patterns rely on character classes that should NOT be loosened).
- Shannon entropy over byte/character distributions.
- Fixed zero-payload preview markers so findings never expose secret-derived
  characters or lengths.
- Line resolution: map a string offset into a 1-based line number.
"""

import math
import re
from collections.abc import Iterator
from dataclasses import dataclass

_PLACEHOLDER_MARKERS = frozenset(
    {
        "changeme",
        "change_me",
        "dummy",
        "example",
        "fake",
        "placeholder",
        "password",
        "test_password",
        "your_password",
    }
)


@dataclass(frozen=True, slots=True)
class SecretMatch:
    """One match of a sensitive-data pattern inside a source file.

    Rules use this location to show users which line needs review while keeping the matched value
    inside the scanner until a zero-payload finding is built.

    Attributes:
        raw: Matched secret text before redaction.
        start_offset: Zero-based start offset in the source text.
        end_offset: Zero-based end offset in the source text.
        line: One-based source line containing the match start.
    """

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


# The seventeen marker categories FAMILY-CONTRACT.md section 5 ratifies. A detector name outside this set
# degrades to the bare marker rather than inventing a category the rest of the family cannot read.
RATIFIED_MARKER_CATEGORIES: frozenset[str] = frozenset(
    {
        "private-key",
        "jwt",
        "aws-access-key",
        "github-token",
        "slack-token",
        "stripe-live-key",
        "google-api-key",
        "anthropic-api-key",
        "npm-token",
        "gitlab-token",
        "gcp-service-account",
        "email",
        "phone",
        "payment-card",
        "ssn",
        "medicare",
        "mrn",
    }
)

_SCHEME_SHAPE = re.compile(r"^[a-z][a-z0-9+.-]*$")


def fixed_preview() -> str:
    """Return the bare marker, used when a detector classified nothing more specific.

    Generic-assignment and entropy matches always use this: they name no class the user can act on.

    Returns:
        Classification-only marker with no value-derived characters or length.
    """
    return "[redacted]"


def category_preview(category: str | None) -> str:
    """Return the most specific marker for a classified match, unconditionally.

    Section 5 removed the configuration that once gated this, because every marker is zero-payload by
    construction, so gating one bought no confidentiality.

    Args:
        category: Ratified category the detector classified; ``None`` or an unratified name yields the
            bare marker.

    Returns:
        ``[redacted:<category>]`` for a ratified category, ``[redacted]`` otherwise.
    """
    # An unratified name would put this port outside the closed family grammar, so it degrades instead.
    if category is None or category not in RATIFIED_MARKER_CATEGORIES:
        return fixed_preview()
    return f"[redacted:{category}]"


def connection_string_preview(scheme: str) -> str:
    """Return the connection marker naming only the scheme, which the URL already publishes in plain text.

    Args:
        scheme: Scheme captured by the detector's own pattern; never user-supplied free text.

    Returns:
        ``[redacted:connection-string:<scheme>]``, or the bare marker when the scheme is malformed.
    """
    normalised = scheme.lower()
    # A scheme outside the grammar's shape would leak whatever the pattern happened to capture.
    if _SCHEME_SHAPE.match(normalised) is None:
        return fixed_preview()
    return f"[redacted:connection-string:{normalised}]"


def is_likely_placeholder_secret(secret: str) -> bool:
    """Return whether *secret* looks like documentation or fixture text.

    Args:
        secret: Candidate secret text after provider-specific extraction.

    Returns:
        True for common dummy/example marker words, false for real-looking
        values that should still be reported.
    """
    normalized = secret.strip().lower()
    if not normalized:
        return True
    return any(marker in normalized for marker in _PLACEHOLDER_MARKERS)


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
