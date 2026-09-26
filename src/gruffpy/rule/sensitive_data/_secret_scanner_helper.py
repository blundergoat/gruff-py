"""Shared helpers for sensitive-data pillar rules.

- Regex compilation utilities (case-sensitive by default; sensitive-data
  patterns rely on character classes that should NOT be loosened).
- Shannon entropy over byte/character distributions.
- Fixed zero-payload preview markers so findings never expose secret-derived
  characters or lengths.
- Line resolution: map a string offset into a 1-based line number.
"""

import hashlib
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


# SHA-256 digests of the 19 values vendors publish as documentation samples, so code that pastes one never reports.
#
# They are AWS's example access key ids and secret keys, the jwt.io sample token and fourteen published test card numbers.
# Digests keep the literals out of this source (FAMILY-CONTRACT.md section 5).
_DOCUMENTED_SAMPLE_DIGESTS = frozenset(
    {
        "19ff47cc8024c133d5845d3f8938caca289929031e7d508c3adf7adff177f0c2",
        "1a5d44a2dca19669d72edf4c4f1c27c4c1ca4b4408fbb17f6ce4ad452d78ddb3",
        "1c9d38ed26cd808fa3b02b9b3b988a7caf474e2e42d95789c0fe07e267c80d8f",
        "2f725bbd1f405a1ed0336abaf85ddfeb6902a9984a76fd877c3b5cc3b5085a82",
        "304945e91de3deff52a61d08733141d72dd42ec9d47972f1060534d54c0c7f90",
        "3a134ef77d4e2e4cdad2d2945ff1f76c1a23296c93c851f6244220a8cedea130",
        "477bba133c182267fe5f086924abdc5db71f77bfc27f01f2843f2cdc69d89f05",
        "51a4ae4c6ae999146474a67cbcb3b05fbcf4c17ab683043a066459da95513ea8",
        "53a8fc816e63b7a5ccd17aaff93f28bcf13abbf418209dcd93947722d7c326ba",
        "576c15a8072461c216efb9bd7306a6fc6039b43a6763c4c1a05930a2dd7b788f",
        "78314b11be2e581549ac1c4f616563fad3fdf0c3b71678f6e2299182080e0598",
        "7f75367e7881255134e1375e723d1dea8ad5f6a4fdb79d938df1f1754a830606",
        "9bbef19476623ca56c17da75fd57734dbf82530686043a6e491c6d71befe8f6e",
        "c6ea27c534f993d31f0aef882e3d200e7b87470c379ae79c8f9b19d3bd363dc9",
        "d79449f462cec9af0d857c3e1af888d4fa8bbdaa511b9eaaafcd2805c4ea6471",
        "d8086d483c15c711ebba19f966b97d3c2adcba74025ff8d7e07c3698c9531deb",
        "dd13cdf9af9dd3baf46ce96aecd7163cabf381ccb21e63f15f0fa10b1c663fa9",
        "e21b597ba6b9cafa59d9ebc4d65c0385f5eb3fa56abab2607fa76589ad849a33",
        "f41e7ca4a3d71c4f047581f2ae2d6a8dbb8c58e51a020fa227edc724474aab6e",
    }
)


def is_documented_sample(matched_value: str) -> bool:
    """Return whether a matched value is, exactly and whole, a vendor-documented sample such as AWS's example key.

    Args:
        matched_value: The whole matched value; a value that merely contains a sample is compared whole and still reports.

    Returns:
        True when the value is a documented sample, so the user sees no finding for it.
    """
    return hashlib.sha256(matched_value.encode("utf-8")).hexdigest() in _DOCUMENTED_SAMPLE_DIGESTS


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
        # A vendor-documented sample, e.g. AWS's example key id pasted from its docs, is not a credential, whichever rule found it.
        if is_documented_sample(match.group(0)):
            continue
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
