"""Read Python comments for checks that act on suppression directives.

The scanner uses the source already read for analysis.
Only real comments can affect a finding or trigger a request for a reason.
"""

import io
import tokenize
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SourceComment:
    """Carry a Python comment and its line number to rules that inspect directives.

    The original token keeps its `#` for exact syntax checks.
    The stripped text is available to rules that read the comment's meaning.

    Attributes:
        line: One-based source line for the comment.
        raw: Raw comment text including the leading ``#``.
        body: Comment text with the leading marker stripped.
    """

    line: int
    raw: str
    body: str


def scan_comments(source: str) -> tuple[SourceComment, ...]:
    """Return comment tokens to rules that match or explain suppression directives.
    Use the scan's existing source so decisions are tied to the same text the rules inspected.

    Args:
        source: Python source from the analysis unit. Empty source produces no comment tokens.

    Returns:
        Comment tokens with line numbers and stripped bodies. Strings containing # are ignored.
        If tokenization fails, the tuple contains only the comments read before the failure, possibly none.
    """
    comments: list[SourceComment] = []
    try:
        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
        # Walk the tokens in source order so directives can be associated with their own line or the next one.
        for token in tokens:
            # A string like `"# nosec"` is source data and cannot hide a finding on that line.
            if token.type != tokenize.COMMENT:
                continue
            raw = token.string
            comments.append(
                SourceComment(
                    line=token.start[0],
                    raw=raw,
                    body=raw.removeprefix("#").strip(),
                )
            )
    except (tokenize.TokenError, SyntaxError):
        # If the user scans a file with an unfinished triple-quoted string, keep earlier comments. The parser reports the syntax failure.
        return tuple(comments)
    return tuple(comments)
