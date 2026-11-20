"""Source-comment scanning helpers for documentation rules."""

import io
import tokenize
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SourceComment:
    """One Python source comment token.

    Attributes:
        line: One-based source line for the comment.
        raw: Raw comment text including the leading ``#``.
        body: Comment text with the leading marker stripped.
    """

    line: int
    raw: str
    body: str


def scan_comments(source: str) -> tuple[SourceComment, ...]:
    """Return real comment tokens from source without reopening files.

    Args:
        source: Python source text from an AnalysisUnit.

    Returns:
        Comment tokens with line numbers and stripped bodies. Strings containing # are ignored.
        If tokenization fails, the tuple contains only the comments read before the failure, possibly none.
    """
    comments: list[SourceComment] = []
    try:
        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
        for token in tokens:
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
        # Bad dedents can raise IndentationError and unfinished input can raise TokenError.
        # Keep earlier comments available to comment rules and leave syntax reporting to the analysis diagnostics.
        return tuple(comments)
    return tuple(comments)
