"""Identifier-tokenizer used by 4+ naming rules.

Splits an identifier into its semantic tokens:

- ``snake_case`` → ``["snake", "case"]``
- ``CamelCase`` → ``["Camel", "Case"]``
- ``mixedCase`` → ``["mixed", "Case"]``
- ``CONSTANT_NAME`` → ``["CONSTANT", "NAME"]``
- ``HTTPServer`` → ``["HTTP", "Server"]`` (acronym preservation)
- ``parseHTTP2Header`` → ``["parse", "HTTP", "2", "Header"]``
- ``temp1`` → ``["temp", "1"]``
- ``__dunder__`` → ``["dunder"]``
- ``_private_x`` → ``["private", "x"]``
"""

import re

# Pattern that splits camel/Pascal/snake/numeric boundaries while keeping
# acronym runs ("HTTP" + "Server", not "H" + "T" + "T" + "P" + "Server").
_TOKEN_PATTERN = re.compile(
    r"""
    [A-Z]+(?=[A-Z][a-z])  # acronym run before a CamelCase word: HTTPServer -> HTTP
    |
    [A-Z]?[a-z]+          # leading-cap or all-lowercase token: Camel / camel
    |
    [A-Z]+                # standalone acronym at end: ID, URL
    |
    [0-9]+                # numeric run: temp1 -> 1
    """,
    re.VERBOSE,
)


def tokenize(identifier: str) -> list[str]:
    """Split an identifier into tokens while preserving acronym casing and separating numeric runs.

    Underscores are ignored.
    Separate numeric tokens let callers recognize placeholder suffixes such as temp1 and result2.

    Args:
        identifier: Python identifier-like name to split.

    Returns:
        Tokens with original acronym casing; empty for empty or underscore-only input, or when no pattern matches.
    """
    stripped = identifier.strip("_")
    if not stripped:
        return []
    return _TOKEN_PATTERN.findall(stripped)


def lower_tokens(identifier: str) -> list[str]:
    """Return tokenize output with every token lowercased.

    Convenient when only the semantic content matters, not the casing.

    Args:
        identifier: Python identifier-like name to split.

    Returns:
        Lowercased tokens; empty when the identifier is empty, contains only underscores or has no matches in tokenize.
    """
    return [t.lower() for t in tokenize(identifier)]
