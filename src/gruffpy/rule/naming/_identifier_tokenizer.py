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
    """Return *identifier*'s semantic tokens, preserving acronyms and numbers.

    Leading/trailing/internal underscores are dropped. Numeric runs are
    returned as separate tokens so callers can detect ``temp1`` / ``result2``
    placeholder patterns.

    Args:
        identifier: Python identifier-like name to split.

    Returns:
        Semantic tokens with original acronym casing preserved.
    """
    stripped = identifier.strip("_")
    if not stripped:
        return []
    return _TOKEN_PATTERN.findall(stripped)


def lower_tokens(identifier: str) -> list[str]:
    """Return :func:`tokenize` output with every token lowercased.

    Convenient when only the semantic content matters, not the casing.

    Args:
        identifier: Python identifier-like name to split.

    Returns:
        Lowercased semantic tokens.
    """
    return [t.lower() for t in tokenize(identifier)]
