import pytest

from gruffpy.rule.naming._identifier_tokenizer import lower_tokens, tokenize


@pytest.mark.parametrize(
    ("identifier", "expected"),
    [
        ("", []),
        ("__", []),
        ("snake_case_thing", ["snake", "case", "thing"]),
        ("CamelCaseThing", ["Camel", "Case", "Thing"]),
        ("mixedCaseThing", ["mixed", "Case", "Thing"]),
        ("CONSTANT_NAME", ["CONSTANT", "NAME"]),
        ("HTTPServer", ["HTTP", "Server"]),
        ("parseHTTPHeader", ["parse", "HTTP", "Header"]),
        ("temp1", ["temp", "1"]),
        ("result2", ["result", "2"]),
        ("data42", ["data", "42"]),
        ("parseHTTP2Header", ["parse", "HTTP", "2", "Header"]),
        ("_private", ["private"]),
        ("__init__", ["init"]),
        ("x", ["x"]),
        ("X", ["X"]),
        ("URL", ["URL"]),
        ("get_HTTP_response", ["get", "HTTP", "response"]),
    ],
    ids=[
        "empty",
        "underscores_only",
        "snake_case",
        "camel_case",
        "mixed_case",
        "constant_name",
        "acronym_before_camel",
        "acronym_inside_camel",
        "trailing_digit_temp",
        "trailing_digit_result",
        "trailing_digits_run",
        "camel_with_digit_inside",
        "leading_underscore",
        "dunder",
        "single_lower",
        "single_upper",
        "all_uppercase_acronym",
        "mixed_underscores_and_camel",
    ],
)
def test_tokenize(identifier: str, expected: list[str]) -> None:
    """Split an identifier into its snake-case, camel-case, acronym and digit tokens, dropping underscores.

    Args:
        identifier: Identifier to split; the cases cover empty, underscore-only, snake, camel, acronym, digit and dunder shapes.
        expected: Tokens the case expects, in order.
    """
    assert tokenize(identifier) == expected


@pytest.mark.parametrize(
    ("identifier", "expected"),
    [
        ("HTTPServer", ["http", "server"]),
        ("UserName_thing", ["user", "name", "thing"]),
    ],
    ids=["acronym_prefix", "mixed_snake_camel"],
)
def test_lower_tokens(identifier: str, expected: list[str]) -> None:
    """Split an identifier into lower-cased tokens.

    Args:
        identifier: Identifier with an acronym prefix or mixed snake and camel case.
        expected: Lower-cased tokens the case expects, in order.
    """
    assert lower_tokens(identifier) == expected
