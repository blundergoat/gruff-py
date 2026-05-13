from gruff.rule.naming._identifier_tokenizer import lower_tokens, tokenize


def test_empty_returns_empty():
    assert tokenize("") == []


def test_underscores_only_returns_empty():
    assert tokenize("__") == []


def test_snake_case():
    assert tokenize("snake_case_thing") == ["snake", "case", "thing"]


def test_camel_case():
    assert tokenize("CamelCaseThing") == ["Camel", "Case", "Thing"]


def test_mixed_case():
    assert tokenize("mixedCaseThing") == ["mixed", "Case", "Thing"]


def test_constant_name():
    assert tokenize("CONSTANT_NAME") == ["CONSTANT", "NAME"]


def test_acronym_preserved_before_camel_word():
    assert tokenize("HTTPServer") == ["HTTP", "Server"]


def test_acronym_followed_by_camel():
    assert tokenize("parseHTTPHeader") == ["parse", "HTTP", "Header"]


def test_numeric_runs_become_separate_tokens():
    assert tokenize("temp1") == ["temp", "1"]
    assert tokenize("result2") == ["result", "2"]
    assert tokenize("data42") == ["data", "42"]


def test_camel_with_number_inside():
    assert tokenize("parseHTTP2Header") == ["parse", "HTTP", "2", "Header"]


def test_leading_underscore_dropped():
    assert tokenize("_private") == ["private"]


def test_dunder_stripped():
    assert tokenize("__init__") == ["init"]


def test_lower_tokens_lowercases():
    assert lower_tokens("HTTPServer") == ["http", "server"]
    assert lower_tokens("UserName_thing") == ["user", "name", "thing"]


def test_single_letter():
    assert tokenize("x") == ["x"]
    assert tokenize("X") == ["X"]


def test_all_uppercase_acronym():
    assert tokenize("URL") == ["URL"]


def test_mixed_underscores_and_camel():
    assert tokenize("get_HTTP_response") == ["get", "HTTP", "response"]
