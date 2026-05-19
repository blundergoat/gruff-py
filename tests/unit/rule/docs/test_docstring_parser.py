from gruffpy.rule.docs._docstring_parser import DocstringStyle, parse_docstring


def test_empty_returns_none():
    assert parse_docstring("") is None


def test_whitespace_only_returns_none():
    assert parse_docstring("   \n\t\n  ") is None


def test_plain_summary_only():
    parsed = parse_docstring("Just a one-liner.")
    assert parsed is not None
    assert parsed.summary == "Just a one-liner."
    assert parsed.params == ()
    assert parsed.returns is None
    assert parsed.raises == ()


_GOOGLE_TEXT = (
    "Summary line.\n\n"
    "Args:\n"
    "    x (int): The x value.\n"
    "    y: The y value.\n\n"
    "Returns:\n"
    "    str: A description.\n\n"
    "Raises:\n"
    "    ValueError: When x is negative.\n"
)


def test_google_style_detected():
    parsed = parse_docstring(_GOOGLE_TEXT)
    assert parsed is not None
    assert (parsed.style, parsed.summary) == (DocstringStyle.GOOGLE, "Summary line.")


def test_google_style_extracts_params():
    parsed = parse_docstring(_GOOGLE_TEXT)
    assert parsed is not None
    assert [(p.name, p.type_hint, p.description) for p in parsed.params] == [
        ("x", "int", "The x value."),
        ("y", None, "The y value."),
    ]


def test_google_style_extracts_returns():
    parsed = parse_docstring(_GOOGLE_TEXT)
    assert parsed is not None
    assert parsed.returns is not None
    assert (parsed.returns.type_hint, parsed.returns.description) == ("str", "A description.")


def test_google_style_extracts_raises():
    parsed = parse_docstring(_GOOGLE_TEXT)
    assert parsed is not None
    assert [(r.name, r.description) for r in parsed.raises] == [
        ("ValueError", "When x is negative."),
    ]


_NUMPY_TEXT = (
    "Summary.\n\n"
    "Parameters\n"
    "----------\n"
    "x : int\n"
    "    The x value.\n"
    "y\n"
    "    The y value.\n\n"
    "Returns\n"
    "-------\n"
    "str\n"
    "    A description.\n"
)


def test_numpy_style_detected():
    parsed = parse_docstring(_NUMPY_TEXT)
    assert parsed is not None
    assert (parsed.style, parsed.summary) == (DocstringStyle.NUMPY, "Summary.")


def test_numpy_style_extracts_params_and_returns():
    parsed = parse_docstring(_NUMPY_TEXT)
    assert parsed is not None
    assert [p.name for p in parsed.params] == ["x", "y"]
    assert parsed.returns is not None
    assert parsed.returns.description == "A description."


_SPHINX_TEXT = (
    "Summary.\n\n"
    ":param x: The x value.\n"
    ":type x: int\n"
    ":param y: The y value.\n"
    ":returns: A description.\n"
    ":rtype: str\n"
    ":raises ValueError: When x is negative.\n"
)


def test_sphinx_rest_style_detected():
    parsed = parse_docstring(_SPHINX_TEXT)
    assert parsed is not None
    assert parsed.style is DocstringStyle.SPHINX


def test_sphinx_rest_style_extracts_params_returns_and_raises():
    parsed = parse_docstring(_SPHINX_TEXT)
    assert parsed is not None
    assert {p.name for p in parsed.params} == {"x", "y"}
    assert parsed.returns is not None
    assert parsed.returns.description == "A description."
    assert any(r.name == "ValueError" for r in parsed.raises)


def test_long_description_captured():
    text = (
        "Summary.\n\n"
        "This is a longer prose paragraph that should\n"
        "be captured in the description field.\n\n"
        "Args:\n"
        "    x: a value\n"
    )
    parsed = parse_docstring(text)
    assert parsed is not None
    assert parsed.summary == "Summary."
    assert parsed.description is not None
    assert "longer prose paragraph" in parsed.description


def test_returns_without_type():
    text = "Summary.\n\nReturns:\n    Just a description without a type.\n"
    parsed = parse_docstring(text)
    assert parsed is not None
    assert parsed.returns is not None
    assert parsed.returns.description == "Just a description without a type."


def test_google_style_minimal():
    parsed = parse_docstring("Sum two values.\n\nArgs:\n    x: a value.\n")
    assert parsed is not None
    assert parsed.style is DocstringStyle.GOOGLE
    assert [p.name for p in parsed.params] == ["x"]


def test_google_style_with_descriptions_only():
    text = "Compute the total.\n\nArgs:\n    items: the inputs.\n    weight: the scaling factor.\n"
    parsed = parse_docstring(text)
    assert parsed is not None
    assert parsed.style is DocstringStyle.GOOGLE
    assert {p.name for p in parsed.params} == {"items", "weight"}


def test_numpy_style_with_returns_only():
    text = "Summary.\n\nReturns\n-------\nint\n    The result.\n"
    parsed = parse_docstring(text)
    assert parsed is not None
    assert parsed.style is DocstringStyle.NUMPY
    assert parsed.returns is not None
    assert parsed.returns.type_hint == "int"


def test_numpy_style_raises_section():
    text = "Summary.\n\nRaises\n------\nValueError\n    When inputs are out of range.\n"
    parsed = parse_docstring(text)
    assert parsed is not None
    assert parsed.style is DocstringStyle.NUMPY
    assert any(r.name == "ValueError" for r in parsed.raises)


def test_sphinx_style_returns_only():
    parsed = parse_docstring("Summary.\n\n:returns: the count.\n:rtype: int\n")
    assert parsed is not None
    assert parsed.style is DocstringStyle.SPHINX
    assert parsed.returns is not None
    assert parsed.returns.description == "the count."


def test_sphinx_style_multiple_raises():
    text = (
        "Summary.\n\n"
        ":raises ValueError: when input is bad.\n"
        ":raises RuntimeError: when state is bad.\n"
    )
    parsed = parse_docstring(text)
    assert parsed is not None
    assert parsed.style is DocstringStyle.SPHINX
    assert {r.name for r in parsed.raises} == {"ValueError", "RuntimeError"}


def test_extract_docstring_round_trip():
    import ast

    from gruffpy.rule.docs._docstring_parser import extract_docstring

    src = '''
def f(x):
    """The docstring."""
    return x
'''
    module = ast.parse(src)
    fn = module.body[0]
    assert isinstance(fn, ast.FunctionDef)
    assert extract_docstring(fn) == "The docstring."


def test_extract_docstring_returns_none_when_absent():
    import ast

    from gruffpy.rule.docs._docstring_parser import extract_docstring

    src = "def f(x):\n    return x\n"
    module = ast.parse(src)
    fn = module.body[0]
    assert isinstance(fn, ast.FunctionDef)
    assert extract_docstring(fn) is None
