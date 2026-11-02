import ast

from gruffpy.rule.size._lines import code_line_numbers, lines_for_size, qualified_symbol


def _measure(source: str) -> int:
    """Measure the size lines of the first top-level function, async function or class in source.

    Args:
        source: Python source to parse.

    Returns:
        The number of lines that count toward size for that definition.

    Raises:
        AssertionError: The source has no top-level function or class.
    """
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            return lines_for_size(node, code_line_numbers(source, tree))
    raise AssertionError("no def/class found")


def test_simple_function_counts_def_to_end_inclusive():
    """Count a ``def`` line and its return as 2 lines."""
    assert _measure("def f():\n    return 1\n") == 2


def test_docstring_blank_lines_and_comments_are_free():
    """Count 2 lines for a function whose docstring, blank line and comment sit between the ``def`` and the return."""
    src = '''def f():
    """Docstring.

    Long form.
    """

    # Explain the return.
    return 1
'''
    assert _measure(src) == 2


def test_decorator_lines_are_free():
    """Count 2 lines for a function with two decorators."""
    assert _measure("@decorator_a\n@decorator_b\ndef f():\n    return 1\n") == 2


def test_multiline_decorator_lines_are_free():
    """Count 2 lines for a function with a three-line decorator."""
    assert _measure("@decorator_a(\n    'arg',\n)\ndef f():\n    return 1\n") == 2


def test_class_counts_the_code_lines_of_its_methods():
    """Count 5 lines for a class with two methods: the class line, two ``def`` lines and two returns."""
    src = "class C:\n    def a(self):\n        return 1\n\n    def b(self):\n        return 2\n"
    class_line_two_defs_two_returns = 5
    assert _measure(src) == class_line_two_defs_two_returns


def test_async_function():
    """Count 2 lines for an async function."""
    assert _measure("async def f():\n    return 1\n") == 2


def test_string_literal_used_as_data_still_counts():
    """Count 5 lines when a three-line string is assigned as data inside the function."""
    src = 'def f():\n    text = """one\n    two\n    three"""\n    return text\n'
    def_line_three_string_lines_and_return = 5
    assert _measure(src) == def_line_three_string_lines_and_return


def test_lambda_single_line():
    """Count 1 line for a lambda."""
    source = "g = lambda x: x + 1\n"
    tree = ast.parse(source)
    assign = tree.body[0]
    assert isinstance(assign, ast.Assign)
    lam = assign.value
    assert isinstance(lam, ast.Lambda)
    assert lines_for_size(lam, code_line_numbers(source, tree)) == 1


def test_qualified_symbol_module_function():
    """Name a module-level function by its bare name."""
    tree = ast.parse("def f():\n    return 1\n")
    fn = tree.body[0]
    assert isinstance(fn, ast.FunctionDef)
    assert qualified_symbol(fn, parents=[]) == "f"


def test_qualified_symbol_method_in_class():
    """Name a method by its class and name, as ``C.m``."""
    tree = ast.parse("class C:\n    def m(self):\n        return 1\n")
    cls = tree.body[0]
    assert isinstance(cls, ast.ClassDef)
    method = cls.body[0]
    assert isinstance(method, ast.FunctionDef)
    assert qualified_symbol(method, parents=[cls]) == "C.m"


def test_qualified_symbol_lambda_uses_line_marker():
    """Name a lambda with a symbol starting ``<lambda:``."""
    tree = ast.parse("\ng = lambda x: x + 1\n")
    assign = tree.body[0]
    assert isinstance(assign, ast.Assign)
    lam = assign.value
    assert isinstance(lam, ast.Lambda)
    sym = qualified_symbol(lam, parents=[])
    assert sym.startswith("<lambda:")
