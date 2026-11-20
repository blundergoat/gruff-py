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
    """Count a def line and its return as 2 lines.

    Returns:
        None. Asserts that the function header and its return both count.
    """
    assert _measure("def f():\n    return 1\n") == 2


def test_docstring_blank_lines_and_comments_are_free():
    """Count 2 lines for a function whose docstring, blank line and comment sit between the def and the return.

    Returns:
        None. Asserts that only the function header and return count in this fixture.
    """
    src = '''def f():
    """Docstring.

    Long form.
    """

    # Explain the return.
    return 1
'''
    assert _measure(src) == 2


def test_decorator_lines_are_free():
    """Count 2 lines for a function with two decorators.

    Returns:
        None. Asserts that both decorator lines are excluded from the count.
    """
    assert _measure("@decorator_a\n@decorator_b\ndef f():\n    return 1\n") == 2


def test_multiline_decorator_lines_are_free():
    """Count 2 lines for a function with a three-line decorator.

    Returns:
        None. Asserts that the full multiline decorator is excluded from the count.
    """
    assert _measure("@decorator_a(\n    'arg',\n)\ndef f():\n    return 1\n") == 2


def test_class_counts_the_code_lines_of_its_methods():
    """Count 5 lines for a class with two methods: the class line, two def lines and two returns.

    Returns:
        None. Asserts that the class total includes its header and both methods' code lines.
    """
    src = "class C:\n    def a(self):\n        return 1\n\n    def b(self):\n        return 2\n"
    class_line_two_defs_two_returns = 5
    assert _measure(src) == class_line_two_defs_two_returns


def test_async_function():
    """Count 2 lines for an async function.

    Returns:
        None. Asserts that the async function header and its return both count.
    """
    assert _measure("async def f():\n    return 1\n") == 2


def test_string_literal_used_as_data_still_counts():
    """Count 5 lines when a three-line string is assigned as data inside the function.

    Returns:
        None. Asserts that all three lines of the assigned string contribute to the count.
    """
    src = 'def f():\n    text = """one\n    two\n    three"""\n    return text\n'
    def_line_three_string_lines_and_return = 5
    assert _measure(src) == def_line_three_string_lines_and_return


def test_lambda_single_line():
    """Count 1 line for a lambda.

    Returns:
        None. Asserts that the parsed single-line lambda counts as one code line.
    """
    source = "g = lambda x: x + 1\n"
    tree = ast.parse(source)
    assign = tree.body[0]
    assert isinstance(assign, ast.Assign)
    lam = assign.value
    assert isinstance(lam, ast.Lambda)
    assert lines_for_size(lam, code_line_numbers(source, tree)) == 1


def test_qualified_symbol_module_function():
    """Name a module-level function by its bare name.

    Returns:
        None. Asserts that the symbol is the function name alone.
    """
    tree = ast.parse("def f():\n    return 1\n")
    fn = tree.body[0]
    assert isinstance(fn, ast.FunctionDef)
    assert qualified_symbol(fn, parents=[]) == "f"


def test_qualified_symbol_method_in_class():
    """Name a method by its class and name, as C.m.

    Returns:
        None. Asserts that the enclosing class name qualifies the method symbol.
    """
    tree = ast.parse("class C:\n    def m(self):\n        return 1\n")
    cls = tree.body[0]
    assert isinstance(cls, ast.ClassDef)
    method = cls.body[0]
    assert isinstance(method, ast.FunctionDef)
    assert qualified_symbol(method, parents=[cls]) == "C.m"


def test_qualified_symbol_lambda_uses_line_marker():
    """Name a lambda with a symbol starting <lambda:.

    Returns:
        None. Asserts the symbol prefix for the parsed lambda.
    """
    tree = ast.parse("\ng = lambda x: x + 1\n")
    assign = tree.body[0]
    assert isinstance(assign, ast.Assign)
    lam = assign.value
    assert isinstance(lam, ast.Lambda)
    sym = qualified_symbol(lam, parents=[])
    assert sym.startswith("<lambda:")
