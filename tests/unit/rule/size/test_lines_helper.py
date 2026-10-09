import ast

from gruffpy.rule.size._lines import code_line_numbers, lines_for_size, qualified_symbol


def _measure(source: str) -> int:
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            return lines_for_size(node, code_line_numbers(source, tree))
    raise AssertionError("no def/class found")


def test_simple_function_counts_def_to_end_inclusive():
    assert _measure("def f():\n    return 1\n") == 2


def test_docstring_blank_lines_and_comments_are_free():
    src = '''def f():
    """Docstring.

    Long form.
    """

    # Explain the return.
    return 1
'''
    assert _measure(src) == 2


def test_decorator_lines_are_free():
    assert _measure("@decorator_a\n@decorator_b\ndef f():\n    return 1\n") == 2


def test_multiline_decorator_lines_are_free():
    assert _measure("@decorator_a(\n    'arg',\n)\ndef f():\n    return 1\n") == 2


def test_class_counts_the_code_lines_of_its_methods():
    src = "class C:\n    def a(self):\n        return 1\n\n    def b(self):\n        return 2\n"
    class_line_two_defs_two_returns = 5
    assert _measure(src) == class_line_two_defs_two_returns


def test_async_function():
    assert _measure("async def f():\n    return 1\n") == 2


def test_string_literal_used_as_data_still_counts():
    src = 'def f():\n    text = """one\n    two\n    three"""\n    return text\n'
    def_line_three_string_lines_and_return = 5
    assert _measure(src) == def_line_three_string_lines_and_return


def test_lambda_single_line():
    source = "g = lambda x: x + 1\n"
    tree = ast.parse(source)
    assign = tree.body[0]
    assert isinstance(assign, ast.Assign)
    lam = assign.value
    assert isinstance(lam, ast.Lambda)
    assert lines_for_size(lam, code_line_numbers(source, tree)) == 1


def test_qualified_symbol_module_function():
    tree = ast.parse("def f():\n    return 1\n")
    fn = tree.body[0]
    assert isinstance(fn, ast.FunctionDef)
    assert qualified_symbol(fn, parents=[]) == "f"


def test_qualified_symbol_method_in_class():
    tree = ast.parse("class C:\n    def m(self):\n        return 1\n")
    cls = tree.body[0]
    assert isinstance(cls, ast.ClassDef)
    method = cls.body[0]
    assert isinstance(method, ast.FunctionDef)
    assert qualified_symbol(method, parents=[cls]) == "C.m"


def test_qualified_symbol_lambda_uses_line_marker():
    tree = ast.parse("\ng = lambda x: x + 1\n")
    assign = tree.body[0]
    assert isinstance(assign, ast.Assign)
    lam = assign.value
    assert isinstance(lam, ast.Lambda)
    sym = qualified_symbol(lam, parents=[])
    assert sym.startswith("<lambda:")
