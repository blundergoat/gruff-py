import ast

from gruff.rule.size._lines import lines_for_size, qualified_symbol


def _first_def(source: str) -> ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef:
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            return node
    raise AssertionError("no def/class found")


def test_simple_function_counts_def_to_end_inclusive():
    src = "def f():\n    return 1\n"
    assert lines_for_size(_first_def(src)) == 2


def test_function_with_docstring_counts_docstring_and_blanks():
    src = '''def f():
    """Docstring.

    Long form.
    """

    return 1
'''
    assert lines_for_size(_first_def(src)) == 7


def test_decorated_function_counts_decorator_lines():
    src = """@decorator_a
@decorator_b
def f():
    return 1
"""
    # decorator_a on line 1, body returns on line 4 -> span = 4
    assert lines_for_size(_first_def(src)) == 4


def test_decorated_function_with_multiline_decorator():
    src = """@decorator_a(
    'arg',
)
def f():
    return 1
"""
    # decorator opens line 1, function ends line 5 -> span = 5
    assert lines_for_size(_first_def(src)) == 5


def test_class_with_nested_methods_counts_full_span():
    src = """class C:
    def a(self):
        return 1

    def b(self):
        return 2
"""
    # class opens line 1, last method body line is 6 -> span = 6
    assert lines_for_size(_first_def(src)) == 6


def test_async_function():
    src = "async def f():\n    return 1\n"
    assert lines_for_size(_first_def(src)) == 2


def test_lambda_single_line():
    tree = ast.parse("g = lambda x: x + 1\n")
    assign = tree.body[0]
    assert isinstance(assign, ast.Assign)
    lam = assign.value
    assert isinstance(lam, ast.Lambda)
    assert lines_for_size(lam) == 1


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
