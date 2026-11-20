from gruffpy.rule.docs.missing_function_docstring_rule import MissingFunctionDocstringRule
from tests.unit.rule.docs._helpers import default_ctx, every_callable_ctx, make_unit


def test_function_with_docstring_skipped():
    """Report nothing for a public function with a docstring.

    Returns:
        None. Checks that the rule emits no finding for the documented function.
    """
    src = 'def f():\n    """It does a thing."""\n    return 1\n'
    assert MissingFunctionDocstringRule().analyse(make_unit(src), default_ctx()) == []


def test_function_without_docstring_emits():
    """Report an undocumented public function once, asking for an intent description and a Returns section.

    Returns:
        None. Asserts the count, symbol, and exact message of the finding for f.
    """
    src = "def f():\n    return 1\n"
    findings = MissingFunctionDocstringRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].symbol == "f"
    assert findings[0].message == "Function 'f' needs a docstring with a brief intent description and a Returns section."


def test_pytest_function_without_docstring_in_test_file_skipped():
    """Report nothing for an undocumented test function in a test file with everyCallable off.

    Returns:
        None. Asserts that the test function fixture produces no docstring findings.
    """
    src = "def test_service_returns_value():\n    assert service() == 1\n"
    findings = MissingFunctionDocstringRule().analyse(
        make_unit(src, "tests/test_service.py"), every_callable_ctx(MissingFunctionDocstringRule.ID, enabled=False)
    )
    assert findings == []


def test_pytest_method_without_docstring_in_test_file_skipped():
    """Report nothing for an undocumented test method in a test file with everyCallable off.

    Returns:
        None. Asserts that the test method fixture produces no docstring findings.
    """
    src = "class TestService:\n    def test_returns_value(self):\n        assert service() == 1\n"
    findings = MissingFunctionDocstringRule().analyse(
        make_unit(src, "tests/test_service.py"), every_callable_ctx(MissingFunctionDocstringRule.ID, enabled=False)
    )
    assert findings == []


def test_test_named_function_without_docstring_in_production_file_emits():
    """Report an undocumented test_-named function once when it sits in a production file.

    Returns:
        None. Asserts that the only finding names test_service_returns_value.
    """
    src = "def test_service_returns_value():\n    return service()\n"
    findings = MissingFunctionDocstringRule().analyse(make_unit(src, "src/service_helpers.py"), default_ctx())
    assert len(findings) == 1
    assert findings[0].symbol == "test_service_returns_value"


def test_private_function_skipped():
    """Report nothing for an undocumented private function with everyCallable off.

    Returns:
        None. Asserts that the rule produces no findings for _helper with that option disabled.
    """
    src = "def _helper():\n    return 1\n"
    assert MissingFunctionDocstringRule().analyse(make_unit(src), every_callable_ctx(MissingFunctionDocstringRule.ID, enabled=False)) == []


def test_default_options_check_private_functions():
    """Report an undocumented private function at default options, as everyCallable is on by default.

    Returns:
        None. Asserts that the default run reports _helper as its sole finding symbol.
    """
    src = "def _helper():\n    return 1\n"
    assert [f.symbol for f in MissingFunctionDocstringRule().analyse(make_unit(src), default_ctx())] == ["_helper"]


def test_dunder_method_skipped():
    """Report nothing for an undocumented __init__ method.

    Returns:
        None. Asserts that the constructor fixture produces no docstring findings.
    """
    src = "class C:\n    def __init__(self): pass\n"
    assert MissingFunctionDocstringRule().analyse(make_unit(src), default_ctx()) == []


def test_abstract_method_skipped():
    """Report nothing for an undocumented abstract method.

    Returns:
        None. Checks that the rule emits no finding for the abstract method.
    """
    src = "from abc import abstractmethod\n\nclass C:\n    @abstractmethod\n    def m(self): ...\n"
    assert MissingFunctionDocstringRule().analyse(make_unit(src), default_ctx()) == []


def test_overload_stub_skipped():
    """Report nothing for undocumented @overload stubs beside a documented implementation.

    Returns:
        None. Asserts that the overload fixture produces no docstring findings.
    """
    src = (
        "from typing import overload\n\n"
        "@overload\n"
        "def f(x: int) -> int: ...\n"
        "@overload\n"
        "def f(x: str) -> str: ...\n"
        "def f(x):\n"
        '    """Real impl."""\n'
        "    return x\n"
    )
    assert MissingFunctionDocstringRule().analyse(make_unit(src), default_ctx()) == []


def test_property_getter_without_docstring_emits():
    """Report an undocumented property getter once, as C.name.

    Returns:
        None. Asserts that the only finding names C.name.
    """
    src = "class C:\n    @property\n    def name(self):\n        return 'x'\n"
    findings = MissingFunctionDocstringRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].symbol == "C.name"


def test_property_setter_skipped():
    """Report nothing for an undocumented setter of a documented property.

    Returns:
        None. Checks that the rule emits no finding for the setter.
    """
    src = (
        "class C:\n"
        "    @property\n"
        "    def name(self):\n"
        '        """The name."""\n'
        "        return 'x'\n"
        "    @name.setter\n"
        "    def name(self, value):\n"
        "        self._name = value\n"
    )
    assert MissingFunctionDocstringRule().analyse(make_unit(src), default_ctx()) == []


def test_nested_single_callsite_regex_callback_skipped():
    """Report nothing for an undocumented nested callback passed once to re.sub.

    Returns:
        None. Checks that the rule emits no findings for the single-reference callback.
    """
    src = (
        "import re\n"
        "def format_codes(text):\n"
        '    """Format codes."""\n'
        "    def replace(match):\n"
        "        return match.group(0)\n"
        "    return re.sub(r'X', replace, text)\n"
    )
    assert MissingFunctionDocstringRule().analyse(make_unit(src), default_ctx()) == []


def test_nested_event_generator_passed_once_skipped():
    """Report nothing when a single call to an undocumented nested async generator supplies the response body.

    Returns:
        None. Asserts that the streaming response fixture produces no docstring findings.
    """
    src = (
        "async def stream_endpoint():\n"
        '    """SSE endpoint."""\n'
        "    async def event_generator():\n"
        "        yield 1\n"
        "    return StreamingResponse(event_generator(), media_type='text/event-stream')\n"
    )
    assert MissingFunctionDocstringRule().analyse(make_unit(src), default_ctx()) == []


def test_nested_function_called_twice_still_emits():
    """Report one finding for outer.helper when it has two call sites in the enclosing function.

    Returns:
        None. Checks the finding count and qualified symbol.
    """
    src = 'def outer(xs):\n    """Outer."""\n    def helper(x):\n        return x + 1\n    return [helper(x) + helper(y) for x, y in xs]\n'
    findings = MissingFunctionDocstringRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].symbol == "outer.helper"


def test_message_asks_only_for_what_the_function_has():
    """Ask each undocumented function only for the entries and sections it needs, skipping an underscore parameter.

    Returns:
        None. Checks the exact diagnostics for act, convert, and walk.
    """
    src = (
        "def act():\n    print(1)\n\n"
        "def convert(value, unit, _cache=None):\n    if value < 0:\n        raise ValueError\n    return value\n\n"
        "def walk(root):\n    yield root\n"
    )
    messages = {f.symbol: f.message for f in MissingFunctionDocstringRule().analyse(make_unit(src), default_ctx())}
    assert messages == {
        "act": "Function 'act' needs a docstring with a brief intent description.",
        "convert": (
            "Function 'convert' needs a docstring with a brief intent description, "
            "entries for parameters 'value' and 'unit', a Returns section and a Raises section."
        ),
        "walk": "Function 'walk' needs a docstring with a brief intent description, an entry for parameter 'root' and a Yields section.",
    }


def test_private_and_test_functions_reported_with_every_callable():
    """Report an undocumented private function and a test function in a test file when everyCallable is set.

    Returns:
        None. Asserts that the combined findings name _f and test_service in that order.
    """
    ctx = every_callable_ctx(MissingFunctionDocstringRule.ID)
    private = MissingFunctionDocstringRule().analyse(make_unit("def _f():\n    return 1\n"), ctx)
    test = MissingFunctionDocstringRule().analyse(make_unit("def test_service():\n    assert service() == 1\n", "tests/test_service.py"), ctx)
    assert [f.symbol for f in private + test] == ["_f", "test_service"]
