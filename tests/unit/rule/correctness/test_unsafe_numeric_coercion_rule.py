import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.correctness.unsafe_numeric_coercion_rule import UnsafeNumericCoercionRule
from gruffpy.source.source_file import SourceFile


def _unit(source: str) -> AnalysisUnit:
    """Parse source, link every non-root AST node to its parent and wrap it as an analysis unit for x.py.

    Args:
        source: Python source to parse.

    Returns:
        Analysis unit for x.py containing the source and AST with parent links.
    """
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]  # -- ast.AST omits parent; the rule needs links to find enclosing try blocks.
    file = SourceFile(absolute_path="/x.py", display_path="x.py", type="python")
    return AnalysisUnit(file=file, source=source, tree=tree)


def _ctx() -> RuleContext:
    """Build a rule context with the unsafe numeric coercion rule enabled.

    Returns:
        Context enabling the unsafe numeric coercion rule.
    """
    rule = UnsafeNumericCoercionRule()
    return RuleContext(
        project_root="/",
        config=AnalysisConfig(rules={rule.definition().id: RuleSettings(enabled=True)}),
    )


def _analyse(source: str):
    """Run the unsafe numeric coercion rule over source as x.py.

    Args:
        source: Python source to analyse.

    Returns:
        The rule's findings, empty when nothing matches or a module-level binding of int causes the rule to skip the file.
    """
    return UnsafeNumericCoercionRule().analyse(_unit(source), _ctx())


def test_guard_then_int_fires():
    """Flag int() under an isnumeric() guard once as a guarded string coercion naming that guard.

    Returns:
        None. Asserts one guarded-string finding with isnumeric recorded as the guard.
    """
    src = "def parse(raw):\n    if raw.isnumeric():\n        return int(raw)\n    return None\n"
    findings = _analyse(src)
    assert len(findings) == 1
    assert findings[0].metadata["shape"] == "guarded-string-coercion"
    assert findings[0].metadata["guard"] == "isnumeric"


def test_isdigit_guard_in_ternary_fires():
    """Flag int() in a conditional expression guarded by isdigit() once, naming that guard.

    Returns:
        None. Asserts one finding with isdigit recorded as the guard.
    """
    src = "def parse(raw):\n    return int(raw) if raw.isdigit() else 0\n"
    findings = _analyse(src)
    assert len(findings) == 1
    assert findings[0].metadata["guard"] == "isdigit"


def test_early_exit_negated_guard_fires():
    """Flag int() after a negated isdigit() early exit once as a guarded string coercion.

    Returns:
        None. Asserts one guarded-string finding for the conversion after the early exit.
    """
    src = 'def parse(raw):\n    if not raw.isdigit():\n        raise ValueError("not a number")\n    return int(raw)\n'
    findings = _analyse(src)
    assert len(findings) == 1
    assert findings[0].metadata["shape"] == "guarded-string-coercion"


def test_try_except_value_error_is_clean():
    """Report nothing for an unguarded int() inside a try that catches ValueError.

    Returns:
        None after all assertions pass.
    """
    src = "def parse(raw):\n    try:\n        return int(raw)\n    except ValueError:\n        return None\n"
    assert _analyse(src) == []


def test_guarded_int_inside_outer_try_is_clean():
    """Report nothing for a guarded int() inside a try that catches ValueError.

    Returns:
        None. Asserts that the guarded conversion produces no finding with the enclosing ValueError handler.
    """
    src = (
        "def parse(raw):\n"
        "    try:\n"
        "        if raw.isnumeric():\n"
        "            return int(raw)\n"
        "    except ValueError:\n"
        "        return None\n"
        "    return None\n"
    )
    assert _analyse(src) == []


def test_guard_on_different_name_is_clean():
    """Report nothing when the isnumeric() guard checks a different variable from the one converted.

    Returns:
        None. Asserts that guarding a different variable produces no finding for the conversion.
    """
    src = "def parse(raw, other):\n    if other.isnumeric():\n        return int(raw)\n    return None\n"
    assert _analyse(src) == []


def test_unchecked_float_in_untyped_function_fires():
    """Flag int() of an unchecked float() result in an untyped function once as an unchecked float coercion.

    Returns:
        None after all assertions pass.
    """
    src = "def coerce(value):\n    number = float(value)\n    return int(number)\n"
    findings = _analyse(src)
    assert len(findings) == 1
    assert findings[0].metadata["shape"] == "unchecked-float-coercion"


def test_isfinite_guarded_float_is_clean():
    """Report nothing when math.isfinite guards the converted float.

    Returns:
        None. Asserts that the conversion produces no finding when math.isfinite checks the float.
    """
    src = "import math\n\ndef coerce(value):\n    number = float(value)\n    if math.isfinite(number):\n        return int(number)\n    return 0\n"
    assert _analyse(src) == []


def test_unrelated_isfinite_call_does_not_suppress():
    """Flag int(number) once when math.isfinite checks a different value.

    Returns:
        None after checking the finding count, unchecked-float shape, and converted name.
    """
    # For a finite check to suppress the finding, it must name the int() argument or a name in the float() input.
    src = "import math\n\ndef coerce(value, other):\n    if math.isfinite(other):\n        pass\n    number = float(value)\n    return int(number)\n"
    findings = _analyse(src)
    assert len(findings) == 1
    assert findings[0].metadata["shape"] == "unchecked-float-coercion"
    assert findings[0].metadata["value"] == "number"


def test_isfinite_on_float_source_is_clean():
    """Report nothing when an isfinite early exit checks the value before float() converts it.

    Returns:
        None. Asserts that checking the input to float() leaves no finding for the later int() call.
    """
    # The rule treats a finite check on the input to float() as covering the resulting float.
    src = "import math\n\ndef coerce(value):\n    if not math.isfinite(value):\n        return 0\n    number = float(value)\n    return int(number)\n"
    assert _analyse(src) == []


def test_typed_parameter_function_float_is_clean():
    """Report nothing for the float-then-int conversion in a function whose parameter is annotated str.

    Returns:
        None after all assertions pass.
    """
    src = "def coerce(value: str) -> int:\n    number = float(value)\n    return int(number)\n"
    assert _analyse(src) == []


def test_float_from_literal_is_clean():
    """Report nothing when float() converts a string literal.

    Returns:
        None. Asserts that converting a literal-sourced float to int produces no finding.
    """
    src = 'def coerce(value):\n    number = float("1.5")\n    return int(number)\n'
    assert _analyse(src) == []


def test_float_int_inside_try_overflow_is_clean():
    """Report nothing when int() of a float sits in a try that catches ValueError and OverflowError.

    Returns:
        None. Asserts that handling both ValueError and OverflowError leaves no findings.
    """
    src = (
        "def coerce(value):\n"
        "    number = float(value)\n"
        "    try:\n"
        "        return int(number)\n"
        "    except (ValueError, OverflowError):\n"
        "        return 0\n"
    )
    assert _analyse(src) == []


def test_rebound_int_is_clean():
    """Report nothing when the module defines its own int function.

    Returns:
        None. Asserts that a guarded call to the module's own int function produces no finding.
    """
    src = "def int(value):\n    return 0\n\ndef parse(raw):\n    if raw.isnumeric():\n        return int(raw)\n    return None\n"
    assert _analyse(src) == []


def test_nested_defensive_functions_flag_the_conversion_once():
    """Flag int() of a float inside a nested function once, as an unchecked float coercion.

    Returns:
        None. Asserts one unchecked-float finding for the nested conversion.
    """
    # Walking the inner conversion from both function scopes could collect the same site twice before deduplication.
    src = "def outer(x):\n    def inner(y):\n        number = float(y)\n        return int(number)\n    return inner(x)\n"
    findings = _analyse(src)
    assert len(findings) == 1
    assert findings[0].metadata["shape"] == "unchecked-float-coercion"


def test_float_in_try_value_error_only_still_fires_on_overflow():
    """Still flag int() of a float once when its try catches only ValueError.

    Returns:
        None. Asserts one unchecked-float finding when the handler catches only ValueError.
    """
    # The ValueError handler leaves the OverflowError from int(float("inf")) uncaught, so the rule still reports the conversion.
    src = "def coerce(value):\n    number = float(value)\n    try:\n        return int(number)\n    except ValueError:\n        return 0\n"
    findings = _analyse(src)
    assert len(findings) == 1
    assert findings[0].metadata["shape"] == "unchecked-float-coercion"


def test_guarded_string_in_try_overflow_only_still_fires_on_value_error():
    """Still flag a guarded int() once when its try catches only OverflowError.

    Returns:
        None. Asserts one guarded-string finding when the handler catches only OverflowError.
    """
    # The OverflowError handler leaves the ValueError from int("²") uncaught, so the rule still reports the conversion.
    src = (
        "def parse(raw):\n"
        "    if raw.isnumeric():\n"
        "        try:\n"
        "            return int(raw)\n"
        "        except OverflowError:\n"
        "            return 0\n"
        "    return None\n"
    )
    findings = _analyse(src)
    assert len(findings) == 1
    assert findings[0].metadata["shape"] == "guarded-string-coercion"


def test_conversion_in_try_else_clause_is_not_protected():
    """Flag int() of a float once when it sits in the else clause of a try with covering handlers.

    Returns:
        None. Asserts one unchecked-float finding for the conversion in the else clause.
    """
    # The handler only covers the try body, so an exception from int() in the else clause would escape it.
    src = (
        "def coerce(value):\n"
        "    number = float(value)\n"
        "    try:\n"
        "        pass\n"
        "    except (ValueError, OverflowError):\n"
        "        return 0\n"
        "    else:\n"
        "        return int(number)\n"
    )
    findings = _analyse(src)
    assert len(findings) == 1
    assert findings[0].metadata["shape"] == "unchecked-float-coercion"


def test_isascii_guard_with_isdigit_is_clean():
    """Report nothing when isascii() joins the isdigit() guard.

    Returns:
        None. Asserts that the combined isdigit() and isascii() guard leaves no findings.
    """
    # Adding isascii() to the isdigit() guard excludes the non-ASCII digits that int() would reject.
    src = "def parse(raw):\n    if raw.isdigit() and raw.isascii():\n        return int(raw)\n    return None\n"
    assert _analyse(src) == []


def test_isascii_negated_early_exit_is_clean():
    """Report nothing for a negated early exit on isdigit() and isascii() together.

    Returns:
        None. Asserts no findings when the early exit limits the conversion to ASCII digits.
    """
    src = "def parse(raw):\n    if not (raw.isdigit() and raw.isascii()):\n        raise ValueError\n    return int(raw)\n"
    assert _analyse(src) == []


def test_redundant_guards_flag_the_conversion_once():
    """Flag a conversion covered by both an early-exit guard and a direct guard once.

    Returns:
        None. Asserts one finding for the conversion that matches both guard patterns.
    """
    # The direct-guard and early-exit passes can both collect this conversion, so deduplication must leave one finding.
    src = (
        "def parse(raw):\n"
        "    if not raw.isdigit():\n"
        "        raise ValueError\n"
        "    if raw.isdigit():\n"
        "        value = int(raw)\n"
        "        print(value)\n"
    )
    findings = _analyse(src)
    assert len(findings) == 1


def test_definition_is_advisory_high_confidence_correctness():
    """Define the rule as an advisory, high-confidence correctness rule that is enabled by default.

    Returns:
        None. Asserts the rule's default severity, confidence, pillar, and enabled state.
    """
    definition = UnsafeNumericCoercionRule().definition()
    assert definition.default_severity.value == "advisory"
    assert definition.confidence.value == "high"
    assert definition.pillar.value == "correctness"
    assert definition.default_enabled is True
