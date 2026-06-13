import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.correctness.unsafe_numeric_coercion_rule import UnsafeNumericCoercionRule
from gruffpy.source.source_file import SourceFile


def _unit(source: str) -> AnalysisUnit:
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]  # AST parent links
    file = SourceFile(absolute_path="/x.py", display_path="x.py", type="python")
    return AnalysisUnit(file=file, source=source, tree=tree)


def _ctx() -> RuleContext:
    rule = UnsafeNumericCoercionRule()
    return RuleContext(
        project_root="/",
        config=AnalysisConfig(rules={rule.definition().id: RuleSettings(enabled=True)}),
    )


def _analyse(source: str):
    return UnsafeNumericCoercionRule().analyse(_unit(source), _ctx())


def test_guard_then_int_fires():
    src = "def parse(raw):\n    if raw.isnumeric():\n        return int(raw)\n    return None\n"
    findings = _analyse(src)
    assert len(findings) == 1
    assert findings[0].metadata["shape"] == "guarded-string-coercion"
    assert findings[0].metadata["guard"] == "isnumeric"


def test_isdigit_guard_in_ternary_fires():
    src = "def parse(raw):\n    return int(raw) if raw.isdigit() else 0\n"
    findings = _analyse(src)
    assert len(findings) == 1
    assert findings[0].metadata["guard"] == "isdigit"


def test_early_exit_negated_guard_fires():
    src = (
        "def parse(raw):\n"
        "    if not raw.isdigit():\n"
        '        raise ValueError("not a number")\n'
        "    return int(raw)\n"
    )
    findings = _analyse(src)
    assert len(findings) == 1
    assert findings[0].metadata["shape"] == "guarded-string-coercion"


def test_try_except_value_error_is_clean():
    src = (
        "def parse(raw):\n"
        "    try:\n"
        "        return int(raw)\n"
        "    except ValueError:\n"
        "        return None\n"
    )
    assert _analyse(src) == []


def test_guarded_int_inside_outer_try_is_clean():
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
    src = (
        "def parse(raw, other):\n"
        "    if other.isnumeric():\n"
        "        return int(raw)\n"
        "    return None\n"
    )
    assert _analyse(src) == []


def test_unchecked_float_in_untyped_function_fires():
    src = "def coerce(value):\n    number = float(value)\n    return int(number)\n"
    findings = _analyse(src)
    assert len(findings) == 1
    assert findings[0].metadata["shape"] == "unchecked-float-coercion"


def test_isfinite_guarded_float_is_clean():
    src = (
        "import math\n\n"
        "def coerce(value):\n"
        "    number = float(value)\n"
        "    if math.isfinite(number):\n"
        "        return int(number)\n"
        "    return 0\n"
    )
    assert _analyse(src) == []


def test_unrelated_isfinite_call_does_not_suppress():
    # math.isfinite on a different value must not suppress the int(float(...))
    # finding; the finite check has to cover the converted value or its source.
    src = (
        "import math\n\n"
        "def coerce(value, other):\n"
        "    if math.isfinite(other):\n"
        "        pass\n"
        "    number = float(value)\n"
        "    return int(number)\n"
    )
    findings = _analyse(src)
    assert len(findings) == 1
    assert findings[0].metadata["shape"] == "unchecked-float-coercion"
    assert findings[0].metadata["value"] == "number"


def test_isfinite_on_float_source_is_clean():
    # A finite check on the source value (before float()) also protects the
    # later int(float(value)) conversion.
    src = (
        "import math\n\n"
        "def coerce(value):\n"
        "    if not math.isfinite(value):\n"
        "        return 0\n"
        "    number = float(value)\n"
        "    return int(number)\n"
    )
    assert _analyse(src) == []


def test_typed_parameter_function_float_is_clean():
    src = "def coerce(value: str) -> int:\n    number = float(value)\n    return int(number)\n"
    assert _analyse(src) == []


def test_float_from_literal_is_clean():
    src = 'def coerce(value):\n    number = float("1.5")\n    return int(number)\n'
    assert _analyse(src) == []


def test_float_int_inside_try_overflow_is_clean():
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
    src = (
        "def int(value):\n"
        "    return 0\n\n"
        "def parse(raw):\n"
        "    if raw.isnumeric():\n"
        "        return int(raw)\n"
        "    return None\n"
    )
    assert _analyse(src) == []


def test_definition_is_advisory_high_confidence_correctness():
    definition = UnsafeNumericCoercionRule().definition()
    assert definition.default_severity.value == "advisory"
    assert definition.confidence.value == "high"
    assert definition.pillar.value == "correctness"
    assert definition.default_enabled is True
