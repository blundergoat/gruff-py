from gruffpy.rule.docs.useless_docstring_rule import UselessDocstringRule
from tests.unit.rule.docs._helpers import default_ctx, make_unit


def test_pure_restatement_emits():
    src = 'def process(value):\n    """Process the value."""\n    return value\n'
    findings = UselessDocstringRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].symbol == "process"
    assert findings[0].metadata["reason"] == "restates the signature without adding intent"


def test_thin_function_docstring_emits():
    src = 'def parse_config(path):\n    """Parse config."""\n    return path\n'
    findings = UselessDocstringRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].symbol == "parse_config"
    assert findings[0].metadata["kind"] == "function"


def test_thin_module_docstring_emits():
    src = '"""Module docstring."""\n\nVALUE = 1\n'
    findings = UselessDocstringRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].symbol == "<module>"
    assert findings[0].metadata["kind"] == "module"


def test_thin_class_docstring_emits():
    src = 'class AnalysisReport:\n    """Report."""\n    pass\n'
    findings = UselessDocstringRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].symbol == "AnalysisReport"
    assert findings[0].metadata["kind"] == "class"


def test_descriptive_summary_skipped():
    src = (
        "def get_name(self):\n"
        '    """Return the rule\'s stable identifier as configured in defaults()."""\n'
        "    return self._name\n"
    )
    assert UselessDocstringRule().analyse(make_unit(src), default_ctx()) == []


def test_descriptive_module_docstring_skipped():
    src = (
        '"""Builds the serialisable analysis report payload returned by CLI and API callers."""\n'
        "\n"
        "VALUE = 1\n"
    )
    assert UselessDocstringRule().analyse(make_unit(src), default_ctx()) == []


def test_descriptive_class_docstring_skipped():
    src = (
        "class AnalysisReport:\n"
        '    """Immutable analysis payload shared by reporters and exit-code handling."""\n'
        "    pass\n"
    )
    assert UselessDocstringRule().analyse(make_unit(src), default_ctx()) == []


def test_summary_plus_body_skipped():
    src = (
        "def process(value):\n"
        '    """Process the value.\n\n'
        "    More context: the value flows through three stages.\n"
        '    """\n'
        "    return value\n"
    )
    assert UselessDocstringRule().analyse(make_unit(src), default_ctx()) == []


def test_summary_with_args_section_skipped():
    src = (
        "def process(value):\n"
        '    """Process the value.\n\n'
        "    Args:\n"
        "        value: the thing.\n"
        '    """\n'
        "    return value\n"
    )
    assert UselessDocstringRule().analyse(make_unit(src), default_ctx()) == []


def test_private_function_skipped():
    src = 'def _process(value):\n    """Process the value."""\n    return value\n'
    assert UselessDocstringRule().analyse(make_unit(src), default_ctx()) == []
