from gruffpy.rule.docs.useless_docstring_rule import UselessDocstringRule
from tests.unit.rule.docs._helpers import default_ctx, make_unit


def test_pure_restatement_emits():
    src = 'def process(value):\n    """Process the value."""\n    return value\n'
    findings = UselessDocstringRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].symbol == "process"


def test_descriptive_summary_skipped():
    src = (
        "def get_name(self):\n"
        '    """Return the rule\'s stable identifier as configured in defaults()."""\n'
        "    return self._name\n"
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
