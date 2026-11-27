import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.correctness.substring_vocabulary_match_rule import (
    SubstringVocabularyMatchRule,
)
from gruffpy.source.source_file import SourceFile


def _unit(source: str) -> AnalysisUnit:
    """Parse source into an analysis unit for x.py.

    Args:
        source: Python source to parse.

    Returns:
        Analysis unit containing the source and parsed tree for x.py.
    """
    tree = ast.parse(source)
    file = SourceFile(absolute_path="/x.py", display_path="x.py", type="python")
    return AnalysisUnit(file=file, source=source, tree=tree)


def _ctx() -> RuleContext:
    """Build a rule context with the substring vocabulary match rule enabled.

    Returns:
        Context enabling the substring vocabulary match rule.
    """
    rule = SubstringVocabularyMatchRule()
    return RuleContext(
        project_root="/",
        config=AnalysisConfig(rules={rule.definition().id: RuleSettings(enabled=True)}),
    )


def _analyse(source: str):
    """Run the substring vocabulary match rule over source as x.py.

    Args:
        source: Python source to analyse.

    Returns:
        The rule's findings, or an empty list when no scan qualifies.
    """
    return SubstringVocabularyMatchRule().analyse(_unit(source), _ctx())


def test_any_scan_over_parameter_lowered_text_fires():
    """Flag an any() substring scan over a lowered parameter once, naming the vocabulary and text and advising token matching.

    Returns:
        None after checking the finding count, metadata, and advice.
    """
    src = (
        'ROUTING_TERMS = ("fee", "form", "file")\n\n'
        "def route(message):\n"
        "    message_lower = message.lower()\n"
        "    return any(term in message_lower for term in ROUTING_TERMS)\n"
    )
    findings = _analyse(src)
    assert len(findings) == 1
    assert findings[0].metadata["vocabulary"] == "ROUTING_TERMS"
    assert findings[0].metadata["text"] == "message_lower"
    assert "word-boundary or token matching" in findings[0].message


def test_any_scan_directly_over_parameter_fires():
    """Flag an any() scan of a frozenset vocabulary directly over a parameter once.

    Returns:
        None after checking the finding count.
    """
    src = 'TOPIC_WORDS = frozenset({"refund", "fee"})\n\ndef classify(text):\n    return any(term in text for term in TOPIC_WORDS)\n'
    findings = _analyse(src)
    assert len(findings) == 1


def test_loop_form_fires():
    """Flag a for loop that tests each vocabulary term with in against a parameter once.

    Returns:
        None after checking the finding count.
    """
    src = (
        'TOPIC_WORDS = ("fee", "form")\n\n'
        "def classify(question):\n"
        "    for term in TOPIC_WORDS:\n"
        "        if term in question:\n"
        "            return term\n"
        "    return None\n"
    )
    findings = _analyse(src)
    assert len(findings) == 1


def test_token_membership_after_findall_is_clean():
    """Report nothing when the terms are checked against re.findall tokens instead of the text.

    Returns:
        None after checking that the rule reports no findings.
    """
    src = (
        "import re\n\n"
        'TERM_SET = ("fee", "form")\n\n'
        "def classify(message):\n"
        '    tokens = re.findall(r"\\w+", message.lower())\n'
        "    return any(term in tokens for term in TERM_SET)\n"
    )
    assert _analyse(src) == []


def test_same_name_token_reassignment_is_clean():
    """Report nothing when the text parameter is reassigned to its split tokens before the scan.

    Returns:
        None after checking that the rule reports no findings.
    """
    # After text.split(), in checks whole tokens under the same name, so the rule should accept its own suggested fix.
    src = 'TERM_SET = ("fee", "form")\n\ndef classify(text):\n    text = text.split()\n    return any(term in text for term in TERM_SET)\n'
    assert _analyse(src) == []


def test_compiled_word_boundary_regex_is_clean():
    """Report nothing for a compiled word-boundary regex search over the lowered message.

    Returns:
        None after checking that the rule reports no findings.
    """
    src = 'import re\n\n_PATTERN = re.compile(r"\\b(?:fee|form)\\b")\n\ndef classify(message):\n    return bool(_PATTERN.search(message.lower()))\n'
    assert _analyse(src) == []


def test_phrase_only_vocabulary_is_clean():
    """Report nothing when every vocabulary entry is a multi-word phrase.

    Returns:
        None after checking that the rule reports no findings.
    """
    src = 'PHRASES = ("reset my password", "talk to a human")\n\ndef route(message):\n    return any(term in message for term in PHRASES)\n'
    assert _analyse(src) == []


def test_non_free_text_name_is_clean():
    """Report nothing for a marker scan over a normalized local derived from the secret parameter.

    Returns:
        None after checking that the rule reports no findings.
    """
    # The rule skips this marker scan because neither secret nor normalized has a free-text name token.
    src = (
        'MARKERS = ("dummy", "example")\n\n'
        "def has_marker(secret):\n"
        "    normalized = secret.strip().lower()\n"
        "    return any(marker in normalized for marker in MARKERS)\n"
    )
    assert _analyse(src) == []


def test_call_derived_text_is_clean():
    """Report nothing when the scanned text comes from a function call, not a parameter.

    Returns:
        None after checking that the rule reports no findings.
    """
    src = (
        'TERMS = ("fee", "form")\n\n'
        "def load():\n"
        '    return "irrelevant"\n\n'
        "def route(message):\n"
        "    text = load()\n"
        "    return any(term in text for term in TERMS)\n"
    )
    assert _analyse(src) == []


def test_local_vocabulary_is_clean():
    """Report nothing when the vocabulary is a local tuple, not a module constant.

    Returns:
        None after checking that the rule reports no findings.
    """
    src = 'def route(message):\n    terms = ("fee", "form")\n    return any(term in message for term in terms)\n'
    assert _analyse(src) == []


def test_nested_function_scan_flagged_once():
    """Flag a scan inside a nested function once, though the outer function shares its text parameter name.

    Returns:
        None after checking the finding count.
    """
    # The scan belongs to the inner pass even when both functions use text, so the outer pass must skip the inner body.
    src = (
        'TERMS = ("fee", "form")\n\n'
        "def outer(text):\n"
        "    def inner(text):\n"
        "        return any(term in text for term in TERMS)\n"
        "    return inner(text)\n"
    )
    findings = _analyse(src)
    assert len(findings) == 1


def test_dict_typed_parameter_membership_is_clean():
    """Report nothing for a key-membership scan over a parameter annotated as a dict.

    Returns:
        None after checking that the rule reports no findings.
    """
    # Dict membership checks keys, so the rule skips tool_input even though its name includes the free-text token input.
    src = (
        "from typing import Any\n\n"
        'RANGE_KEYS = ("offset", "limit", "ranges")\n\n'
        "def matches(tool_input: dict[str, Any]) -> bool:\n"
        "    return any(k in tool_input for k in RANGE_KEYS)\n"
    )
    assert _analyse(src) == []


def test_str_annotated_parameter_still_fires():
    """Flag a scan over a parameter annotated as str once.

    Returns:
        None after checking the finding count.
    """
    # The collection-annotation guard must not suppress genuine str parameters.
    src = 'TERMS = ("fee", "form")\n\ndef classify(message: str) -> bool:\n    return any(term in message for term in TERMS)\n'
    findings = _analyse(src)
    assert len(findings) == 1


def test_optional_collection_parameter_is_clean():
    """Report nothing for a scan over a parameter annotated Optional[list[str]].

    Returns:
        None after checking that the rule reports no findings.
    """
    # The rule sees the list inside Optional and excludes the parameter from free-text scanning.
    src = (
        "from typing import Optional\n\n"
        'KEYS = ("offset", "limit", "ranges")\n\n'
        "def matches(tool_input: Optional[list[str]]) -> bool:\n"
        "    return any(k in tool_input for k in KEYS)\n"
    )
    assert _analyse(src) == []


def test_union_collection_parameter_is_clean():
    """Report nothing for a scan over a parameter annotated Union[str, dict].

    Returns:
        None. Asserts that the vocabulary scan produces no findings for the union-annotated parameter.
    """
    src = (
        "from typing import Union\n\n"
        'KEYS = ("offset", "limit")\n\n'
        "def classify(query: Union[str, dict]) -> bool:\n"
        "    return any(k in query for k in KEYS)\n"
    )
    assert _analyse(src) == []


def test_definition_is_advisory_medium_confidence_correctness():
    """Define the rule as an advisory, medium-confidence correctness rule that is enabled by default.

    Returns:
        None. Asserts the rule's default severity, confidence, pillar, and enabled state.
    """
    definition = SubstringVocabularyMatchRule().definition()
    assert definition.default_severity.value == "advisory"
    assert definition.confidence.value == "medium"
    assert definition.pillar.value == "correctness"
    assert definition.default_enabled is True
