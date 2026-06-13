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
    tree = ast.parse(source)
    file = SourceFile(absolute_path="/x.py", display_path="x.py", type="python")
    return AnalysisUnit(file=file, source=source, tree=tree)


def _ctx() -> RuleContext:
    rule = SubstringVocabularyMatchRule()
    return RuleContext(
        project_root="/",
        config=AnalysisConfig(rules={rule.definition().id: RuleSettings(enabled=True)}),
    )


def _analyse(source: str):
    return SubstringVocabularyMatchRule().analyse(_unit(source), _ctx())


def test_any_scan_over_parameter_lowered_text_fires():
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
    src = (
        'TOPIC_WORDS = frozenset({"refund", "fee"})\n\n'
        "def classify(text):\n"
        "    return any(term in text for term in TOPIC_WORDS)\n"
    )
    findings = _analyse(src)
    assert len(findings) == 1


def test_loop_form_fires():
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
    src = (
        "import re\n\n"
        'TERM_SET = ("fee", "form")\n\n'
        "def classify(message):\n"
        '    tokens = re.findall(r"\\w+", message.lower())\n'
        "    return any(term in tokens for term in TERM_SET)\n"
    )
    assert _analyse(src) == []


def test_same_name_token_reassignment_is_clean():
    # Reassigning the free-text parameter to a token list under the same name
    # makes `term in text` list membership, not substring matching - the rule
    # must not flag the tokenise-then-membership fix it recommends.
    src = (
        'TERM_SET = ("fee", "form")\n\n'
        "def classify(text):\n"
        "    text = text.split()\n"
        "    return any(term in text for term in TERM_SET)\n"
    )
    assert _analyse(src) == []


def test_compiled_word_boundary_regex_is_clean():
    src = (
        "import re\n\n"
        '_PATTERN = re.compile(r"\\b(?:fee|form)\\b")\n\n'
        "def classify(message):\n"
        "    return bool(_PATTERN.search(message.lower()))\n"
    )
    assert _analyse(src) == []


def test_phrase_only_vocabulary_is_clean():
    src = (
        'PHRASES = ("reset my password", "talk to a human")\n\n'
        "def route(message):\n"
        "    return any(term in message for term in PHRASES)\n"
    )
    assert _analyse(src) == []


def test_non_free_text_name_is_clean():
    # Marker scans over identifier-ish values are intentional substring checks.
    src = (
        'MARKERS = ("dummy", "example")\n\n'
        "def has_marker(secret):\n"
        "    normalized = secret.strip().lower()\n"
        "    return any(marker in normalized for marker in MARKERS)\n"
    )
    assert _analyse(src) == []


def test_call_derived_text_is_clean():
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
    src = (
        "def route(message):\n"
        '    terms = ("fee", "form")\n'
        "    return any(term in message for term in terms)\n"
    )
    assert _analyse(src) == []


def test_definition_is_advisory_medium_confidence_correctness():
    definition = SubstringVocabularyMatchRule().definition()
    assert definition.default_severity.value == "advisory"
    assert definition.confidence.value == "medium"
    assert definition.pillar.value == "correctness"
    assert definition.default_enabled is True
