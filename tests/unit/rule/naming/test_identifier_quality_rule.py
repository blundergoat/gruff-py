"""Exercise placeholder names as users encounter them in scan results.

The tests distinguish genuine draft names from legitimate work-queue language.
Retained controls protect the warning text and identities users baseline.
"""

import ast

import pytest

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.naming.identifier_quality_rule import IdentifierQualityRule
from gruffpy.source.source_file import SourceFile


def _unit(source: str) -> AnalysisUnit:
    """Parse one user file into the analysis unit scanned by the rule.

    Args:
        source: User-authored Python; empty text means no identifiers to review.

    Returns:
        An x.py unit with parent-linked descendants; empty source produces a module with no statements.
    """
    tree = ast.parse(source)
    # Match production parsing so rule fixtures receive the same AST metadata.
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]  # ast.AST does not declare the parent field that the production parser attaches.
    return AnalysisUnit(
        file=SourceFile(absolute_path="/x.py", display_path="x.py", type="python"),
        source=source,
        tree=tree,
    )


def _ctx() -> RuleContext:
    """Build the default identifier-quality settings a normal scan uses.

    Returns:
        Rule context with the identifier-quality rule enabled and its options empty.
    """
    rule = IdentifierQualityRule()
    return RuleContext(
        project_root="/",
        config=AnalysisConfig(rules={rule.definition().id: RuleSettings(enabled=True)}),
    )


def test_temp_variable_fires():
    """Report temp once, with a pattern that names it a placeholder token.

    Returns:
        None after checking that temp produces one finding with a placeholder token reason.
    """
    src = "temp = 1\n"
    findings = IdentifierQualityRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert "placeholder token 'temp'" in findings[0].metadata["pattern"]


def test_foo_variable_fires():
    """Report one finding for source whose only statement assigns foo.

    Returns:
        None after the assertion succeeds.
    """
    src = "foo = 1\n"
    findings = IdentifierQualityRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1


def test_result1_fires():
    """Report one finding with a numbered-placeholder pattern for source that only assigns result1.

    Returns:
        None after the assertions succeed.
    """
    src = "result1 = 1\n"
    findings = IdentifierQualityRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert "numbered placeholder" in findings[0].metadata["pattern"]


def test_data42_fires():
    """Report one finding for source whose only statement assigns data42.

    Returns:
        None after the assertion succeeds.
    """
    src = "data42 = []\n"
    findings = IdentifierQualityRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1


def test_descriptive_name_does_not_fire():
    """Report nothing for user_count and response.

    Returns:
        None after the assertion succeeds.
    """
    src = "user_count = 1\nresponse = None\n"
    findings = IdentifierQualityRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_temperature_does_not_fire():
    """Report nothing for temperature, which only begins with temp.

    Returns:
        None after checking that temperature produces no findings.
    """
    # 'temperature' tokenizes to ['temperature'] - first token 'temperature'
    # is NOT 'temp'. Make sure we match exact tokens, not prefixes.
    src = "temperature = 20\n"
    findings = IdentifierQualityRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_dunder_does_not_fire():
    """Report nothing for the dunder class attribute __foo__.

    Returns:
        None after the assertion succeeds.
    """
    src = "class C:\n    __foo__ = None\n"
    findings = IdentifierQualityRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_function_name_fires():
    """Report a function named foo among the findings.

    Returns:
        None after the assertion succeeds.
    """
    src = "def foo(): return 1\n"
    findings = IdentifierQualityRule().analyse(_unit(src), _ctx())
    assert any(f.metadata["identifier"] == "foo" for f in findings)


def test_camel_case_placeholder_fires():
    """Report one finding for source whose only statement assigns FooBar.

    Returns:
        None after the assertion succeeds.
    """
    src = "FooBar = 1\n"
    findings = IdentifierQualityRule().analyse(_unit(src), _ctx())
    # Camel-case tokenization exposes foo as the leading placeholder.
    assert len(findings) == 1


def test_parameter_temp_fires():
    """Report the parameter temp among the findings.

    Returns:
        None after the assertion succeeds.
    """
    src = "def f(temp): return temp\n"
    findings = IdentifierQualityRule().analyse(_unit(src), _ctx())
    assert any(f.metadata["identifier"] == "temp" for f in findings)


def test_result_without_number_does_not_fire():
    """Report nothing for result without a number.

    Returns:
        None after checking that unnumbered result produces an empty findings list.
    """
    src = "result = compute()\n"
    findings = IdentifierQualityRule().analyse(_unit(src), _ctx())
    # Unnumbered result is allowed; numbered result names are flagged.
    assert findings == []


def test_todo_domain_name_does_not_fire():
    """Report nothing for a class named TodoDensityRule.

    Returns:
        None after checking that the class name TodoDensityRule produces no findings.
    """
    src = "class TodoDensityRule: pass\n"
    findings = IdentifierQualityRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_domain_numbers_do_not_fire():
    """Report nothing for adr020, step0 and V110, domain names that end in numbers.

    Returns:
        None after the assertion succeeds.
    """
    src = "adr020 = 'accepted'\nstep0 = 'bootstrap'\nV110 = 'protocol'\n"
    findings = IdentifierQualityRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_todo_work_queue_name_does_not_fire() -> None:
    """Keep a populated and consumed user work queue out of placeholder results.

    Returns:
        None after checking that todo produces no findings when used as a work queue.
    """
    user_source = "todo = [task for task in tasks if task.ready]\nfor task in todo:\n    consume(task)\n"

    user_findings = IdentifierQualityRule().analyse(_unit(user_source), _ctx())

    assert user_findings == []


def test_todo_none_is_not_inferred_as_placeholder() -> None:
    """Avoid guessing unfinished work from a user's todo name alone.

    Returns:
        None after checking that assigning None to todo produces no findings.
    """
    # A user may initialize a legitimate domain slot before loading its value.
    user_source = "todo = None\n"

    user_findings = IdentifierQualityRule().analyse(_unit(user_source), _ctx())

    assert user_findings == []


@pytest.mark.parametrize(
    ("user_source", "expected_identifier", "expected_fingerprint", "expected_identity"),
    [
        ("temp = None\n", "temp", "dbd0d9bc18dfb0ca", "756b3afb96f5b929"),
        ("foo = None\n", "foo", "38d709870aa21f21", "cc1867a989f7a73d"),
        ("result1 = None\n", "result1", "1ccf42a0c55a51b1", "202743f7eaf19752"),
    ],
    ids=["temp-prefix", "foo-prefix", "numbered-result"],
)
def test_retained_placeholders_keep_user_finding_identity(
    user_source: str,
    expected_identifier: str,
    expected_fingerprint: str,
    expected_identity: str,
) -> None:
    """Keep genuine placeholder warnings stable for existing user baselines.

    Args:
        user_source: One placeholder declaration; empty text is not a case.
        expected_identifier: Name the user sees in finding metadata.
        expected_fingerprint: Location-sensitive baseline identity.
        expected_identity: Line-insensitive finding identity.

    Returns:
        None after checking the first finding's identifier, fingerprint and stable identity.
    """
    user_finding = IdentifierQualityRule().analyse(_unit(user_source), _ctx())[0]

    assert user_finding.metadata["identifier"] == expected_identifier
    assert user_finding.fingerprint() == expected_fingerprint
    assert user_finding.stable_identity() == expected_identity
