from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.rule.context import RuleContext
from gruffpy.rule.docs.complex_branch_rationale_rule import ComplexBranchRationaleRule
from tests.unit.rule.docs._helpers import default_ctx, make_unit


def _complex_function(name: str = "route_payload", comment: str = "") -> str:
    """Return source for a function with eleven ``if`` branches, optionally preceded by one comment line.

    Args:
        name: Function name; defaults to ``route_payload``.
        comment: Comment line placed before the branches; empty adds none.

    Returns:
        The function source.
    """
    comment_line = f"    {comment}\n" if comment else ""
    branches = "".join(f"    if value == {index}:\n        total += {index}\n" for index in range(11))
    return f"def {name}(value):\n    total = 0\n{comment_line}{branches}    return total\n"


def test_complex_public_function_without_rationale_emits():
    """Report an undocumented eleven-branch public function once, recording cyclomatic above 10 and no docstring."""
    findings = ComplexBranchRationaleRule().analyse(make_unit(_complex_function()), default_ctx())

    assert len(findings) == 1
    assert findings[0].symbol == "route_payload"
    assert findings[0].metadata["cyclomatic"] > 10
    assert findings[0].metadata["hasDocstring"] is False


def test_substantive_docstring_skips_complex_function():
    """Report nothing when the complex function has a docstring that explains its branches."""
    src = (
        "def route_payload(value):\n"
        '    """Route compatibility payloads across legacy protocol branches.\n\n'
        "    The branch table mirrors the published wire contract while the "
        "downstream parser migrates.\n"
        '    """\n'
        "    total = 0\n" + "".join(f"    if value == {index}:\n        total += {index}\n" for index in range(11)) + "    return total\n"
    )

    assert ComplexBranchRationaleRule().analyse(make_unit(src), default_ctx()) == []


def test_branch_rationale_comment_skips_complex_function():
    """Report nothing when a compatibility rationale comment precedes the branches."""
    src = _complex_function(comment="# Compatibility fallback for legacy payload branches.")

    assert ComplexBranchRationaleRule().analyse(make_unit(src), default_ctx()) == []


def test_generic_branch_comment_still_emits():
    """Report the function once when its only comment is a generic one."""
    src = _complex_function(comment="# check condition")

    findings = ComplexBranchRationaleRule().analyse(make_unit(src), default_ctx())

    assert len(findings) == 1


def test_private_function_uses_higher_threshold():
    """Report nothing for the same eleven-branch function when it is private."""
    src = _complex_function(name="_route_payload")

    assert ComplexBranchRationaleRule().analyse(make_unit(src), default_ctx()) == []


def test_config_can_lower_private_threshold():
    """Report the private eleven-branch function once after options lower the private thresholds to the public values."""
    src = _complex_function(name="_route_payload")
    rule = ComplexBranchRationaleRule()
    ctx = RuleContext(
        project_root="/",
        config=AnalysisConfig(
            rules={
                rule.definition().id: RuleSettings(
                    options={
                        "cyclomatic_warning": 10,
                        "cognitive_warning": 15,
                        "private_cyclomatic_warning": 10,
                        "private_cognitive_warning": 15,
                    }
                )
            }
        ),
    )

    findings = rule.analyse(make_unit(src), ctx)

    assert len(findings) == 1
