"""``test-quality.setup-bloat`` measures a fixture by its code lines, so documenting one never makes it bloated."""

from gruffpy.rule.test_quality.setup_bloat_rule import SetupBloatRule
from tests.unit.rule.test_quality._helpers import default_ctx, make_unit

MAX_SETUP_LINES = 30  # the rule's default maxSetupLines


def _fixture(code_lines: int, documentation: str = "") -> str:
    """Return a module whose ``@pytest.fixture()`` function holds exactly *code_lines* code lines."""
    body = "\n".join(f"    value_{i} = {i}" for i in range(code_lines - 2))
    return f"import pytest\n\n\n@pytest.fixture()\ndef shared_config():\n{documentation}{body}\n    return value_0\n"


def test_fixture_long_in_code_lines_is_reported():
    over_limit = MAX_SETUP_LINES + 1
    findings = SetupBloatRule().analyse(make_unit(_fixture(over_limit)), default_ctx())
    assert [finding.metadata["lines"] for finding in findings] == [over_limit]


def test_documented_fixture_under_the_limit_is_not_reported():
    fields = "\n".join(f"    Field {i} is explained here." for i in range(8))
    docstring = f'    """Build the shared configuration.\n\n{fields}\n    """\n'
    comments = "".join(f"    # Step {i}.\n" for i in range(5))
    module = _fixture(MAX_SETUP_LINES, docstring + comments)
    assert SetupBloatRule().analyse(make_unit(module), default_ctx()) == []
