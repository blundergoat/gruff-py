"""``test-quality.setup-bloat`` measures a fixture by its code lines, so documenting one never makes it bloated."""

from dataclasses import replace
from textwrap import indent

import pytest

from gruffpy.rule.registry import RuleRegistry
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


@pytest.mark.parametrize(
    ("display_path", "is_method"),
    [("docs/_ext/djangodocs.py", False), ("fastapi/applications.py", True)],
    ids=["sphinx-extension", "application-method"],
)
def test_production_setup_hooks_are_not_reported(display_path: str, is_method: bool):
    """Keep the two observed production hook shapes outside test setup detection.

    Args:
        display_path: Observed non-test source path.
        is_method: Whether the hook is an application method rather than a module function.
    """
    source = _fixture(MAX_SETUP_LINES + 1).replace("@pytest.fixture()\n", "").replace("shared_config", "setup")
    if is_method:
        function = source.split("\n\n\n", 1)[1].replace("def setup():", "def setup(self):")
        source = "class Application:\n" + indent(function, "    ")
    assert SetupBloatRule().analyse(make_unit(source, display_path), default_ctx()) == []


@pytest.mark.parametrize(
    "hook_name",
    ["setUp", "setUpClass", "setup_method", "setup_class", "setup_function"],
    ids=["setUp", "setUpClass", "setup_method", "setup_class", "setup_function"],
)
def test_conventional_lifecycle_names_are_retained(hook_name: str):
    """Preserve each existing lifecycle spelling while narrowing only plain setup.

    Args:
        hook_name: Existing supported lifecycle spelling.
    """
    source = _fixture(MAX_SETUP_LINES + 1).replace("@pytest.fixture()\n", "").replace("shared_config", hook_name)
    findings = SetupBloatRule().analyse(make_unit(source), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["lines"] == MAX_SETUP_LINES + 1


@pytest.mark.parametrize(
    "display_path",
    ["test_setup.py", "tests/template_tests/utils.py"],
    ids=["test-module", "test-helper"],
)
def test_plain_setup_in_test_context_is_retained(display_path: str):
    """Retain ordinary test modules and the observed Django test-helper context.

    Args:
        display_path: Conventional test-module or test-helper path.
    """
    source = _fixture(MAX_SETUP_LINES + 1).replace("@pytest.fixture()\n", "").replace("shared_config", "setup")
    findings = SetupBloatRule().analyse(make_unit(source, display_path), default_ctx())
    assert len(findings) == 1


def test_decorated_setup_outside_test_paths_is_retained():
    """Explicit fixture evidence remains sufficient in a support library."""
    source = _fixture(MAX_SETUP_LINES + 1).replace("shared_config", "setup")
    findings = SetupBloatRule().analyse(make_unit(source, "lib/sqlalchemy/testing/fixtures/base.py"), default_ctx())
    assert len(findings) == 1


def test_default_off_and_explicit_enable_use_the_same_detector():
    """Keep oversized fixtures quiet by default and report them when explicitly enabled."""
    registry = RuleRegistry.defaults()
    unit = make_unit(_fixture(MAX_SETUP_LINES + 1))
    context = default_ctx()
    assert not SetupBloatRule().definition().default_enabled
    assert not any(finding.rule_id == SetupBloatRule.ID for finding in registry.analyse([unit], context))
    settings = replace(context.config.rule_settings(SetupBloatRule.ID), enabled=True)
    enabled_context = replace(context, config=context.config.with_rule_settings(SetupBloatRule.ID, settings))
    enabled = [finding for finding in registry.analyse([unit], enabled_context) if finding.rule_id == SetupBloatRule.ID]
    assert len(enabled) == 1
    assert enabled[0].metadata["lines"] == MAX_SETUP_LINES + 1


def test_plain_setup_keeps_test_path_for_explicit_file_input():
    """Retain test-directory evidence when an explicit file displays only its basename."""
    source = _fixture(MAX_SETUP_LINES + 1).replace("@pytest.fixture()\n", "").replace("shared_config", "setup")
    unit = make_unit(source, "utils.py")
    unit = replace(unit, file=replace(unit.file, absolute_path="/repo/tests/template_tests/utils.py"))
    findings = SetupBloatRule().analyse(unit, default_ctx())
    assert len(findings) == 1
    assert findings[0].file_path == "utils.py"
    assert findings[0].metadata["lines"] == MAX_SETUP_LINES + 1
