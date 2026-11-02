import ast
from dataclasses import replace

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.dead_code_allowlist import DeadCodeAllowlist
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.dead_code.exported_but_unreferenced_rule import ExportedButUnreferencedRule
from gruffpy.source.source_file import SourceFile

_DEAD_FUNCTION_MODULE = (
    '__all__ = ["render_legacy", "render_current"]\n\n'
    "def render_legacy(payload):\n"
    "    return payload\n\n"
    "def render_current(payload):\n"
    "    return payload\n"
)
_REEXPORT_INIT = "from pkg.render import render_current, render_legacy\n"
_CALLER_MODULE = "from pkg.render import render_current\n\ndef run(payload):\n    return render_current(payload)\n\nresult = run({})\n"


def _unit(source: str, display_path: str) -> AnalysisUnit:
    """Parse source into an analysis unit at display_path.

    Args:
        source: Python source to parse.
        display_path: Project-relative path of the unit.

    Returns:
        The analysis unit.
    """
    tree = ast.parse(source)
    file = SourceFile(absolute_path=f"/{display_path}", display_path=display_path, type="python")
    return AnalysisUnit(file=file, source=source, tree=tree)


def _ctx(
    scan_scope: str = "full-project",
    *,
    options: dict[str, object] | None = None,
    allowlist: DeadCodeAllowlist | None = None,
) -> RuleContext:
    """Build a rule context with the exported-but-unreferenced rule enabled.

    Args:
        scan_scope: Scan scope the context reports; defaults to ``full-project``.
        options: Rule options; None applies none.
        allowlist: Dead-code allowlist; None applies an empty one.

    Returns:
        The rule context.
    """
    rule = ExportedButUnreferencedRule()
    settings = RuleSettings(enabled=True, options=dict(options or {}))
    config = AnalysisConfig(
        rules={rule.definition().id: settings},
        dead_code_allowlist=allowlist or DeadCodeAllowlist(),
    )
    return RuleContext(project_root="/", config=config, scan_scope=scan_scope)


def _analyse(units: list[AnalysisUnit], context: RuleContext | None = None):
    """Run the exported-but-unreferenced rule over the units as one project.

    Args:
        units: Analysis units analysed together.
        context: Rule context; None uses a full-project context with default settings.

    Returns:
        The rule's findings.
    """
    return ExportedButUnreferencedRule().analyse_project(units, context or _ctx())


def test_dead_export_in_all_plus_reexport_fires_under_full_project():
    """Report only ``render_legacy``, which ``__all__`` and a re-export name but nothing calls, as an unreferenced function.

    The finding's message contains the phrase ``no reference beyond its definition``.
    """
    units = [
        _unit(_DEAD_FUNCTION_MODULE, "pkg/render.py"),
        _unit(_REEXPORT_INIT, "pkg/__init__.py"),
        _unit(_CALLER_MODULE, "pkg/app.py"),
    ]
    findings = _analyse(units)
    assert [finding.symbol for finding in findings] == ["render_legacy"]
    assert findings[0].metadata["kind"] == "function"
    assert "no reference beyond its definition" in findings[0].message


def test_called_symbol_is_clean():
    """Report nothing once another module calls both exported functions."""
    units = [
        _unit(_DEAD_FUNCTION_MODULE, "pkg/render.py"),
        _unit(_REEXPORT_INIT, "pkg/__init__.py"),
        _unit(
            "from pkg.render import render_current, render_legacy\n\nresult = render_legacy(render_current({}))\n",
            "pkg/app.py",
        ),
    ]
    findings = _analyse(units)
    assert [finding.symbol for finding in findings] == []


def test_reference_from_an_ignored_file_counts_but_the_file_never_reports():
    """Count a call in a reference-only tree while reporting only symbols still unreferenced everywhere."""
    units = [
        _unit(_DEAD_FUNCTION_MODULE, "pkg/render.py"),
        _unit(_REEXPORT_INIT, "pkg/__init__.py"),
        _unit(_CALLER_MODULE, "pkg/app.py"),
    ]
    ignored_test = ast.parse("from pkg.render import render_legacy\n\ndef test_legacy():\n    assert render_legacy({}) == {}\n")
    ignored_dead_helper = ast.parse("def unused_fixture_builder():\n    return {}\n")
    context = replace(_ctx(), reference_trees=(ignored_test, ignored_dead_helper))
    assert _analyse(units, context) == []


def test_partial_scope_suppresses_entirely():
    """Report nothing under a partial scan scope."""
    units = [_unit(_DEAD_FUNCTION_MODULE, "pkg/render.py")]
    assert _analyse(units, _ctx(scan_scope="partial-scope")) == []


def test_default_context_scope_is_suppressed():
    """Report nothing under a rule context built with its default scan scope."""
    units = [_unit(_DEAD_FUNCTION_MODULE, "pkg/render.py")]
    rule = ExportedButUnreferencedRule()
    config = AnalysisConfig(rules={rule.definition().id: RuleSettings(enabled=True)})
    context = RuleContext(project_root="/", config=config)
    assert rule.analyse_project(units, context) == []


def test_attribute_access_counts_as_use():
    """Count a call through the module attribute ``pkg.util.helper`` as a use."""
    units = [
        _unit("def helper():\n    return 1\n", "pkg/util.py"),
        _unit("import pkg.util\n\nvalue = pkg.util.helper()\n", "pkg/app.py"),
    ]
    assert _analyse(units) == []


def test_getattr_string_counts_as_use():
    """Count a ``getattr`` lookup by string name as a use."""
    units = [
        _unit("def handler():\n    return 1\n", "pkg/util.py"),
        _unit('import pkg.util\n\nfn = getattr(pkg.util, "handler")\n', "pkg/app.py"),
    ]
    assert _analyse(units) == []


def test_aliased_import_counts_as_use():
    """Count an aliased import as a use of the original name."""
    units = [
        _unit("def legacy_name():\n    return 1\n", "pkg/util.py"),
        _unit("from pkg.util import legacy_name as modern_name\n", "pkg/app.py"),
    ]
    assert _analyse(units) == []


def test_class_used_only_as_base_is_clean():
    """Count use as another class's base as a use of the class."""
    units = [
        _unit("class BasePort:\n    pass\n", "pkg/ports.py"),
        _unit(
            "from pkg.ports import BasePort\n\nclass FilePort(BasePort):\n    pass\n\nport = FilePort()\n",
            "pkg/app.py",
        ),
    ]
    findings = _analyse(units)
    assert [finding.symbol for finding in findings] == []


def test_framework_decorated_definition_is_exempt():
    """Exempt a function decorated with ``click.command()``."""
    units = [
        _unit(
            "import click\n\n@click.command()\ndef cli_entry():\n    return 0\n",
            "pkg/cli.py",
        ),
    ]
    assert _analyse(units) == []


def test_fastapi_on_event_handler_is_exempt():
    """Exempt an async handler registered with ``app.on_event``."""
    # @app.on_event("startup") is registered by the decorator and called by the
    # framework, never by name - it must not be flagged as unreferenced.
    units = [
        _unit(
            'import app\n\n@app.on_event("startup")\nasync def startup_event():\n    return None\n',
            "pkg/main.py",
        ),
    ]
    assert _analyse(units) == []


def test_flask_before_request_handler_is_exempt():
    """Exempt a handler registered with ``app.before_request``."""
    units = [
        _unit(
            "import app\n\n@app.before_request\ndef load_user():\n    return None\n",
            "pkg/web.py",
        ),
    ]
    assert _analyse(units) == []


def test_entry_point_pattern_option_exempts():
    """Exempt a function matching an ``entryPointPatterns`` glob."""
    units = [_unit("def handle_payment(event):\n    return event\n", "pkg/handlers.py")]
    context = _ctx(options={"entryPointPatterns": ["handle_*"]})
    assert _analyse(units, context) == []


def test_dead_code_allowlist_symbol_exempts():
    """Exempt a function the dead-code allowlist names as a symbol."""
    units = [_unit("def keep_me():\n    return 1\n", "pkg/api.py")]
    context = _ctx(allowlist=DeadCodeAllowlist(symbols=("keep_me",)))
    assert _analyse(units, context) == []


def test_dead_code_allowlist_path_exempts():
    """Exempt a function in a file the dead-code allowlist names by path."""
    units = [_unit("def keep_me():\n    return 1\n", "pkg/public_api.py")]
    context = _ctx(allowlist=DeadCodeAllowlist(paths=("pkg/public_api.py",)))
    assert _analyse(units, context) == []


def test_test_files_produce_no_candidates_but_count_as_users():
    """Report nothing when only a test calls a function, and nothing for an uncalled helper under ``tests``."""
    units = [
        _unit("def fixture_target():\n    return 1\n", "pkg/util.py"),
        _unit(
            "from pkg.util import fixture_target\n\ndef test_it():\n    assert fixture_target() == 1\n",
            "tests/test_util.py",
        ),
        _unit("def helper_only_in_tests():\n    return 2\n", "tests/support.py"),
    ]
    findings = _analyse(units)
    assert [finding.symbol for finding in findings] == []


def test_private_and_dunder_names_are_not_candidates():
    """Report nothing for an uncalled private function and private class."""
    units = [
        _unit("def _internal():\n    return 1\n\nclass _Helper:\n    pass\n", "pkg/util.py"),
    ]
    assert _analyse(units) == []


def test_underscore_test_suffix_files_are_not_candidates():
    """Report nothing for an uncalled function in a file named with a ``_test`` suffix."""
    # `widget_test.py` is a pytest/unittest test file even outside a tests/ dir,
    # so its symbols are callers, not export candidates.
    units = [_unit("def widget_case():\n    return 1\n", "pkg/widget_test.py")]
    assert _analyse(units) == []


def test_quoted_dotted_annotation_reference_counts_as_use():
    """Count a quoted, dotted return annotation as a use of the class it names."""
    # A class referenced only through a quoted *dotted* forward ref
    # (`-> "pkg.models.Payload"`) must not be flagged - annotations count as use.
    units = [
        _unit("class Payload:\n    pass\n", "pkg/models.py"),
        _unit(
            "from typing import TYPE_CHECKING\n\n"
            "if TYPE_CHECKING:\n"
            "    import pkg.models\n\n"
            'def build(raw) -> "pkg.models.Payload":\n'
            "    return raw\n\n"
            "value = build({})\n",
            "pkg/api.py",
        ),
    ]
    findings = _analyse(units)
    assert [finding.symbol for finding in findings] == []


def test_definition_is_advisory_medium_confidence_dead_code():
    """Define the rule as an advisory, medium-confidence dead-code rule, off by default with no entry-point patterns."""
    definition = ExportedButUnreferencedRule().definition()
    assert definition.default_severity.value == "advisory"
    assert definition.confidence.value == "medium"
    assert definition.pillar.value == "dead-code"
    assert definition.default_enabled is False
    assert definition.default_options == {"entryPointPatterns": []}


def test_quoted_annotation_reference_counts_as_use():
    """Count a quoted return annotation as a use of the class it names."""
    # A public class referenced only through a quoted (forward-ref) annotation
    # under TYPE_CHECKING must not be flagged - the rule's contract says
    # annotations count as use.
    units = [
        _unit("class Payload:\n    pass\n", "pkg/models.py"),
        _unit(
            "from typing import TYPE_CHECKING\n\n"
            "if TYPE_CHECKING:\n"
            "    from pkg.models import Payload\n\n"
            'def build(raw) -> "Payload":\n'
            "    return raw\n\n"
            "value = build({})\n",
            "pkg/api.py",
        ),
    ]
    findings = _analyse(units)
    assert [finding.symbol for finding in findings] == []


def test_quoted_annotation_inside_subscript_counts_as_use():
    """Count a quoted name inside a subscripted return annotation as a use."""
    # The forward reference can be nested inside an otherwise-unquoted generic.
    units = [
        _unit("class Record:\n    pass\n", "pkg/models.py"),
        _unit(
            "from typing import TYPE_CHECKING\n\n"
            "if TYPE_CHECKING:\n"
            "    from pkg.models import Record\n\n"
            'def collect(raw) -> list["Record"]:\n'
            "    return raw\n\n"
            "rows = collect([])\n",
            "pkg/api.py",
        ),
    ]
    findings = _analyse(units)
    assert [finding.symbol for finding in findings] == []
