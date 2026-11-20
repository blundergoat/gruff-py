"""Shared test helpers for the documentation pillar.

Builds AnalysisUnit / RuleContext fixtures without re-implementing the parent
attachment dance in every rule test.
"""

import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.registry import RuleRegistry
from gruffpy.source.source_file import SourceFile


def make_unit(source: str, display_path: str = "x.py") -> AnalysisUnit:
    """Parse source into an AnalysisUnit with parent links so docs rules can traverse enclosing nodes.

    Args:
        source: Python source to parse.
        display_path: File path stored on the unit (controls test-file detection).

    Returns:
        Ready-to-analyse unit pointing at an in-memory SourceFile.
    """
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]  # ast.AST omits the parent attribute needed by rule traversal.
    file = SourceFile(absolute_path=f"/{display_path}", display_path=display_path, type="python")
    return AnalysisUnit(file=file, source=source, tree=tree)


def default_ctx(project_root: str = "/tmp/no-such-root") -> RuleContext:
    """Build a RuleContext seeded with every built-in rule at its default settings.

    Used by docs-pillar tests that don't need to override thresholds or options.

    Args:
        project_root: Root where the missing README rule looks for a README. If omitted, it searches a placeholder root intended to contain no README.

    Returns:
        Default RuleContext for the docs pillar.
    """
    config = AnalysisConfig.from_registry(RuleRegistry.defaults())
    return RuleContext(project_root=project_root, config=config)


def every_callable_ctx(rule_id: str, *, enabled: bool = True) -> RuleContext:
    """Build a RuleContext that sets one docs rule's everyCallable option explicitly.

    Args:
        rule_id: Rule whose callable scope the test exercises.
        enabled: Value written for the option; false pins the public-only scope.

    Returns:
        Context whose settings for rule_id carry everyCallable set to enabled.
    """
    return RuleContext(project_root="/", config=AnalysisConfig(rules={rule_id: RuleSettings(options={"everyCallable": enabled})}))
