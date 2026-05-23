"""Shared test helpers for the documentation pillar.

Builds AnalysisUnit / RuleContext fixtures without re-implementing the parent
attachment dance in every rule test.
"""

import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.registry import RuleRegistry
from gruffpy.source.source_file import SourceFile


def make_unit(source: str, display_path: str = "x.py") -> AnalysisUnit:
    """Parse *source* into an ``AnalysisUnit`` with ``.parent`` links attached.

    Several docs rules walk back up the AST via ``getattr(node, "parent", ...)``;
    this helper attaches the parent reference that ``ast.parse`` does not
    populate by default so test fixtures behave like the real parser.

    Args:
        source: Python source to parse.
        display_path: File path stored on the unit (controls test-file detection).

    Returns:
        Ready-to-analyse unit pointing at an in-memory ``SourceFile``.
    """
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]  # AST parent links
    file = SourceFile(absolute_path=f"/{display_path}", display_path=display_path, type="python")
    return AnalysisUnit(file=file, source=source, tree=tree)


def default_ctx(project_root: str = "/tmp/no-such-root") -> RuleContext:
    """Build a ``RuleContext`` seeded with every built-in rule at its default settings.

    Used by docs-pillar tests that don't need to override thresholds or
    options - they just want a working context.

    Args:
        project_root: Project root recorded on the context (rarely matters
            for docs-rule tests, but some rules use it for path display).

    Returns:
        Default ``RuleContext`` for the docs pillar.
    """
    config = AnalysisConfig.from_registry(RuleRegistry.defaults())
    return RuleContext(project_root=project_root, config=config)
