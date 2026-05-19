"""Shared test helpers for test-quality rule tests."""

import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.registry import RuleRegistry
from gruffpy.source.source_file import SourceFile


def make_unit(source: str, display_path: str = "test_x.py") -> AnalysisUnit:
    """Parse *source* into an ``AnalysisUnit`` with ``.parent`` links attached.

    Default ``display_path`` starts with ``test_`` so the test-quality
    rules' test-file detection (path or filename heuristic) picks the
    fixture up by default.

    Args:
        source: Python test-file source to parse.
        display_path: Display path (must start with ``test_`` or be under
            ``tests/`` for rules that gate on test files).

    Returns:
        Ready-to-analyse unit pointing at an in-memory ``SourceFile``.
    """
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]
    file = SourceFile(absolute_path=f"/{display_path}", display_path=display_path, type="python")
    return AnalysisUnit(file=file, source=source, tree=tree)


def default_ctx() -> RuleContext:
    """Build a ``RuleContext`` seeded with every built-in rule at its default settings.

    Used by test-quality tests that don't need custom thresholds or
    options.

    Returns:
        Default ``RuleContext`` for the test-quality pillar.
    """
    config = AnalysisConfig.from_registry(RuleRegistry.defaults())
    return RuleContext(project_root="/tmp/no-such-root", config=config)
