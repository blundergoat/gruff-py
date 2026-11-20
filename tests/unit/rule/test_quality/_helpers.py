"""Shared test helpers for test-quality rule tests."""

import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.registry import RuleRegistry
from gruffpy.source.source_file import SourceFile


def make_unit(source: str, display_path: str = "test_x.py") -> AnalysisUnit:
    """Parse test source into an AnalysisUnit with parent links for rules that inspect enclosing scopes.

    The default display path lets test-quality rules recognise the fixture as a test file.

    Args:
        source: Python test-file source to parse.
        display_path: Path that rules inspect to classify the fixture. Use a path such as src/main.py to exercise non-test file filtering.

    Returns:
        Ready-to-analyse unit pointing at an in-memory SourceFile.
    """
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]  # AST nodes lack a declared parent attribute; rules need enclosing scopes.
    file = SourceFile(absolute_path=f"/{display_path}", display_path=display_path, type="python")
    return AnalysisUnit(file=file, source=source, tree=tree)


def default_ctx() -> RuleContext:
    """Build a RuleContext seeded with every built-in rule at its default settings.

    Used by test-quality tests that don't need custom thresholds or options.

    Returns:
        Context with built-in rule defaults and a placeholder project root for tests that do not need on-disk project settings.
    """
    config = AnalysisConfig.from_registry(RuleRegistry.defaults())
    return RuleContext(project_root="/tmp/no-such-root", config=config)
