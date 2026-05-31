"""Shared test helpers for security-pillar rule tests."""

import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.registry import RuleRegistry
from gruffpy.source.source_file import SourceFile


def make_unit(source: str, display_path: str = "x.py") -> AnalysisUnit:
    """Parse *source* into an ``AnalysisUnit`` with ``.parent`` links attached.

    Several security rules walk up the AST via ``getattr(node, "parent", ...)``
    (e.g. to find the enclosing assignment or function). ``ast.parse``
    doesn't populate ``parent`` by default; this helper does.

    Args:
        source: Python source to parse.
        display_path: File path stored on the unit (some rules gate on the path).

    Returns:
        Ready-to-analyse unit pointing at an in-memory ``SourceFile``.
    """
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]  # AST parent links
    file = SourceFile(absolute_path=f"/{display_path}", display_path=display_path, type="python")
    return AnalysisUnit(file=file, source=source, tree=tree)


def make_text_unit(source: str, display_path: str) -> AnalysisUnit:
    """Build a text-typed ``AnalysisUnit`` (``tree=None``) for ``SourceTextRule`` tests.

    GitHub Actions and dependency-posture rules scan raw file text rather than a
    Python AST, so their tests need a unit with ``type="text"`` and no tree.

    Args:
        source: Raw file text to scan.
        display_path: Path stored on the unit (text rules gate on it).

    Returns:
        A text-typed unit pointing at an in-memory ``SourceFile``.
    """
    file = SourceFile(absolute_path=f"/{display_path}", display_path=display_path, type="text")
    return AnalysisUnit(file=file, source=source, tree=None)


def default_ctx() -> RuleContext:
    """Build a ``RuleContext`` seeded with every built-in rule at its default settings.

    Used by security-pillar tests that don't need custom thresholds or
    options.

    Returns:
        Default ``RuleContext`` for the security pillar.
    """
    config = AnalysisConfig.from_registry(RuleRegistry.defaults())
    return RuleContext(project_root="/tmp/no-such-root", config=config)
