"""Shared test helpers for security-pillar rule tests."""

import ast
from dataclasses import replace

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.registry import RuleRegistry
from gruffpy.source.source_file import SourceFile


def make_unit(source: str, display_path: str = "x.py") -> AnalysisUnit:
    """Parse source into an AnalysisUnit with parent links for security rules that inspect enclosing nodes.

    Args:
        source: Python source to parse.
        display_path: File path stored on the unit (some rules gate on the path).

    Returns:
        Ready-to-analyse unit pointing at an in-memory SourceFile.
    """
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]  # The fixture adds parent metadata outside the standard AST fields.
    file = SourceFile(absolute_path=f"/{display_path}", display_path=display_path, type="python")
    return AnalysisUnit(file=file, source=source, tree=tree)


def make_text_unit(source: str, display_path: str) -> AnalysisUnit:
    """Build a text-typed AnalysisUnit with no tree for SourceTextRule tests.

    GitHub Actions and dependency-posture rules scan raw text, so their tests need a text-typed unit without a Python AST.

    Args:
        source: Raw file text to scan.
        display_path: Path stored on the unit (text rules gate on it).

    Returns:
        A text-typed unit pointing at an in-memory SourceFile.
    """
    file = SourceFile(absolute_path=f"/{display_path}", display_path=display_path, type="text")
    return AnalysisUnit(file=file, source=source, tree=None)


def default_ctx() -> RuleContext:
    """Build a RuleContext seeded with every built-in rule at its default settings.

    Used by security-pillar tests that don't need custom thresholds or options.

    Returns:
        Context with built-in rule defaults and a placeholder root for tests without a project directory.
    """
    config = AnalysisConfig.from_registry(RuleRegistry.defaults())
    return RuleContext(project_root="/tmp/no-such-root", config=config)


def ctx_enabling(*rule_ids: str) -> RuleContext:
    """Build the default RuleContext with the named rules switched on, as a project that enables them would.

    Used for rules that ship off by default, so their detection stays tested.

    Args:
        rule_ids: Ids of built-in rules to enable; an empty call gives the default context.

    Returns:
        Context with the named rules enabled and a placeholder root for tests without a project directory.
    """
    config = AnalysisConfig.from_registry(RuleRegistry.defaults())
    for rule_id in rule_ids:
        config = config.with_rule_settings(rule_id, replace(config.rule_settings(rule_id), enabled=True))
    return RuleContext(project_root="/tmp/no-such-root", config=config)
