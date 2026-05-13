"""Shared test helpers for the documentation pillar.

Builds AnalysisUnit / RuleContext fixtures without re-implementing the parent
attachment dance in every rule test.
"""

import ast

from gruff.config.analysis_config import AnalysisConfig
from gruff.parser.analysis_unit import AnalysisUnit
from gruff.rule.context import RuleContext
from gruff.rule.registry import RuleRegistry
from gruff.source.source_file import SourceFile


def make_unit(source: str, display_path: str = "x.py") -> AnalysisUnit:
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]
    file = SourceFile(absolute_path=f"/{display_path}", display_path=display_path, type="python")
    return AnalysisUnit(file=file, source=source, tree=tree)


def default_ctx(project_root: str = "/tmp/no-such-root") -> RuleContext:
    config = AnalysisConfig.from_registry(RuleRegistry.defaults())
    return RuleContext(project_root=project_root, config=config)
