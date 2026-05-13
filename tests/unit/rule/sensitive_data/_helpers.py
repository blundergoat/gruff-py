"""Shared test helpers for sensitive-data rule tests.

Builds text-typed AnalysisUnit fixtures so the SourceTextRule subclasses
operate on ``unit.source`` (the tree is None, as the registry expects).
"""

from gruff.config.analysis_config import AnalysisConfig
from gruff.parser.analysis_unit import AnalysisUnit
from gruff.rule.context import RuleContext
from gruff.rule.registry import RuleRegistry
from gruff.source.source_file import SourceFile, SourceFileType


def make_unit(
    source: str,
    display_path: str = "x.py",
    source_type: SourceFileType = "python",
) -> AnalysisUnit:
    file = SourceFile(absolute_path=f"/{display_path}", display_path=display_path, type=source_type)
    return AnalysisUnit(file=file, source=source, tree=None)


def default_ctx() -> RuleContext:
    config = AnalysisConfig.from_registry(RuleRegistry.defaults())
    return RuleContext(project_root="/tmp/no-such-root", config=config)
