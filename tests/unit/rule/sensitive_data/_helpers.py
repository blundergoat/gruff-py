"""Shared test helpers for sensitive-data rule tests.

Builds text-typed AnalysisUnit fixtures so the SourceTextRule subclasses
operate on ``unit.source`` (the tree is None, as the registry expects).
"""

from dataclasses import replace

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.registry import RuleRegistry
from gruffpy.source.source_file import SourceFile, SourceFileType


def make_unit(
    source: str,
    display_path: str = "x.py",
    source_type: SourceFileType = "python",
) -> AnalysisUnit:
    """Build an AnalysisUnit without an AST for source-text rule tests.

    Args:
        source: Raw file text to scan.
        display_path: Path shown in findings; rules also use it to recognize files such as .env.
        source_type: "python" or "text"; determines whether the file is eligible for Python-only rules.

    Returns:
        Unit with the supplied source and file metadata; tree=None avoids constructing an AST for these tests.
    """
    file = SourceFile(absolute_path=f"/{display_path}", display_path=display_path, type=source_type)
    return AnalysisUnit(file=file, source=source, tree=None)


def default_ctx() -> RuleContext:
    """Build a RuleContext seeded with every built-in rule at its default settings.

    Used by sensitive-data tests that don't need custom thresholds or
    options.

    Returns:
        Default RuleContext for the sensitive-data pillar.
    """
    config = AnalysisConfig.from_registry(RuleRegistry.defaults())
    return RuleContext(project_root="/tmp/no-such-root", config=config)


def ctx_enabling(*rule_ids: str) -> RuleContext:
    """Build the default RuleContext with the named rules switched on, as a project that enables them would.

    Used for rules that ship off by default, so their detection stays tested.

    Args:
        rule_ids: Ids of built-in rules to enable; an empty call gives the default context.

    Returns:
        Default RuleContext with every named rule enabled.
    """
    config = AnalysisConfig.from_registry(RuleRegistry.defaults())
    # Each named rule keeps its default thresholds and options; only enabled changes.
    for rule_id in rule_ids:
        config = config.with_rule_settings(rule_id, replace(config.rule_settings(rule_id), enabled=True))
    return RuleContext(project_root="/tmp/no-such-root", config=config)
