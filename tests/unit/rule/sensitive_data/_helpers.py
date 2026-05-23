"""Shared test helpers for sensitive-data rule tests.

Builds text-typed AnalysisUnit fixtures so the SourceTextRule subclasses
operate on ``unit.source`` (the tree is None, as the registry expects).
"""

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
    """Build a text-typed ``AnalysisUnit`` (``tree=None``) for ``SourceTextRule`` tests.

    Sensitive-data rules subclass :class:`SourceTextRule` and operate on
    ``unit.source`` directly - they never need the AST, so leaving the tree
    unset matches what the registry hands them at runtime.

    Args:
        source: Raw file text to scan.
        display_path: Display path stored on the unit; some rules gate on
            this (e.g. ``.env``-file detection).
        source_type: ``"python"`` or ``"text"``; controls
            ``SourceFile.is_python``.

    Returns:
        Unit with a populated ``source`` and ``tree=None``.
    """
    file = SourceFile(absolute_path=f"/{display_path}", display_path=display_path, type=source_type)
    return AnalysisUnit(file=file, source=source, tree=None)


def default_ctx() -> RuleContext:
    """Build a ``RuleContext`` seeded with every built-in rule at its default settings.

    Used by sensitive-data tests that don't need custom thresholds or
    options.

    Returns:
        Default ``RuleContext`` for the sensitive-data pillar.
    """
    config = AnalysisConfig.from_registry(RuleRegistry.defaults())
    return RuleContext(project_root="/tmp/no-such-root", config=config)
