"""Abstract base class every per-file rule implements."""

import abc

from gruff.finding.finding import Finding
from gruff.parser.analysis_unit import AnalysisUnit
from gruff.rule.context import RuleContext
from gruff.rule.definition import RuleDefinition


class Rule(abc.ABC):
    @abc.abstractmethod
    def definition(self) -> RuleDefinition: ...

    @abc.abstractmethod
    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]: ...


class SourceTextRule(Rule):
    """Marker base class for rules that should also run on non-Python text files
    (e.g. .env, JSON, TOML, YAML). Default rules only run on Python sources."""
