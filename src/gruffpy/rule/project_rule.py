"""Protocol for rules that examine the whole project rather than one unit at a time."""

from typing import Protocol, runtime_checkable

from gruffpy.finding.finding import Finding
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition


@runtime_checkable
class ProjectRuleProtocol(Protocol):
    def definition(self) -> RuleDefinition: ...

    def analyse_project(
        self,
        units: list[AnalysisUnit],
        context: RuleContext,
    ) -> list[Finding]: ...
