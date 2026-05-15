from typing import Protocol, runtime_checkable

from gruff.finding.finding import Finding
from gruff.parser.analysis_unit import AnalysisUnit
from gruff.rule.context import RuleContext
from gruff.rule.definition import RuleDefinition


@runtime_checkable
class ProjectRuleProtocol(Protocol):
    def definition(self) -> RuleDefinition: ...

    def analyse_project(
        self,
        units: list[AnalysisUnit],
        context: RuleContext,
    ) -> list[Finding]: ...
