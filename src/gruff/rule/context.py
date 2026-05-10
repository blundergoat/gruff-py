from dataclasses import dataclass

from gruff.config.analysis_config import AnalysisConfig
from gruff.config.rule_settings import RuleSettings
from gruff.rule.definition import RuleDefinition


@dataclass(frozen=True, slots=True)
class RuleContext:
    project_root: str
    config: AnalysisConfig

    def settings_for(self, definition: RuleDefinition) -> RuleSettings:
        return self.config.rule_settings(definition.id)
