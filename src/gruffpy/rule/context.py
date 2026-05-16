"""Per-run context passed to every rule (project root + resolved config)."""

from dataclasses import dataclass

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.rule.definition import RuleDefinition


@dataclass(frozen=True, slots=True)
class RuleContext:
    project_root: str
    config: AnalysisConfig

    def settings_for(self, definition: RuleDefinition) -> RuleSettings:
        return self.config.rule_settings(definition.id)
