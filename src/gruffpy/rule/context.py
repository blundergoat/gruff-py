"""Per-run context passed to every rule (project root + resolved config)."""

from dataclasses import dataclass

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.rule.definition import RuleDefinition


@dataclass(frozen=True, slots=True)
class RuleContext:
    """Read-only context handed to every rule's ``analyse()`` call.

    Carries the project root (for resolving ``pyproject.toml`` / paths)
    and the resolved ``AnalysisConfig`` so rules can look up their own
    settings via ``settings_for()``.
    """

    project_root: str
    config: AnalysisConfig

    def settings_for(self, definition: RuleDefinition) -> RuleSettings:
        """Return the per-rule settings for *definition*'s id.

        Convenience indirection so rules can call ``context.settings_for(self.definition())``
        without reaching into the config dict themselves.

        Args:
            definition: The rule's definition record.

        Returns:
            Resolved ``RuleSettings`` (thresholds, options, enabled flag).
        """
        return self.config.rule_settings(definition.id)
