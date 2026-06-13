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

    Attributes:
        project_root: Absolute project root used to resolve
            ``pyproject.toml`` and display paths.
        config: Resolved analysis configuration for the run; rules read
            their own settings from it via :meth:`settings_for`.
        scan_scope: The runner's run classification
            (``"full-project"`` / ``"partial-scope"``) so scope-sensitive
            project rules can suppress themselves on partial context
            (ADR-025); the default is the suppressed-safe value for any
            constructor that does not thread it.
    """

    project_root: str
    config: AnalysisConfig
    scan_scope: str = "partial-scope"

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
