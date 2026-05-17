"""Indexed catalogue of every built-in rule, keyed by rule id."""

import json
from collections.abc import Iterable

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.finding.finding import Finding
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.project_rule import ProjectRuleProtocol
from gruffpy.rule.rule import Rule, SourceTextRule

RuleLike = Rule | ProjectRuleProtocol


class RuleRegistry:
    def __init__(self, rule_like_items: Iterable[RuleLike]) -> None:
        indexed: dict[str, RuleLike] = {}
        for rule in rule_like_items:
            rule_id = rule.definition().id
            if rule_id in indexed:
                raise ValueError(f'Duplicate rule id "{rule_id}".')
            indexed[rule_id] = rule
        self._rules: dict[str, RuleLike] = dict(sorted(indexed.items()))

    @classmethod
    def defaults(cls) -> "RuleRegistry":
        from gruffpy.rule.builtins import default_rules

        return cls(default_rules())

    def all(self) -> list[RuleLike]:
        return list(self._rules.values())

    def has(self, rule_id: str) -> bool:
        return rule_id in self._rules

    def get(self, rule_id: str) -> RuleLike:
        if rule_id not in self._rules:
            raise KeyError(f'Unknown rule id "{rule_id}".')
        return self._rules[rule_id]

    def enabled_rules(self, config: AnalysisConfig) -> list[RuleLike]:
        result: list[RuleLike] = []
        for rule in self._rules.values():
            definition = rule.definition()
            settings = config.rule_settings(definition.id)
            if settings.enabled and config.rule_selection.is_allowed(definition):
                result.append(rule)
        return result

    def analyse(self, units: list[AnalysisUnit], context: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        enabled = self.enabled_rules(context.config)
        project_units = [
            unit
            for unit in units
            if not unit.has_parse_errors() and unit.file.is_python() and unit.tree is not None
        ]

        for unit in units:
            if unit.has_parse_errors():
                continue
            is_python = unit.file.is_python()
            for rule in enabled:
                if isinstance(rule, ProjectRuleProtocol):
                    continue
                if not is_python and not isinstance(rule, SourceTextRule):
                    continue
                findings.extend(rule.analyse(unit, context))

        for rule in enabled:
            if isinstance(rule, ProjectRuleProtocol):
                findings.extend(rule.analyse_project(project_units, context))

        findings = self._deduplicate(findings)
        findings.sort(
            key=lambda f: (f.file_path, f.line if f.line is not None else 0, f.rule_id, f.message)
        )
        return findings

    @staticmethod
    def _deduplicate(findings: list[Finding]) -> list[Finding]:
        seen: set[tuple[str, ...]] = set()
        result: list[Finding] = []
        for finding in findings:
            key = (
                finding.rule_id,
                finding.file_path,
                str(finding.line) if finding.line is not None else "",
                str(finding.end_line) if finding.end_line is not None else "",
                str(finding.column) if finding.column is not None else "",
                finding.symbol or "",
                finding.message,
                json.dumps(finding.metadata, sort_keys=True),
            )
            if key in seen:
                continue
            seen.add(key)
            result.append(finding)
        return result
