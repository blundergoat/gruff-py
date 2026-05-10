import json
from collections.abc import Iterable

from gruff.config.analysis_config import AnalysisConfig
from gruff.finding.finding import Finding
from gruff.parser.analysis_unit import AnalysisUnit
from gruff.rule.context import RuleContext
from gruff.rule.rule import Rule, SourceTextRule


class RuleRegistry:
    def __init__(self, rules: Iterable[Rule]) -> None:
        indexed: dict[str, Rule] = {}
        for rule in rules:
            rule_id = rule.definition().id
            if rule_id in indexed:
                raise ValueError(f'Duplicate rule id "{rule_id}".')
            indexed[rule_id] = rule
        self._rules: dict[str, Rule] = dict(sorted(indexed.items()))

    @classmethod
    def defaults(cls) -> "RuleRegistry":
        from gruff.rule.size.file_length_rule import FileLengthRule

        return cls([FileLengthRule()])

    def all(self) -> list[Rule]:
        return list(self._rules.values())

    def has(self, rule_id: str) -> bool:
        return rule_id in self._rules

    def get(self, rule_id: str) -> Rule:
        if rule_id not in self._rules:
            raise KeyError(f'Unknown rule id "{rule_id}".')
        return self._rules[rule_id]

    def enabled_rules(self, config: AnalysisConfig) -> list[Rule]:
        result: list[Rule] = []
        for rule in self._rules.values():
            definition = rule.definition()
            settings = config.rule_settings(definition.id)
            if settings.enabled and config.rule_selection.allows(definition):
                result.append(rule)
        return result

    def analyse(self, units: list[AnalysisUnit], context: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        enabled = self.enabled_rules(context.config)

        for unit in units:
            if unit.has_parse_errors():
                continue
            is_python = unit.file.is_python()
            for rule in enabled:
                if not is_python and not isinstance(rule, SourceTextRule):
                    continue
                findings.extend(rule.analyse(unit, context))

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
