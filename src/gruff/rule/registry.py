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
        from gruff.rule.complexity.cognitive_complexity_rule import CognitiveComplexityRule
        from gruff.rule.complexity.cyclomatic_complexity_rule import CyclomaticComplexityRule
        from gruff.rule.complexity.halstead_volume_rule import HalsteadVolumeRule
        from gruff.rule.complexity.maintainability_index_rule import MaintainabilityIndexRule
        from gruff.rule.complexity.nesting_depth_rule import NestingDepthRule
        from gruff.rule.complexity.npath_complexity_rule import NPathComplexityRule
        from gruff.rule.dead_code.unused_private_attribute_rule import (
            UnusedPrivateAttributeRule,
        )
        from gruff.rule.dead_code.unused_private_function_rule import (
            UnusedPrivateFunctionRule,
        )
        from gruff.rule.size.attribute_count_rule import AttributeCountRule
        from gruff.rule.size.average_function_length_rule import AverageFunctionLengthRule
        from gruff.rule.size.class_length_rule import ClassLengthRule
        from gruff.rule.size.file_length_rule import FileLengthRule
        from gruff.rule.size.function_length_rule import FunctionLengthRule
        from gruff.rule.size.parameter_count_rule import ParameterCountRule
        from gruff.rule.size.public_method_count_rule import PublicMethodCountRule
        from gruff.rule.waste.commented_out_code_rule import CommentedOutCodeRule
        from gruff.rule.waste.empty_class_rule import EmptyClassRule
        from gruff.rule.waste.empty_function_rule import EmptyFunctionRule
        from gruff.rule.waste.one_line_function_rule import OneLineFunctionRule
        from gruff.rule.waste.redundant_variable_rule import RedundantVariableRule
        from gruff.rule.waste.unreachable_code_rule import UnreachableCodeRule
        from gruff.rule.waste.unused_import_rule import UnusedImportRule
        from gruff.rule.waste.unused_parameter_rule import UnusedParameterRule

        return cls(
            [
                # Complexity pillar (M03)
                CognitiveComplexityRule(),
                CyclomaticComplexityRule(),
                HalsteadVolumeRule(),
                MaintainabilityIndexRule(),
                NestingDepthRule(),
                NPathComplexityRule(),
                # Dead-code pillar (M04)
                UnusedPrivateAttributeRule(),
                UnusedPrivateFunctionRule(),
                # Size pillar (M02)
                AttributeCountRule(),
                AverageFunctionLengthRule(),
                ClassLengthRule(),
                FileLengthRule(),
                FunctionLengthRule(),
                ParameterCountRule(),
                PublicMethodCountRule(),
                # Waste pillar (M04)
                CommentedOutCodeRule(),
                EmptyClassRule(),
                EmptyFunctionRule(),
                OneLineFunctionRule(),
                RedundantVariableRule(),
                UnreachableCodeRule(),
                UnusedImportRule(),
                UnusedParameterRule(),
            ]
        )

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
