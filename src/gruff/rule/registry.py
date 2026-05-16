"""Indexed catalogue of every built-in rule, keyed by rule id."""

import json
from collections.abc import Iterable

from gruff.config.analysis_config import AnalysisConfig
from gruff.finding.finding import Finding
from gruff.parser.analysis_unit import AnalysisUnit
from gruff.rule.context import RuleContext
from gruff.rule.project_rule import ProjectRuleProtocol
from gruff.rule.rule import Rule, SourceTextRule

RuleLike = Rule | ProjectRuleProtocol


class RuleRegistry:
    def __init__(self, rules: Iterable[RuleLike]) -> None:
        indexed: dict[str, RuleLike] = {}
        for rule in rules:
            rule_id = rule.definition().id
            if rule_id in indexed:
                raise ValueError(f'Duplicate rule id "{rule_id}".')
            indexed[rule_id] = rule
        self._rules: dict[str, RuleLike] = dict(sorted(indexed.items()))

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
        from gruff.rule.design.single_implementor_protocol_rule import (
            SingleImplementorProtocolRule,
        )
        from gruff.rule.docs.missing_class_docstring_rule import MissingClassDocstringRule
        from gruff.rule.docs.missing_function_docstring_rule import MissingFunctionDocstringRule
        from gruff.rule.docs.missing_module_docstring_rule import MissingModuleDocstringRule
        from gruff.rule.docs.missing_param_doc_rule import MissingParamDocRule
        from gruff.rule.docs.missing_raises_doc_rule import MissingRaisesDocRule
        from gruff.rule.docs.missing_readme_rule import MissingReadmeRule
        from gruff.rule.docs.missing_return_doc_rule import MissingReturnDocRule
        from gruff.rule.docs.stale_param_doc_rule import StaleParamDocRule
        from gruff.rule.docs.todo_density_rule import TodoDensityRule
        from gruff.rule.docs.useless_docstring_rule import UselessDocstringRule
        from gruff.rule.naming.boolean_prefix_rule import BooleanPrefixRule
        from gruff.rule.naming.confusing_name_rule import ConfusingNameRule
        from gruff.rule.naming.generic_function_rule import GenericFunctionRule
        from gruff.rule.naming.hungarian_notation_rule import HungarianNotationRule
        from gruff.rule.naming.identifier_quality_rule import IdentifierQualityRule
        from gruff.rule.naming.module_name_mismatch_rule import ModuleNameMismatchRule
        from gruff.rule.naming.parameter_type_name_rule import ParameterTypeNameRule
        from gruff.rule.naming.short_variable_rule import ShortVariableRule
        from gruff.rule.naming.test_naming_consistency_rule import (
            TestNamingConsistencyRule,
        )
        from gruff.rule.security.dangerous_function_call_rule import DangerousFunctionCallRule
        from gruff.rule.security.disabled_ssl_verification_rule import (
            DisabledSslVerificationRule,
        )
        from gruff.rule.security.error_suppression_rule import ErrorSuppressionRule
        from gruff.rule.security.extract_compact_user_input_rule import (
            ExtractCompactUserInputRule,
        )
        from gruff.rule.security.header_injection_rule import HeaderInjectionRule
        from gruff.rule.security.insecure_random_rule import InsecureRandomRule
        from gruff.rule.security.shell_injection_rule import ShellInjectionRule
        from gruff.rule.security.silent_except_rule import SilentExceptRule
        from gruff.rule.security.sql_concatenation_rule import SqlConcatenationRule
        from gruff.rule.security.unsafe_pickle_rule import UnsafePickleRule
        from gruff.rule.security.variable_import_rule import VariableImportRule
        from gruff.rule.security.weak_crypto_rule import WeakCryptoRule
        from gruff.rule.sensitive_data.api_key_pattern_rule import ApiKeyPatternRule
        from gruff.rule.sensitive_data.aws_access_key_rule import AwsAccessKeyRule
        from gruff.rule.sensitive_data.database_url_password_rule import (
            DatabaseUrlPasswordRule,
        )
        from gruff.rule.sensitive_data.hardcoded_env_value_rule import HardcodedEnvValueRule
        from gruff.rule.sensitive_data.high_entropy_string_rule import HighEntropyStringRule
        from gruff.rule.sensitive_data.jwt_token_rule import JwtTokenRule
        from gruff.rule.sensitive_data.phi_pattern_rule import PhiPatternRule
        from gruff.rule.sensitive_data.pii_test_fixture_rule import PiiTestFixtureRule
        from gruff.rule.sensitive_data.private_key_rule import PrivateKeyRule
        from gruff.rule.size.attribute_count_rule import AttributeCountRule
        from gruff.rule.size.average_function_length_rule import AverageFunctionLengthRule
        from gruff.rule.size.class_length_rule import ClassLengthRule
        from gruff.rule.size.file_length_rule import FileLengthRule
        from gruff.rule.size.function_length_rule import FunctionLengthRule
        from gruff.rule.size.parameter_count_rule import ParameterCountRule
        from gruff.rule.size.public_method_count_rule import PublicMethodCountRule
        from gruff.rule.test_quality.conditional_logic_rule import ConditionalLogicRule
        from gruff.rule.test_quality.eager_test_rule import EagerTestRule
        from gruff.rule.test_quality.empty_parametrize_rule import EmptyParametrizeRule
        from gruff.rule.test_quality.exception_type_only_rule import ExceptionTypeOnlyRule
        from gruff.rule.test_quality.excessive_mocking_rule import ExcessiveMockingRule
        from gruff.rule.test_quality.extends_production_class_rule import (
            ExtendsProductionClassRule,
        )
        from gruff.rule.test_quality.global_state_mutation_rule import GlobalStateMutationRule
        from gruff.rule.test_quality.loop_assertion_without_message_rule import (
            LoopAssertionWithoutMessageRule,
        )
        from gruff.rule.test_quality.loop_in_test_rule import LoopInTestRule
        from gruff.rule.test_quality.magic_number_assertion_rule import (
            MagicNumberAssertionRule,
        )
        from gruff.rule.test_quality.mock_only_test_rule import MockOnlyTestRule
        from gruff.rule.test_quality.mock_without_expectation_rule import (
            MockWithoutExpectationRule,
        )
        from gruff.rule.test_quality.mocking_domain_object_rule import MockingDomainObjectRule
        from gruff.rule.test_quality.multiple_aaa_cycles_rule import MultipleAaaCyclesRule
        from gruff.rule.test_quality.mystery_guest_rule import MysteryGuestRule
        from gruff.rule.test_quality.naming_consistency_rule import NamingConsistencyRule
        from gruff.rule.test_quality.no_assertions_rule import NoAssertionsRule
        from gruff.rule.test_quality.parametrize_annotation_rule import (
            ParametrizeAnnotationRule,
        )
        from gruff.rule.test_quality.private_reflection_rule import PrivateReflectionRule
        from gruff.rule.test_quality.pytest_coverage_source_missing_rule import (
            PytestCoverageSourceMissingRule,
        )
        from gruff.rule.test_quality.pytest_deprecations_not_fatal_rule import (
            PytestDeprecationsNotFatalRule,
        )
        from gruff.rule.test_quality.pytest_strict_config_missing_rule import (
            PytestStrictConfigMissingRule,
        )
        from gruff.rule.test_quality.repeated_structure_missing_parametrize_rule import (
            RepeatedStructureMissingParametrizeRule,
        )
        from gruff.rule.test_quality.setup_bloat_rule import SetupBloatRule
        from gruff.rule.test_quality.skipped_without_reason_rule import (
            SkippedWithoutReasonRule,
        )
        from gruff.rule.test_quality.sleep_in_test_rule import SleepInTestRule
        from gruff.rule.test_quality.sut_not_called_rule import SutNotCalledRule
        from gruff.rule.test_quality.tautological_type_assertion_rule import (
            TautologicalTypeAssertionRule,
        )
        from gruff.rule.test_quality.test_function_too_long_rule import (
            TestFunctionTooLongRule,
        )
        from gruff.rule.test_quality.test_longer_than_sut_rule import TestLongerThanSutRule
        from gruff.rule.test_quality.testdox_readability_rule import TestdoxReadabilityRule
        from gruff.rule.test_quality.trivial_assertion_rule import TrivialAssertionRule
        from gruff.rule.test_quality.trivial_snapshot_rule import TrivialSnapshotRule
        from gruff.rule.test_quality.unused_mock_rule import UnusedMockRule
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
                # Complexity pillar
                CognitiveComplexityRule(),
                CyclomaticComplexityRule(),
                HalsteadVolumeRule(),
                MaintainabilityIndexRule(),
                NestingDepthRule(),
                NPathComplexityRule(),
                # Dead-code pillar
                UnusedPrivateAttributeRule(),
                UnusedPrivateFunctionRule(),
                # Design project rules
                SingleImplementorProtocolRule(),
                # Documentation pillar
                MissingClassDocstringRule(),
                MissingFunctionDocstringRule(),
                MissingModuleDocstringRule(),
                MissingParamDocRule(),
                MissingRaisesDocRule(),
                MissingReadmeRule(),
                MissingReturnDocRule(),
                StaleParamDocRule(),
                TodoDensityRule(),
                UselessDocstringRule(),
                # Naming pillar
                BooleanPrefixRule(),
                ConfusingNameRule(),
                GenericFunctionRule(),
                HungarianNotationRule(),
                IdentifierQualityRule(),
                ModuleNameMismatchRule(),
                ParameterTypeNameRule(),
                ShortVariableRule(),
                TestNamingConsistencyRule(),
                # Security pillar
                DangerousFunctionCallRule(),
                DisabledSslVerificationRule(),
                ErrorSuppressionRule(),
                ExtractCompactUserInputRule(),
                HeaderInjectionRule(),
                InsecureRandomRule(),
                ShellInjectionRule(),
                SilentExceptRule(),
                SqlConcatenationRule(),
                UnsafePickleRule(),
                VariableImportRule(),
                WeakCryptoRule(),
                # Sensitive-data pillar
                ApiKeyPatternRule(),
                AwsAccessKeyRule(),
                DatabaseUrlPasswordRule(),
                HardcodedEnvValueRule(),
                HighEntropyStringRule(),
                JwtTokenRule(),
                PhiPatternRule(),
                PiiTestFixtureRule(),
                PrivateKeyRule(),
                # Test-quality pillar
                ConditionalLogicRule(),
                EagerTestRule(),
                EmptyParametrizeRule(),
                ExceptionTypeOnlyRule(),
                ExcessiveMockingRule(),
                ExtendsProductionClassRule(),
                GlobalStateMutationRule(),
                LoopAssertionWithoutMessageRule(),
                LoopInTestRule(),
                MagicNumberAssertionRule(),
                MockOnlyTestRule(),
                MockWithoutExpectationRule(),
                MockingDomainObjectRule(),
                MultipleAaaCyclesRule(),
                MysteryGuestRule(),
                NamingConsistencyRule(),
                NoAssertionsRule(),
                ParametrizeAnnotationRule(),
                PrivateReflectionRule(),
                PytestCoverageSourceMissingRule(),
                PytestDeprecationsNotFatalRule(),
                PytestStrictConfigMissingRule(),
                RepeatedStructureMissingParametrizeRule(),
                SetupBloatRule(),
                SkippedWithoutReasonRule(),
                SleepInTestRule(),
                SutNotCalledRule(),
                TautologicalTypeAssertionRule(),
                TestFunctionTooLongRule(),
                TestLongerThanSutRule(),
                TestdoxReadabilityRule(),
                TrivialAssertionRule(),
                TrivialSnapshotRule(),
                UnusedMockRule(),
                # Size pillar
                AttributeCountRule(),
                AverageFunctionLengthRule(),
                ClassLengthRule(),
                FileLengthRule(),
                FunctionLengthRule(),
                ParameterCountRule(),
                PublicMethodCountRule(),
                # Waste pillar
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
            if settings.enabled and config.rule_selection.allows(definition):
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
