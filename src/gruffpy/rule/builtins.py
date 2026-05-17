"""Built-in rule factories for the default registry."""

from collections.abc import Callable

from gruffpy.rule.complexity.cognitive_complexity_rule import CognitiveComplexityRule
from gruffpy.rule.complexity.cyclomatic_complexity_rule import CyclomaticComplexityRule
from gruffpy.rule.complexity.halstead_volume_rule import HalsteadVolumeRule
from gruffpy.rule.complexity.maintainability_index_rule import MaintainabilityIndexRule
from gruffpy.rule.complexity.nesting_depth_rule import NestingDepthRule
from gruffpy.rule.complexity.npath_complexity_rule import NPathComplexityRule
from gruffpy.rule.dead_code.unused_private_attribute_rule import UnusedPrivateAttributeRule
from gruffpy.rule.dead_code.unused_private_function_rule import UnusedPrivateFunctionRule
from gruffpy.rule.design.single_implementor_protocol_rule import SingleImplementorProtocolRule
from gruffpy.rule.docs.missing_class_docstring_rule import MissingClassDocstringRule
from gruffpy.rule.docs.missing_function_docstring_rule import MissingFunctionDocstringRule
from gruffpy.rule.docs.missing_module_docstring_rule import MissingModuleDocstringRule
from gruffpy.rule.docs.missing_param_doc_rule import MissingParamDocRule
from gruffpy.rule.docs.missing_raises_doc_rule import MissingRaisesDocRule
from gruffpy.rule.docs.missing_readme_rule import MissingReadmeRule
from gruffpy.rule.docs.missing_return_doc_rule import MissingReturnDocRule
from gruffpy.rule.docs.stale_param_doc_rule import StaleParamDocRule
from gruffpy.rule.docs.todo_density_rule import TodoDensityRule
from gruffpy.rule.docs.useless_docstring_rule import UselessDocstringRule
from gruffpy.rule.naming.boolean_prefix_rule import BooleanPrefixRule
from gruffpy.rule.naming.confusing_name_rule import ConfusingNameRule
from gruffpy.rule.naming.generic_function_rule import GenericFunctionRule
from gruffpy.rule.naming.hungarian_notation_rule import HungarianNotationRule
from gruffpy.rule.naming.identifier_quality_rule import IdentifierQualityRule
from gruffpy.rule.naming.module_name_mismatch_rule import ModuleNameMismatchRule
from gruffpy.rule.naming.parameter_type_name_rule import ParameterTypeNameRule
from gruffpy.rule.naming.short_variable_rule import ShortVariableRule
from gruffpy.rule.naming.test_naming_consistency_rule import TestNamingConsistencyRule
from gruffpy.rule.project_rule import ProjectRuleProtocol
from gruffpy.rule.rule import Rule
from gruffpy.rule.security.dangerous_function_call_rule import DangerousFunctionCallRule
from gruffpy.rule.security.disabled_ssl_verification_rule import DisabledSslVerificationRule
from gruffpy.rule.security.error_suppression_rule import ErrorSuppressionRule
from gruffpy.rule.security.extract_compact_user_input_rule import ExtractCompactUserInputRule
from gruffpy.rule.security.header_injection_rule import HeaderInjectionRule
from gruffpy.rule.security.insecure_random_rule import InsecureRandomRule
from gruffpy.rule.security.shell_injection_rule import ShellInjectionRule
from gruffpy.rule.security.silent_except_rule import SilentExceptRule
from gruffpy.rule.security.sql_concatenation_rule import SqlConcatenationRule
from gruffpy.rule.security.unsafe_pickle_rule import UnsafePickleRule
from gruffpy.rule.security.variable_import_rule import VariableImportRule
from gruffpy.rule.security.weak_crypto_rule import WeakCryptoRule
from gruffpy.rule.sensitive_data.api_key_pattern_rule import ApiKeyPatternRule
from gruffpy.rule.sensitive_data.aws_access_key_rule import AwsAccessKeyRule
from gruffpy.rule.sensitive_data.database_url_password_rule import DatabaseUrlPasswordRule
from gruffpy.rule.sensitive_data.hardcoded_env_value_rule import HardcodedEnvValueRule
from gruffpy.rule.sensitive_data.high_entropy_string_rule import HighEntropyStringRule
from gruffpy.rule.sensitive_data.jwt_token_rule import JwtTokenRule
from gruffpy.rule.sensitive_data.phi_pattern_rule import PhiPatternRule
from gruffpy.rule.sensitive_data.pii_test_fixture_rule import PiiTestFixtureRule
from gruffpy.rule.sensitive_data.private_key_rule import PrivateKeyRule
from gruffpy.rule.size.attribute_count_rule import AttributeCountRule
from gruffpy.rule.size.average_function_length_rule import AverageFunctionLengthRule
from gruffpy.rule.size.class_length_rule import ClassLengthRule
from gruffpy.rule.size.file_length_rule import FileLengthRule
from gruffpy.rule.size.function_length_rule import FunctionLengthRule
from gruffpy.rule.size.parameter_count_rule import ParameterCountRule
from gruffpy.rule.size.public_method_count_rule import PublicMethodCountRule
from gruffpy.rule.test_quality.conditional_logic_rule import ConditionalLogicRule
from gruffpy.rule.test_quality.eager_test_rule import EagerTestRule
from gruffpy.rule.test_quality.empty_parametrize_rule import EmptyParametrizeRule
from gruffpy.rule.test_quality.exception_type_only_rule import ExceptionTypeOnlyRule
from gruffpy.rule.test_quality.excessive_mocking_rule import ExcessiveMockingRule
from gruffpy.rule.test_quality.extends_production_class_rule import ExtendsProductionClassRule
from gruffpy.rule.test_quality.global_state_mutation_rule import GlobalStateMutationRule
from gruffpy.rule.test_quality.loop_assertion_without_message_rule import (
    LoopAssertionWithoutMessageRule,
)
from gruffpy.rule.test_quality.loop_in_test_rule import LoopInTestRule
from gruffpy.rule.test_quality.magic_number_assertion_rule import MagicNumberAssertionRule
from gruffpy.rule.test_quality.mock_only_test_rule import MockOnlyTestRule
from gruffpy.rule.test_quality.mock_without_expectation_rule import MockWithoutExpectationRule
from gruffpy.rule.test_quality.mocking_domain_object_rule import MockingDomainObjectRule
from gruffpy.rule.test_quality.multiple_aaa_cycles_rule import MultipleAaaCyclesRule
from gruffpy.rule.test_quality.mystery_guest_rule import MysteryGuestRule
from gruffpy.rule.test_quality.naming_consistency_rule import NamingConsistencyRule
from gruffpy.rule.test_quality.no_assertions_rule import NoAssertionsRule
from gruffpy.rule.test_quality.parametrize_annotation_rule import ParametrizeAnnotationRule
from gruffpy.rule.test_quality.private_reflection_rule import PrivateReflectionRule
from gruffpy.rule.test_quality.pytest_coverage_source_missing_rule import (
    PytestCoverageSourceMissingRule,
)
from gruffpy.rule.test_quality.pytest_deprecations_not_fatal_rule import (
    PytestDeprecationsNotFatalRule,
)
from gruffpy.rule.test_quality.pytest_strict_config_missing_rule import (
    PytestStrictConfigMissingRule,
)
from gruffpy.rule.test_quality.repeated_structure_missing_parametrize_rule import (
    RepeatedStructureMissingParametrizeRule,
)
from gruffpy.rule.test_quality.setup_bloat_rule import SetupBloatRule
from gruffpy.rule.test_quality.skipped_without_reason_rule import SkippedWithoutReasonRule
from gruffpy.rule.test_quality.sleep_in_test_rule import SleepInTestRule
from gruffpy.rule.test_quality.sut_not_called_rule import SutNotCalledRule
from gruffpy.rule.test_quality.tautological_type_assertion_rule import (
    TautologicalTypeAssertionRule,
)
from gruffpy.rule.test_quality.test_function_too_long_rule import TestFunctionTooLongRule
from gruffpy.rule.test_quality.test_longer_than_sut_rule import TestLongerThanSutRule
from gruffpy.rule.test_quality.testdox_readability_rule import TestdoxReadabilityRule
from gruffpy.rule.test_quality.trivial_assertion_rule import TrivialAssertionRule
from gruffpy.rule.test_quality.trivial_snapshot_rule import TrivialSnapshotRule
from gruffpy.rule.test_quality.unused_mock_rule import UnusedMockRule
from gruffpy.rule.waste.commented_out_code_rule import CommentedOutCodeRule
from gruffpy.rule.waste.empty_class_rule import EmptyClassRule
from gruffpy.rule.waste.empty_function_rule import EmptyFunctionRule
from gruffpy.rule.waste.one_line_function_rule import OneLineFunctionRule
from gruffpy.rule.waste.redundant_variable_rule import RedundantVariableRule
from gruffpy.rule.waste.unreachable_code_rule import UnreachableCodeRule
from gruffpy.rule.waste.unused_import_rule import UnusedImportRule
from gruffpy.rule.waste.unused_parameter_rule import UnusedParameterRule

RuleLike = Rule | ProjectRuleProtocol
RuleFactory = Callable[[], RuleLike]

_DEFAULT_RULE_FACTORIES: tuple[RuleFactory, ...] = (
    CognitiveComplexityRule,
    CyclomaticComplexityRule,
    HalsteadVolumeRule,
    MaintainabilityIndexRule,
    NestingDepthRule,
    NPathComplexityRule,
    UnusedPrivateAttributeRule,
    UnusedPrivateFunctionRule,
    SingleImplementorProtocolRule,
    MissingClassDocstringRule,
    MissingFunctionDocstringRule,
    MissingModuleDocstringRule,
    MissingParamDocRule,
    MissingRaisesDocRule,
    MissingReadmeRule,
    MissingReturnDocRule,
    StaleParamDocRule,
    TodoDensityRule,
    UselessDocstringRule,
    BooleanPrefixRule,
    ConfusingNameRule,
    GenericFunctionRule,
    HungarianNotationRule,
    IdentifierQualityRule,
    ModuleNameMismatchRule,
    ParameterTypeNameRule,
    ShortVariableRule,
    TestNamingConsistencyRule,
    DangerousFunctionCallRule,
    DisabledSslVerificationRule,
    ErrorSuppressionRule,
    ExtractCompactUserInputRule,
    HeaderInjectionRule,
    InsecureRandomRule,
    ShellInjectionRule,
    SilentExceptRule,
    SqlConcatenationRule,
    UnsafePickleRule,
    VariableImportRule,
    WeakCryptoRule,
    ApiKeyPatternRule,
    AwsAccessKeyRule,
    DatabaseUrlPasswordRule,
    HardcodedEnvValueRule,
    HighEntropyStringRule,
    JwtTokenRule,
    PhiPatternRule,
    PiiTestFixtureRule,
    PrivateKeyRule,
    ConditionalLogicRule,
    EagerTestRule,
    EmptyParametrizeRule,
    ExceptionTypeOnlyRule,
    ExcessiveMockingRule,
    ExtendsProductionClassRule,
    GlobalStateMutationRule,
    LoopAssertionWithoutMessageRule,
    LoopInTestRule,
    MagicNumberAssertionRule,
    MockOnlyTestRule,
    MockWithoutExpectationRule,
    MockingDomainObjectRule,
    MultipleAaaCyclesRule,
    MysteryGuestRule,
    NamingConsistencyRule,
    NoAssertionsRule,
    ParametrizeAnnotationRule,
    PrivateReflectionRule,
    PytestCoverageSourceMissingRule,
    PytestDeprecationsNotFatalRule,
    PytestStrictConfigMissingRule,
    RepeatedStructureMissingParametrizeRule,
    SetupBloatRule,
    SkippedWithoutReasonRule,
    SleepInTestRule,
    SutNotCalledRule,
    TautologicalTypeAssertionRule,
    TestFunctionTooLongRule,
    TestLongerThanSutRule,
    TestdoxReadabilityRule,
    TrivialAssertionRule,
    TrivialSnapshotRule,
    UnusedMockRule,
    AttributeCountRule,
    AverageFunctionLengthRule,
    ClassLengthRule,
    FileLengthRule,
    FunctionLengthRule,
    ParameterCountRule,
    PublicMethodCountRule,
    CommentedOutCodeRule,
    EmptyClassRule,
    EmptyFunctionRule,
    OneLineFunctionRule,
    RedundantVariableRule,
    UnreachableCodeRule,
    UnusedImportRule,
    UnusedParameterRule,
)


def default_rules() -> list[RuleLike]:
    """Build the default rule set.

    Returns:
        Fresh rule instances in registry order.
    """
    return [factory() for factory in _DEFAULT_RULE_FACTORIES]
