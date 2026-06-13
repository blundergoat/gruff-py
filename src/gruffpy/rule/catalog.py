"""First-party catalog for built-in rules and their documentation metadata."""

from collections.abc import Callable
from dataclasses import dataclass, replace

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.pillar import Pillar
from gruffpy.rule.catalog_docs import (
    FalsePositiveShape as FalsePositiveShape,
    RuleDocs as RuleDocs,
    custom_docs_for,
)
from gruffpy.rule.catalog_related import RELATED_RULES as RELATED_RULES
from gruffpy.rule.complexity.cognitive_complexity_rule import CognitiveComplexityRule
from gruffpy.rule.complexity.cyclomatic_complexity_rule import CyclomaticComplexityRule
from gruffpy.rule.complexity.halstead_volume_rule import HalsteadVolumeRule
from gruffpy.rule.complexity.maintainability_index_rule import MaintainabilityIndexRule
from gruffpy.rule.complexity.nesting_depth_rule import NestingDepthRule
from gruffpy.rule.correctness.substring_vocabulary_match_rule import SubstringVocabularyMatchRule
from gruffpy.rule.correctness.unsafe_numeric_coercion_rule import UnsafeNumericCoercionRule
from gruffpy.rule.dead_code.exported_but_unreferenced_rule import ExportedButUnreferencedRule
from gruffpy.rule.dead_code.unused_private_attribute_rule import UnusedPrivateAttributeRule
from gruffpy.rule.dead_code.unused_private_function_rule import UnusedPrivateFunctionRule
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.design.runtime_sys_path_mutation_rule import RuntimeSysPathMutationRule
from gruffpy.rule.design.single_implementor_protocol_rule import SingleImplementorProtocolRule
from gruffpy.rule.docs.complex_branch_rationale_rule import ComplexBranchRationaleRule
from gruffpy.rule.docs.dataclass_attributes_rule import DataclassAttributesRule
from gruffpy.rule.docs.ignore_directive_reason_rule import IgnoreDirectiveReasonRule
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
from gruffpy.rule.modernisation.f_string_candidate_rule import FStringCandidateRule
from gruffpy.rule.naming.abbreviation_rule import AbbreviationRule
from gruffpy.rule.naming.boolean_prefix_rule import BooleanPrefixRule
from gruffpy.rule.naming.confusing_name_rule import ConfusingNameRule
from gruffpy.rule.naming.generic_function_rule import GenericFunctionRule
from gruffpy.rule.naming.hungarian_notation_rule import HungarianNotationRule
from gruffpy.rule.naming.identifier_quality_rule import IdentifierQualityRule
from gruffpy.rule.naming.module_name_mismatch_rule import ModuleNameMismatchRule
from gruffpy.rule.naming.short_variable_rule import ShortVariableRule
from gruffpy.rule.naming.test_naming_consistency_rule import TestNamingConsistencyRule
from gruffpy.rule.project_rule import ProjectRuleProtocol
from gruffpy.rule.rule import Rule
from gruffpy.rule.security._security_metadata import rule_security_metadata
from gruffpy.rule.security.cors_wildcard_with_credentials_rule import (
    CorsWildcardWithCredentialsRule,
)
from gruffpy.rule.security.dangerous_function_call_rule import DangerousFunctionCallRule
from gruffpy.rule.security.dependency_git_reference_rule import DependencyGitReferenceRule
from gruffpy.rule.security.dependency_local_path_rule import DependencyLocalPathRule
from gruffpy.rule.security.dependency_url_reference_rule import DependencyUrlReferenceRule
from gruffpy.rule.security.disabled_ssl_verification_rule import DisabledSslVerificationRule
from gruffpy.rule.security.django_mark_safe_rule import DjangoMarkSafeRule
from gruffpy.rule.security.django_raw_sql_rule import DjangoRawSqlRule
from gruffpy.rule.security.error_suppression_rule import ErrorSuppressionRule
from gruffpy.rule.security.extract_compact_user_input_rule import ExtractCompactUserInputRule
from gruffpy.rule.security.flask_debug_enabled_rule import FlaskDebugEnabledRule
from gruffpy.rule.security.github_actions_broad_permissions_rule import (
    GithubActionsBroadPermissionsRule,
)
from gruffpy.rule.security.github_actions_pull_request_target_rule import (
    GithubActionsPullRequestTargetRule,
)
from gruffpy.rule.security.github_actions_remote_shell_rule import (
    GithubActionsRemoteShellRule,
)
from gruffpy.rule.security.github_actions_secrets_in_pr_rule import (
    GithubActionsSecretsInPrRule,
)
from gruffpy.rule.security.github_actions_unpinned_action_rule import (
    GithubActionsUnpinnedActionRule,
)
from gruffpy.rule.security.hardcoded_bind_all_interfaces_rule import (
    HardcodedBindAllInterfacesRule,
)
from gruffpy.rule.security.hardcoded_framework_secret_key_rule import (
    HardcodedFrameworkSecretKeyRule,
)
from gruffpy.rule.security.header_injection_rule import HeaderInjectionRule
from gruffpy.rule.security.insecure_random_rule import InsecureRandomRule
from gruffpy.rule.security.insecure_temp_file_rule import InsecureTempFileRule
from gruffpy.rule.security.insecure_tls_protocol_rule import InsecureTlsProtocolRule
from gruffpy.rule.security.jinja2_autoescape_off_rule import Jinja2AutoescapeOffRule
from gruffpy.rule.security.paramiko_no_host_key_check_rule import (
    ParamikoNoHostKeyCheckRule,
)
from gruffpy.rule.security.path_traversal_rule import PathTraversalRule
from gruffpy.rule.security.shell_injection_rule import ShellInjectionRule
from gruffpy.rule.security.silent_except_rule import SilentExceptRule
from gruffpy.rule.security.sql_concatenation_rule import SqlConcatenationRule
from gruffpy.rule.security.ssrf_rule import SsrfRule
from gruffpy.rule.security.unsafe_pickle_rule import UnsafePickleRule
from gruffpy.rule.security.unsafe_yaml_load_rule import UnsafeYamlLoadRule
from gruffpy.rule.security.unsanitized_markdown_interpolation_rule import (
    UnsanitizedMarkdownInterpolationRule,
)
from gruffpy.rule.security.variable_import_rule import VariableImportRule
from gruffpy.rule.security.weak_crypto_rule import WeakCryptoRule
from gruffpy.rule.security.xxe_rule import XxeRule
from gruffpy.rule.sensitive_data.api_key_pattern_rule import ApiKeyPatternRule
from gruffpy.rule.sensitive_data.aws_access_key_rule import AwsAccessKeyRule
from gruffpy.rule.sensitive_data.database_url_password_rule import DatabaseUrlPasswordRule
from gruffpy.rule.sensitive_data.gcp_service_account_key_rule import GcpServiceAccountKeyRule
from gruffpy.rule.sensitive_data.hardcoded_env_value_rule import HardcodedEnvValueRule
from gruffpy.rule.sensitive_data.high_entropy_string_rule import HighEntropyStringRule
from gruffpy.rule.sensitive_data.jwt_token_rule import JwtTokenRule
from gruffpy.rule.sensitive_data.phi_pattern_rule import PhiPatternRule
from gruffpy.rule.sensitive_data.pii_test_fixture_rule import PiiTestFixtureRule
from gruffpy.rule.sensitive_data.private_key_rule import PrivateKeyRule
from gruffpy.rule.sensitive_data.url_credentials_rule import UrlCredentialsRule
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
from gruffpy.rule.test_quality.static_analysis_redundant_test_rule import (
    StaticAnalysisRedundantTestRule,
)
from gruffpy.rule.test_quality.sut_not_called_rule import SutNotCalledRule
from gruffpy.rule.test_quality.tautological_type_assertion_rule import (
    TautologicalTypeAssertionRule,
)
from gruffpy.rule.test_quality.test_function_too_long_rule import TestFunctionTooLongRule
from gruffpy.rule.test_quality.test_longer_than_sut_rule import TestLongerThanSutRule
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

__all__ = ["RELATED_RULES", "FalsePositiveShape", "RuleDocs"]

RuleLike = Rule | ProjectRuleProtocol
RuleFactory = Callable[[], RuleLike]

_STANDARD_THRESHOLD_METADATA_KEYS = (
    "measuredValue",
    "threshold",
    "thresholdDirection",
    "thresholdType",
)

_THRESHOLD_DIRECTIONS = {
    "complexity.maintainability-index": "below",
}

_FORMULA_PROVENANCE = {
    "complexity.cyclomatic": "Radon-aligned decision-point counting.",
    "complexity.halstead-volume": (
        "Radon-inspired Halstead volume with documented Python AST deltas. "
        "The dogfood rubric uses one configured threshold, `>400` at error "
        "severity; the legacy built-in fallback came from Java/PHP-tuned gruff "
        "defaults. 2026-05-18 metric-calibration on `src/` and `tests/` observed "
        "p50=4.75, p90=38.04, p99=96.0, max=283.39."
    ),
    "complexity.maintainability-index": (
        "gruff per-function maintainability heuristic based on Halstead volume, "
        "cyclomatic complexity, and raw function lines. The dogfood rubric uses "
        "one configured threshold, `<70` at error severity; the legacy built-in "
        "fallback came from Java/PHP-tuned gruff defaults. 2026-05-18 "
        "metric-calibration on `src/` and `tests/` observed min=78.78, p50=100, "
        "p90=100, p99=100. Radon 6.0.1 ranks maintainability index 20-100 as "
        "A/very high, 10-19 as B/medium, and 0-9 as C/extremely low: "
        "https://radon.readthedocs.io/en/stable/commandline.html#the-mi-command."
    ),
}


@dataclass(frozen=True, slots=True)
class BuiltInRule:
    """Catalog entry tying a built-in rule factory to docs metadata.

    Attributes:
        factory: Callable that creates a fresh rule instance.
        definition: Static rule metadata returned by the factory.
        docs: Documentation metadata for reports and generated docs.
    """

    factory: RuleFactory
    definition: RuleDefinition
    docs: RuleDocs

    def create(self) -> RuleLike:
        """Build a fresh rule instance.

        Returns:
            Rule instance for use by the runtime registry.
        """
        return self.factory()


def _entry(factory: RuleFactory) -> BuiltInRule:
    definition = factory().definition()
    return BuiltInRule(
        factory=factory,
        definition=definition,
        docs=_docs_for_definition(definition),
    )


def _docs_for_definition(definition: RuleDefinition) -> RuleDocs:
    subject = definition.name.lower()
    config_keys = _config_keys_for(definition)
    custom_docs = custom_docs_for(definition, config_keys=config_keys)
    if custom_docs is None:
        bad = f"Code that triggers `{definition.id}` leaves {subject} unaddressed."
        good = f"Code that satisfies `{definition.id}` makes {subject} explicit or simpler."
        custom_docs = RuleDocs(
            rationale=_rationale_for(definition),
            fix_guidance=_fix_guidance_for(definition),
            bad_example=bad,
            good_example=good,
            confidence_rationale=_confidence_rationale(definition.confidence),
            config_keys=config_keys,
            formula_provenance=_FORMULA_PROVENANCE.get(definition.id, ""),
            threshold_direction=_threshold_direction(definition),
            threshold_metadata_keys=_threshold_metadata_keys(definition),
            security_metadata=rule_security_metadata(definition.id),
        )
    option_descriptions = _OPTION_DESCRIPTIONS.get(definition.id)
    if option_descriptions is not None:
        custom_docs = replace(custom_docs, option_descriptions=option_descriptions)
    return custom_docs


def _rationale_for(definition: RuleDefinition) -> str:
    return (
        f"`{definition.id}` protects the {definition.pillar.value} pillar by flagging "
        f"{definition.name.lower()} before it becomes costly to review, maintain, or trust."
    )


def _fix_guidance_for(definition: RuleDefinition) -> str:
    return (
        f"Address the reported {definition.name.lower()} directly, or tune this rule with "
        "an explicit project configuration override when the project has a documented exception."
    )


def _confidence_rationale(confidence: Confidence) -> str:
    match confidence:
        case Confidence.HIGH:
            return "High confidence: the rule matches precise AST or source patterns."
        case Confidence.MEDIUM:
            return "Medium confidence: the rule uses bounded heuristics with known safe escapes."
        case Confidence.LOW:
            return "Low confidence: the rule is intentionally conservative and may need tuning."


def _config_keys_for(definition: RuleDefinition) -> tuple[str, ...]:
    keys: list[str] = []
    if definition.default_threshold is not None:
        keys.extend(("threshold", "severity"))
    else:
        keys.extend(f"thresholds.{name}" for name in definition.default_thresholds)
    keys.extend(f"options.{name}" for name in definition.default_options)
    return tuple(keys)


def _threshold_direction(definition: RuleDefinition) -> str:
    if definition.default_threshold is None and not definition.default_thresholds:
        return ""
    return _THRESHOLD_DIRECTIONS.get(definition.id, "above")


def _threshold_metadata_keys(definition: RuleDefinition) -> tuple[str, ...]:
    if definition.default_threshold is None and not definition.default_thresholds:
        return ()
    if definition.default_threshold is not None or definition.pillar in {
        Pillar.SIZE,
        Pillar.COMPLEXITY,
        Pillar.MAINTAINABILITY,
    }:
        return _STANDARD_THRESHOLD_METADATA_KEYS
    return ()


_OPTION_DESCRIPTIONS: dict[str, dict[str, str]] = {
    "dead-code.exported-but-unreferenced": {
        "entryPointPatterns": (
            "fnmatch globs over public symbol names consumed by plugin or "
            "entry-point registration the scan cannot see (e.g. handle_*)."
        ),
    },
    "design.single-implementor-protocol": {
        "externalProtocolBases": (
            "Protocol-shaped base classes whose subclasses are exempt from the "
            "single-implementor check (typing.Sized, typing.Iterable, etc.)."
        ),
        "additionalExcludedPaths": (
            "Project-relative glob patterns for files exempt from the rule."
        ),
    },
    "docs.complex-branch-rationale": {
        "cyclomatic_warning": (
            "Public-function cyclomatic threshold above which rationale is required."
        ),
        "cognitive_warning": (
            "Public-function cognitive complexity threshold above which rationale is required."
        ),
        "private_cyclomatic_warning": (
            "Private-function cyclomatic threshold; private functions get more headroom."
        ),
        "private_cognitive_warning": "Private-function cognitive complexity threshold.",
    },
    "docs.dataclass-attributes": {
        "min_fields": ("Minimum dataclass field count before an Attributes docstring is required."),
        "require_all_fields": (
            "When true, every dataclass field must appear in the Attributes block."
        ),
        "allow_bullets": "When true, accept Markdown bullet lists as well as Sphinx :ivar: blocks.",
    },
    "docs.missing-class-docstring": {
        "class_dataclass_exempt": (
            "When true, @dataclass-decorated classes are exempt (rely on "
            "docs.dataclass-attributes for their docs requirement instead)."
        ),
    },
    "docs.useless-docstring": {
        "min_summary_words": (
            "Per-kind minimum word count for a non-useless summary line "
            "(keys: module, class, function)."
        ),
    },
    "naming.confusing-name": {
        "confusingNames": (
            "Identifier suffixes flagged as low-content (Handler, Manager, Util, ...)."
        ),
    },
    "naming.generic-function": {
        "genericFunctions": (
            "Function names flagged as too generic to convey intent (process, handle, run, ...)."
        ),
    },
    "naming.boolean-prefix": {
        "acceptedBooleanNames": (
            "Exact boolean names accepted for external protocol, CLI, DTO, or schema contracts "
            "(ok, force, verbose, etc.)."
        ),
    },
    "naming.module-name-mismatch": {
        "conventionalModuleNames": (
            "Module names exempt from the convention check "
            "(constants, exceptions, helpers, protocols, types)."
        ),
    },
    "naming.short-variable": {
        "acceptedShortNames": (
            "Single-character identifiers accepted as conventional "
            "(loop counters, math axes, exception variables)."
        ),
    },
    "test-quality.magic-number-assertion": {
        "allowed_numbers": (
            "Integer literals accepted in test assertions without extraction "
            "(small ints and HTTP status codes by default)."
        ),
    },
    "test-quality.extends-production-class": {
        "additionalTestBases": (
            "Exact dotted or terminal base-class names treated as test bases in addition to "
            "the built-in allowlist and *TestCase suffix convention."
        ),
    },
    "test-quality.mocking-domain-object": {
        "domain_namespaces": (
            "Dotted module prefixes considered domain code; mocking imports "
            "from these paths trips the rule. Empty by default; populate to enable."
        ),
    },
    "test-quality.test-longer-than-sut": {
        "ratio": (
            "Allowed test-to-SUT length ratio above which the test is flagged (default 2.0)."
        ),
    },
}


BUILTIN_RULES: tuple[BuiltInRule, ...] = (
    _entry(CognitiveComplexityRule),
    _entry(CyclomaticComplexityRule),
    _entry(HalsteadVolumeRule),
    _entry(MaintainabilityIndexRule),
    _entry(NestingDepthRule),
    _entry(SubstringVocabularyMatchRule),
    _entry(UnsafeNumericCoercionRule),
    _entry(ExportedButUnreferencedRule),
    _entry(UnusedPrivateAttributeRule),
    _entry(UnusedPrivateFunctionRule),
    _entry(RuntimeSysPathMutationRule),
    _entry(SingleImplementorProtocolRule),
    _entry(ComplexBranchRationaleRule),
    _entry(DataclassAttributesRule),
    _entry(IgnoreDirectiveReasonRule),
    _entry(MissingClassDocstringRule),
    _entry(MissingFunctionDocstringRule),
    _entry(MissingModuleDocstringRule),
    _entry(MissingParamDocRule),
    _entry(MissingRaisesDocRule),
    _entry(MissingReadmeRule),
    _entry(MissingReturnDocRule),
    _entry(StaleParamDocRule),
    _entry(TodoDensityRule),
    _entry(UselessDocstringRule),
    _entry(FStringCandidateRule),
    _entry(AbbreviationRule),
    _entry(BooleanPrefixRule),
    _entry(ConfusingNameRule),
    _entry(GenericFunctionRule),
    _entry(HungarianNotationRule),
    _entry(IdentifierQualityRule),
    _entry(ModuleNameMismatchRule),
    _entry(ShortVariableRule),
    _entry(TestNamingConsistencyRule),
    _entry(CorsWildcardWithCredentialsRule),
    _entry(DangerousFunctionCallRule),
    _entry(DependencyGitReferenceRule),
    _entry(DependencyLocalPathRule),
    _entry(DependencyUrlReferenceRule),
    _entry(DisabledSslVerificationRule),
    _entry(DjangoMarkSafeRule),
    _entry(DjangoRawSqlRule),
    _entry(ErrorSuppressionRule),
    _entry(ExtractCompactUserInputRule),
    _entry(FlaskDebugEnabledRule),
    _entry(GithubActionsBroadPermissionsRule),
    _entry(GithubActionsPullRequestTargetRule),
    _entry(GithubActionsRemoteShellRule),
    _entry(GithubActionsSecretsInPrRule),
    _entry(GithubActionsUnpinnedActionRule),
    _entry(HardcodedBindAllInterfacesRule),
    _entry(HardcodedFrameworkSecretKeyRule),
    _entry(HeaderInjectionRule),
    _entry(InsecureRandomRule),
    _entry(InsecureTempFileRule),
    _entry(InsecureTlsProtocolRule),
    _entry(Jinja2AutoescapeOffRule),
    _entry(ParamikoNoHostKeyCheckRule),
    _entry(PathTraversalRule),
    _entry(ShellInjectionRule),
    _entry(SilentExceptRule),
    _entry(SqlConcatenationRule),
    _entry(SsrfRule),
    _entry(UnsafePickleRule),
    _entry(UnsafeYamlLoadRule),
    _entry(UnsanitizedMarkdownInterpolationRule),
    _entry(VariableImportRule),
    _entry(WeakCryptoRule),
    _entry(XxeRule),
    _entry(ApiKeyPatternRule),
    _entry(AwsAccessKeyRule),
    _entry(DatabaseUrlPasswordRule),
    _entry(GcpServiceAccountKeyRule),
    _entry(HardcodedEnvValueRule),
    _entry(HighEntropyStringRule),
    _entry(JwtTokenRule),
    _entry(PhiPatternRule),
    _entry(PiiTestFixtureRule),
    _entry(PrivateKeyRule),
    _entry(UrlCredentialsRule),
    _entry(ConditionalLogicRule),
    _entry(EagerTestRule),
    _entry(EmptyParametrizeRule),
    _entry(ExceptionTypeOnlyRule),
    _entry(ExcessiveMockingRule),
    _entry(ExtendsProductionClassRule),
    _entry(GlobalStateMutationRule),
    _entry(LoopAssertionWithoutMessageRule),
    _entry(LoopInTestRule),
    _entry(MagicNumberAssertionRule),
    _entry(MockOnlyTestRule),
    _entry(MockWithoutExpectationRule),
    _entry(MockingDomainObjectRule),
    _entry(MultipleAaaCyclesRule),
    _entry(MysteryGuestRule),
    _entry(NamingConsistencyRule),
    _entry(NoAssertionsRule),
    _entry(ParametrizeAnnotationRule),
    _entry(PrivateReflectionRule),
    _entry(PytestCoverageSourceMissingRule),
    _entry(PytestDeprecationsNotFatalRule),
    _entry(PytestStrictConfigMissingRule),
    _entry(RepeatedStructureMissingParametrizeRule),
    _entry(SetupBloatRule),
    _entry(SkippedWithoutReasonRule),
    _entry(SleepInTestRule),
    _entry(StaticAnalysisRedundantTestRule),
    _entry(SutNotCalledRule),
    _entry(TautologicalTypeAssertionRule),
    _entry(TestFunctionTooLongRule),
    _entry(TestLongerThanSutRule),
    _entry(TrivialAssertionRule),
    _entry(TrivialSnapshotRule),
    _entry(UnusedMockRule),
    _entry(AttributeCountRule),
    _entry(AverageFunctionLengthRule),
    _entry(ClassLengthRule),
    _entry(FileLengthRule),
    _entry(FunctionLengthRule),
    _entry(ParameterCountRule),
    _entry(PublicMethodCountRule),
    _entry(CommentedOutCodeRule),
    _entry(EmptyClassRule),
    _entry(EmptyFunctionRule),
    _entry(OneLineFunctionRule),
    _entry(RedundantVariableRule),
    _entry(UnreachableCodeRule),
    _entry(UnusedImportRule),
    _entry(UnusedParameterRule),
)

_BUILTIN_RULES_BY_ID: dict[str, BuiltInRule] = {
    entry.definition.id: entry for entry in BUILTIN_RULES
}


def default_rules() -> list[RuleLike]:
    """Build the default rule set.

    Returns:
        Fresh rule instances in catalog order.
    """
    return [entry.create() for entry in BUILTIN_RULES]


def documentation_for_rule(rule_id: str) -> RuleDocs:
    """Return documentation metadata for one built-in rule.

    Args:
        rule_id: Built-in rule id.

    Returns:
        Catalog ``RuleDocs`` (rationale, examples, threshold semantics).

    Raises:
        KeyError: If *rule_id* is not a built-in catalog entry.
    """
    try:
        return _BUILTIN_RULES_BY_ID[rule_id].docs
    except KeyError as exc:
        raise KeyError(f'Unknown built-in rule id "{rule_id}".') from exc


def catalog_definitions() -> list[RuleDefinition]:
    """Return built-in rule definitions in catalog order.

    Returns:
        List of ``RuleDefinition`` records, one per ``BUILTIN_RULES`` entry.
    """
    return [entry.definition for entry in BUILTIN_RULES]
