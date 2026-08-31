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
    if not custom_docs.false_positive_shapes:
        false_positive_guidance = _REVIEWED_FALSE_POSITIVE_GUIDANCE.get(definition.id)
        if false_positive_guidance is not None:
            custom_docs = replace(
                custom_docs,
                false_positive_shapes=(FalsePositiveShape(*false_positive_guidance),),
            )
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


# M04 review guidance for heuristic rules whose richer custom docs do not already
# publish a false-positive shape. Each entry reflects a detector boundary covered
# by the rule's source or tests; the runtime definition remains the single owner of
# confidence, thresholds, and options.
_REVIEWED_FALSE_POSITIVE_GUIDANCE: dict[str, tuple[str, str]] = {
    "complexity.halstead-volume": (
        "A declarative builder dominated by one literal table can have high token volume despite having little control-flow complexity.",
        "Extract the table to data or tune this rule's `threshold` and `severity` when the volume is an accepted project convention.",
    ),
    "complexity.maintainability-index": (
        "A long but linear wiring, data-setup, or generated function can score poorly even when its branching is simple.",
        "Split the function or tune this rule's `threshold` and `severity` after confirming "
        "that logical length, rather than complexity, drives the score.",
    ),
    "dead-code.unused-private-attribute": (
        "A private attribute read through `getattr`, serialization, or framework reflection has no parser-visible load.",
        "Keep an explicit read when practical, or suppress `dead-code.unused-private-attribute` with a reason at the reviewed declaration.",
    ),
    "design.single-implementor-protocol": (
        "A public Protocol or ABC can have downstream implementations or consumers outside "
        "the scanned project while only one local implementation is visible.",
        "Keep the abstraction when it is an external contract; exclude the reviewed path with "
        "`options.additionalExcludedPaths` or suppress the finding with that reason.",
    ),
    "docs.complex-branch-rationale": (
        "A complex function's rationale can live in an architecture record or issue rather "
        "than in the nearby docstring or branch comment this rule inspects.",
        "Add a substantive local rationale, or tune the public/private cyclomatic and cognitive warning options to the project's documented policy.",
    ),
    "docs.dataclass-attributes": (
        "Dataclass fields documented by an inherited schema or external generator are not visible in the class's local docstring.",
        "Add a local Attributes section, or tune `options.min_fields`, "
        "`options.require_all_fields`, and `options.allow_bullets` to match the docs policy.",
    ),
    "docs.missing-module-docstring": (
        "A generated or deliberately single-purpose production module can be documented by its package reference instead of a module docstring.",
        "Add the local module summary, exclude generated paths from analysis, or suppress the rule for the reviewed module with a reason.",
    ),
    "docs.missing-param-doc": (
        "An override can inherit its parameter contract from a documented interface even "
        "though its local docstring has no Args or Parameters section.",
        "Repeat the parameter contract locally, or suppress the rule on the reviewed override "
        "when inherited documentation is the project convention.",
    ),
    "docs.missing-raises-doc": (
        "A wrapper can re-raise an exception whose contract is documented on the interface it implements rather than in its local docstring.",
        "Add a local Raises section, or suppress the rule on the reviewed wrapper when the inherited exception contract is authoritative.",
    ),
    "docs.missing-readme": (
        "A package can use `docs/index.md` or another generated landing page as its maintained entry point instead of a root README.",
        "Add a root README that points to the maintained documentation, or disable this rule "
        "for the project after documenting the alternate entry point.",
    ),
    "docs.missing-return-doc": (
        "An override can inherit its return contract from a documented Protocol or base class while omitting a local Returns section.",
        "Repeat the return contract locally, or suppress the rule on the reviewed override when inherited documentation is authoritative.",
    ),
    "docs.todo-density": (
        "A planning or migration module can intentionally carry several tracked TODO markers while the work remains bounded and owned.",
        "Move the work to the issue tracker or tune this rule's `threshold` and `severity` for the reviewed planning surface.",
    ),
    "docs.useless-docstring": (
        "A protocol adapter or command method can have a deliberately terse summary whose meaning is supplied by a stable interface.",
        "Add the missing behavior or constraint to the summary, or tune `options.min_summary_words` for the project's documentation convention.",
    ),
    "modernisation.f-string-candidate": (
        "A literal `.format()` call can be retained deliberately to mirror a documented format "
        "template or keep a complex formatting expression easier to compare.",
        "Use an f-string when it improves clarity, or suppress this advisory with the reason "
        "the format-template spelling is part of the reviewed code.",
    ),
    "naming.boolean-prefix": (
        "An externally constrained Boolean name can belong to a protocol, CLI, DTO, or schema "
        "that the structural override exemptions do not recognize.",
        "Add the exact contract name to `options.acceptedBooleanNames` instead of renaming the external surface.",
    ),
    "naming.confusing-name": (
        "A deliberately short class name can gain its missing domain context from the enclosing module or package.",
        "Rename the class with explicit domain context, or remove that suffix from "
        "`options.confusingNames` when the package naming convention supplies it.",
    ),
    "naming.generic-function": (
        "A framework hook or protocol can require a generic function name such as `run` or "
        "`handle` even when the implementation has one clear responsibility.",
        "Remove the required hook name from `options.genericFunctions` or suppress the finding at the reviewed implementation.",
    ),
    "naming.module-name-mismatch": (
        "A feature-oriented module can intentionally contain one public class plus supporting functions without being named after that class.",
        "Add the module name to `options.conventionalModuleNames`, reorganize the module, or suppress the reviewed exception.",
    ),
    "naming.short-variable": (
        "A one-character domain or mathematical symbol can be conventional even when it is not one of the built-in loop, axis, or exception names.",
        "Add the exact symbol to `options.acceptedShortNames` with the project's convention, or rename it where the short form is not load-bearing.",
    ),
    "naming.test-naming-consistency": (
        "A compatibility or migration test file can intentionally preserve both unittest-style camelCase names and pytest-style snake_case names.",
        "Finish the rename when compatibility permits, or suppress the file-level advisory with the migration reason.",
    ),
    "security.django-mark-safe": (
        "A dynamic value can already be safe by an upstream validation or trusted-type contract "
        "that is not a wrapping escape call in the inspected expression.",
        "Pass the value through an explicit escaping helper or `format_html`, or suppress the reviewed sink with the upstream safety reason.",
    ),
    "security.error-suppression": (
        "A best-effort cleanup or telemetry path can deliberately suppress every exception because failure must not replace the primary result.",
        "Catch the narrow expected exceptions, or suppress this rule at the reviewed boundary "
        "with the reason the fallback is intentionally fail-open.",
    ),
    "security.extract-compact-user-input": (
        "A request mapping splat can contain only allowlisted keys after validation performed outside the expression this rule sees.",
        "Copy validated keys into an explicit dictionary before `**` expansion, or suppress the reviewed call with the validation contract.",
    ),
    "security.github-actions-secrets-in-pr": (
        "A secret reference in a pull-request workflow can sit behind a trusted-actor condition that the workflow text scan does not evaluate.",
        "Move the secret-bearing job to a trusted workflow or suppress the reviewed reference "
        "only after verifying the actor gate cannot be influenced by the pull request.",
    ),
    "security.hardcoded-bind-all-interfaces": (
        "A containerized service can deliberately bind to all interfaces while an external network policy prevents public exposure.",
        "Read the bind address from deployment configuration, or suppress the reviewed literal with the network-boundary reason.",
    ),
    "security.header-injection": (
        "A dynamic Flask header name can be selected from an internal allowlist or enum before "
        "the assignment, which this local AST check cannot prove.",
        "Map the validated choice to literal header assignments, or suppress the reviewed sink with the allowlist evidence.",
    ),
    "security.insecure-random": (
        "A non-secret simulation value or opaque identifier can use `random` inside a function "
        "whose token- or password-like name suggests a security context.",
        "Use `secrets` when unpredictability matters; otherwise rename the non-security value or suppress the reviewed call with its purpose.",
    ),
    "security.insecure-temp-file": (
        "A fixed temporary path can be process-private inside an isolated sandbox even though that exclusivity is not visible at the call site.",
        "Use `mkstemp` or `NamedTemporaryFile`, or suppress the reviewed path with evidence of the containing permission and lifecycle controls.",
    ),
    "security.sql-concatenation": (
        "A SQL identifier selected from a strict allowlist cannot be bound as a DB-API value, "
        "but its interpolation still looks like user-controlled query structure.",
        "Map the choice to predeclared literal statements and bind all values, or suppress the "
        "reviewed identifier interpolation with its allowlist evidence.",
    ),
    "security.variable-import": (
        "A dynamic module name can come from a closed plugin registry or internal allowlist that the import expression does not expose.",
        "Map allowed names to explicit imports, or suppress the reviewed import with the registry boundary that prevents user control.",
    ),
    "sensitive-data.hardcoded-env-value": (
        "A non-secret value can use a key containing PASS, TOKEN, or SECRET while its length and entropy resemble a credential.",
        "Rename the non-secret key or move the value to runtime configuration so the env-file "
        "assignment no longer resembles committed secret material.",
    ),
    "sensitive-data.high-entropy-string": (
        "A legitimate random-looking test vector, checksum, or opaque constant outside the "
        "built-in identifier and path exclusions can exceed the entropy boundary.",
        "Replace fixtures with a recognizable placeholder, or add a reasoned `sensitiveExclusions` entry for the exact reviewed rule and path.",
    ),
    "sensitive-data.phi-pattern": (
        "A structurally valid synthetic SSN or labelled MRN outside the placeholder set can look like real health data.",
        "Use a recognized placeholder, or add a reasoned `sensitiveExclusions` entry for the exact reviewed rule and fixture path.",
    ),
    "sensitive-data.pii-test-fixture": (
        "An intentionally synthetic but realistic email address or phone number outside the "
        "reserved-domain and 555 placeholder forms can look like real fixture PII.",
        "Use `example` domains or 555-style numbers, or add a reasoned `sensitiveExclusions` entry for the exact reviewed rule and fixture path.",
    ),
    "test-quality.conditional-logic": (
        "A property, state-machine, or compatibility test can intentionally exercise several outcome branches in one named scenario.",
        "Parametrize or split the branches for separate failures, or suppress the reviewed test when one scenario must retain the control flow.",
    ),
    "test-quality.eager-test": (
        "One outcome can require many field-level assertions, so assertion count alone can make a focused contract test look eager.",
        "Compare a structured expected value or tune `thresholds.maxAssertions` after confirming all assertions describe the same behavior.",
    ),
    "test-quality.exception-type-only": (
        "A boundary can intentionally promise only that any wide exception escapes, with no stable message suitable for `match=`.",
        "Prefer a narrow exception or stable message match; otherwise suppress the reviewed assertion with the type-only contract.",
    ),
    "test-quality.excessive-mocking": (
        "A coordinator test can legitimately isolate several collaborators because orchestration is the production responsibility under test.",
        "Use a higher-level test or tune `thresholds.maxMocks` for suites whose reviewed subject is an orchestrator.",
    ),
    "test-quality.global-state-mutation": (
        "A test can restore a `global` binding in a fixture or `finally` block, but this rule reports the declaration without evaluating cleanup.",
        "Use `monkeypatch` or a fixture-owned state boundary, or suppress the reviewed test with the cleanup guarantee.",
    ),
    "test-quality.loop-assertion-without-message": (
        "The compared item can already have a stable, descriptive repr that identifies the failing iteration without a custom assertion message.",
        "Add an iteration-specific message or parametrize the cases; otherwise suppress the "
        "reviewed loop when failure output is already unambiguous.",
    ),
    "test-quality.loop-in-test": (
        "A state-machine, fuzz, or property test can require a loop whose branches make the built-in fixture-loop exemption inapplicable.",
        "Parametrize finite cases, or suppress the reviewed test when iteration is itself the behavior under test.",
    ),
    "test-quality.magic-number-assertion": (
        "A bare literal can be an established domain constant such as a protocol version or exit "
        "code even when it is outside the built-in small-count and HTTP sets.",
        "Assert against a named constant or add the exact value to `options.allowed_numbers`.",
    ),
    "test-quality.mock-only-test": (
        "An interaction can be the complete contract, such as proving an event was dispatched or a boundary received a mapped payload.",
        "Keep an explicit mock expectation and suppress the reviewed test, or add an assertion on "
        "an observable result when the contract is not purely interaction-based.",
    ),
    "test-quality.mock-without-expectation": (
        "A deliberate null-object double can be passed only to satisfy a constructor signature, "
        "with no expectation because no interaction is the contract.",
        "Use a small fake or add an explicit `assert_not_called` expectation so the intent is visible to the rule and reviewer.",
    ),
    "test-quality.mocking-domain-object": (
        "A configured domain namespace can also contain ports or interfaces that are appropriate mock boundaries.",
        "Narrow `options.domain_namespaces` to concrete domain-object packages or use a small fake for the reviewed port.",
    ),
    "test-quality.multiple-aaa-cycles": (
        "One workflow or state-transition test can deliberately assert after each step, making several call-separated assertion blocks one scenario.",
        "Split the transitions or tune `thresholds.maxCycles` after confirming the test is one reviewed workflow.",
    ),
    "test-quality.mystery-guest": (
        "A test can call `open` on `tmp_path` or reach a local test server even though the target is fixture-owned and hermetic.",
        "Move the I/O behind an explicit fixture/helper or suppress the reviewed test with the fixture boundary.",
    ),
    "test-quality.naming-consistency": (
        "A compatibility or staged migration suite can intentionally mix pytest function names with unittest-style function or class names.",
        "Complete the rename when compatibility permits, or suppress the file-level advisory with the migration reason.",
    ),
    "test-quality.parametrize-annotation": (
        "Simple enum, integer, or named-object cases can already have short stable repr values, so "
        "generated pytest case names remain readable without `ids=`.",
        "Add explicit IDs or tune `thresholds.maxCasesWithoutIds` after checking the actual report names.",
    ),
    "test-quality.private-reflection": (
        "A compatibility, serialization, or migration test can deliberately verify a private attribute as the persisted contract.",
        "Prefer public behavior, or suppress the reviewed access with the compatibility contract it protects.",
    ),
    "test-quality.pytest-coverage-source-missing": (
        "Coverage source can be supplied by CI arguments, `.coveragerc`, or environment settings that the pyproject-only check does not read.",
        "Declare `[tool.coverage.run]` source, or suppress the project finding after checking the external coverage command.",
    ),
    "test-quality.pytest-deprecations-not-fatal": (
        "CI can turn deprecations into errors through command-line warning flags or environment "
        "settings that the pyproject-only check does not read.",
        "Declare the error filter in `[tool.pytest.ini_options].filterwarnings`, or suppress the project finding after verifying the external gate.",
    ),
    "test-quality.pytest-strict-config-missing": (
        "CI can pass pytest strict flags on the command line while pyproject omits them, "
        "or a plugin compatibility shim can require permissive markers.",
        "Add both flags to `[tool.pytest.ini_options].addopts`, or suppress the finding with the verified external gate or compatibility reason.",
    ),
    "test-quality.repeated-structure-missing-parametrize": (
        "Three named scenarios can share one AST shape while their separate names and failures are "
        "the contract, especially when only literal values differ.",
        "Parametrize the cases or tune `thresholds.minGroupSize`; suppress the group when separate scenario identities are intentionally retained.",
    ),
    "test-quality.setup-bloat": (
        "A costly domain fixture can be longer than its deliberately small focused tests without representing accidental shared state.",
        "Extract factories or tune `thresholds.maxSetupLines` after confirming the shared setup is the reviewed suite boundary.",
    ),
    "test-quality.sut-not-called": (
        "A contract test can validate module constants or metadata using only builtins and test helpers, with no callable system under test.",
        "Assert through the public contract where possible, or suppress the reviewed test with the declarative surface it verifies.",
    ),
    "test-quality.tautological-type-assertion": (
        "The same call expression evaluated twice can return different runtime types, even though "
        "the structural comparison treats both expressions as identical.",
        "Evaluate the call once and assert the specific expected type, or suppress the reviewed dynamic-factory case.",
    ),
    "test-quality.test-longer-than-sut": (
        "A table-driven contract test can need many scenarios around one short same-file function, so line ratio overstates duplication.",
        "Split or extract setup, or tune `options.ratio` after reviewing the scenario coverage.",
    ),
    "test-quality.trivial-snapshot": (
        "A canonical encoding or compatibility fixture can intentionally pin every element of a large literal collection.",
        "Assert salient invariants, or suppress the reviewed snapshot with the exact compatibility contract it protects.",
    ),
    "waste.commented-out-code": (
        "Explanatory prose can itself be valid Python after the code-like prefilter, such as a comment written as an assignment or call.",
        "Rewrite it as prose that does not parse as a statement, or suppress the reviewed comment with its documentation purpose.",
    ),
    "waste.one-line-function": (
        "A strict passthrough wrapper can still be a stable typing, dispatch, monkey-patching, or public compatibility boundary.",
        "Keep the reviewed wrapper when that boundary is intentional; otherwise inline the call.",
    ),
    "waste.unused-parameter": (
        "An unrecognized callback or protocol can require a parameter that is consumed indirectly through `locals()` or reflection.",
        "Prefix the name with `_` to declare it intentionally unused, or suppress the reviewed signature when the external protocol fixes the name.",
    ),
}


_OPTION_DESCRIPTIONS: dict[str, dict[str, str]] = {
    "dead-code.exported-but-unreferenced": {
        "entryPointPatterns": (
            "fnmatch globs over public symbol names consumed by plugin or entry-point registration the scan cannot see (e.g. handle_*)."
        ),
    },
    "design.single-implementor-protocol": {
        "externalProtocolBases": (
            "Protocol-shaped base classes whose subclasses are exempt from the single-implementor check (typing.Sized, typing.Iterable, etc.)."
        ),
        "additionalExcludedPaths": ("Project-relative glob patterns for files exempt from the rule."),
    },
    "docs.complex-branch-rationale": {
        "cyclomatic_warning": ("Public-function cyclomatic threshold above which rationale is required."),
        "cognitive_warning": ("Public-function cognitive complexity threshold above which rationale is required."),
        "private_cyclomatic_warning": ("Private-function cyclomatic threshold; private functions get more headroom."),
        "private_cognitive_warning": "Private-function cognitive complexity threshold.",
    },
    "docs.dataclass-attributes": {
        "min_fields": ("Minimum dataclass field count before an Attributes docstring is required."),
        "require_all_fields": ("When true, every dataclass field must appear in the Attributes block."),
        "allow_bullets": "When true, accept Markdown bullet lists as well as Sphinx :ivar: blocks.",
    },
    "docs.missing-class-docstring": {
        "class_dataclass_exempt": (
            "When true, @dataclass-decorated classes are exempt (rely on docs.dataclass-attributes for their docs requirement instead)."
        ),
    },
    "docs.useless-docstring": {
        "min_summary_words": ("Per-kind minimum word count for a non-useless summary line (keys: module, class, function)."),
    },
    "naming.confusing-name": {
        "confusingNames": ("Identifier suffixes flagged as low-content (Handler, Manager, Util, ...)."),
    },
    "naming.generic-function": {
        "genericFunctions": ("Function names flagged as too generic to convey intent (process, handle, run, ...)."),
    },
    "naming.boolean-prefix": {
        "acceptedBooleanNames": ("Exact boolean names accepted for external protocol, CLI, DTO, or schema contracts (ok, force, verbose, etc.)."),
    },
    "naming.module-name-mismatch": {
        "conventionalModuleNames": ("Module names exempt from the convention check (constants, exceptions, helpers, protocols, types)."),
    },
    "naming.short-variable": {
        "acceptedShortNames": ("Single-character identifiers accepted as conventional (loop counters, math axes, exception variables)."),
    },
    "security.unsanitized-markdown-interpolation": {
        "labelSanitizers": (
            "Exact call targets trusted for visible link labels. Empty is strict; "
            "html.escape and markupsafe.escape are opt-ins only after verifying "
            "the renderer because they leave Markdown link delimiters unchanged."
        ),
        "urlSanitizers": (
            "Exact call targets trusted for click targets. Defaults to urllib.parse.quote "
            "and quote_plus with delimiter-safe arguments; an empty list trusts no call."
        ),
    },
    "test-quality.magic-number-assertion": {
        "allowed_numbers": ("Integer literals accepted in test assertions without extraction (small ints and HTTP status codes by default)."),
    },
    "test-quality.extends-production-class": {
        "additionalTestBases": (
            "Exact dotted or terminal base-class names treated as test bases in addition to the built-in allowlist and *TestCase suffix convention."
        ),
    },
    "test-quality.mocking-domain-object": {
        "domain_namespaces": (
            "Dotted module prefixes considered domain code; mocking imports from these paths trips the rule. Empty by default; populate to enable."
        ),
    },
    "test-quality.test-longer-than-sut": {
        "ratio": ("Allowed test-to-SUT length ratio above which the test is flagged (default 2.0)."),
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

_BUILTIN_RULES_BY_ID: dict[str, BuiltInRule] = {entry.definition.id: entry for entry in BUILTIN_RULES}


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
