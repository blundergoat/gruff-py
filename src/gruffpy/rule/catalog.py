"""First-party catalog for built-in rules and their documentation metadata."""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.pillar import Pillar
from gruffpy.rule.complexity.cognitive_complexity_rule import CognitiveComplexityRule
from gruffpy.rule.complexity.cyclomatic_complexity_rule import CyclomaticComplexityRule
from gruffpy.rule.complexity.halstead_volume_rule import HalsteadVolumeRule
from gruffpy.rule.complexity.maintainability_index_rule import MaintainabilityIndexRule
from gruffpy.rule.complexity.nesting_depth_rule import NestingDepthRule
from gruffpy.rule.complexity.npath_complexity_rule import NPathComplexityRule
from gruffpy.rule.dead_code.unused_private_attribute_rule import UnusedPrivateAttributeRule
from gruffpy.rule.dead_code.unused_private_function_rule import UnusedPrivateFunctionRule
from gruffpy.rule.definition import RuleDefinition
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
from gruffpy.rule.docs.todo_actionability_rule import TodoActionabilityRule
from gruffpy.rule.docs.todo_density_rule import TodoDensityRule
from gruffpy.rule.docs.useless_docstring_rule import UselessDocstringRule
from gruffpy.rule.naming.abbreviation_rule import AbbreviationRule
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
from gruffpy.rule.security._security_metadata import rule_security_metadata
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
from gruffpy.rule.security.unsafe_yaml_load_rule import UnsafeYamlLoadRule
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
    "complexity.npath": "gruff-specific AST path-counting heuristic.",
}


@dataclass(frozen=True, slots=True)
class RuleDocs:
    """Durable documentation metadata for a built-in rule.

    Attributes:
        rationale: Why the rule exists.
        fix_guidance: Human-readable remediation guidance.
        bad_example: Example code that should trigger the rule.
        good_example: Example code that should satisfy the rule.
        confidence_rationale: Why the rule has its configured confidence.
        config_keys: Public config keys accepted by the rule.
        formula_provenance: Source or calibration note for metric formulas.
        threshold_direction: Whether larger or smaller values are worse.
        threshold_metadata_keys: Metadata keys used by threshold findings.
        security_metadata: SARIF security metadata for security rules.
    """

    rationale: str
    fix_guidance: str
    bad_example: str
    good_example: str
    confidence_rationale: str
    config_keys: tuple[str, ...] = ()
    formula_provenance: str = ""
    threshold_direction: str = ""
    threshold_metadata_keys: tuple[str, ...] = ()
    security_metadata: dict[str, Any] = field(default_factory=dict)

    def to_payload(self) -> dict[str, Any]:
        """Return JSON-ready docs metadata.

        Returns:
            Documentation fields suitable for CLI and SARIF metadata.
        """
        payload: dict[str, Any] = {
            "rationale": self.rationale,
            "fixGuidance": self.fix_guidance,
            "badExample": self.bad_example,
            "goodExample": self.good_example,
            "confidenceRationale": self.confidence_rationale,
            "configKeys": list(self.config_keys),
        }
        if self.formula_provenance:
            payload["formulaProvenance"] = self.formula_provenance
        if self.threshold_direction:
            payload["thresholdDirection"] = self.threshold_direction
        if self.threshold_metadata_keys:
            payload["thresholdMetadataKeys"] = list(self.threshold_metadata_keys)
        if self.security_metadata:
            payload["security"] = dict(self.security_metadata)
        return payload


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
    custom_docs = _custom_docs_for(definition, config_keys=config_keys)
    if custom_docs is not None:
        return custom_docs
    return RuleDocs(
        rationale=_rationale_for(definition),
        fix_guidance=_fix_guidance_for(definition),
        bad_example=f"Code that triggers `{definition.id}` leaves {subject} unaddressed.",
        good_example=f"Code that satisfies `{definition.id}` makes {subject} explicit or simpler.",
        confidence_rationale=_confidence_rationale(definition.confidence),
        config_keys=config_keys,
        formula_provenance=_FORMULA_PROVENANCE.get(definition.id, ""),
        threshold_direction=_threshold_direction(definition),
        threshold_metadata_keys=_threshold_metadata_keys(definition),
        security_metadata=rule_security_metadata(definition.id),
    )


def _custom_docs_for(
    definition: RuleDefinition,
    *,
    config_keys: tuple[str, ...],
) -> RuleDocs | None:
    match definition.id:
        case IgnoreDirectiveReasonRule.ID:
            return RuleDocs(
                rationale=(
                    "Suppression comments age badly unless they explain the local "
                    "compatibility, framework, or test boundary that made the "
                    "suppression acceptable."
                ),
                fix_guidance=(
                    "Keep the suppression precise and add a short reason after "
                    "`-`, `--`, or a second `#` comment marker."
                ),
                bad_example="`import plugin  # noqa`",
                good_example="`import plugin  # noqa: F401 - re-exported public API`",
                confidence_rationale=(
                    "High confidence: the rule only matches explicit suppression "
                    "comment directives parsed from Python comment tokens."
                ),
                config_keys=config_keys,
            )
        case TodoActionabilityRule.ID:
            return RuleDocs(
                rationale=(
                    "TODO-style markers should leave enough ownership, issue, date, "
                    "or concrete action context for a later maintainer to resolve them."
                ),
                fix_guidance=(
                    "Attach an issue, owner, date, or specific imperative action, "
                    "or move the work into the tracker and remove the marker."
                ),
                bad_example="`# TODO: fix later`",
                good_example="`# TODO(#123): remove fallback after parser migration`",
                confidence_rationale=(
                    "Medium confidence: the rule uses bounded source-comment "
                    "heuristics with configurable markers and detail thresholds."
                ),
                config_keys=config_keys,
            )
        case DataclassAttributesRule.ID:
            return RuleDocs(
                rationale=(
                    "Public dataclasses often become reporter, config, or API "
                    "payload contracts; field names alone rarely explain units, "
                    "nullability, or stability guarantees."
                ),
                fix_guidance=(
                    "Add an `Attributes:` section, Sphinx `:ivar:` entries, or a "
                    "field bullet list that explains the payload fields."
                ),
                bad_example="`@dataclass class Report: findings: tuple[str, ...]; exit_code: int`",
                good_example=("`Attributes:` section documenting `findings` and `exit_code`."),
                confidence_rationale=(
                    "Medium confidence: the rule is limited to public dataclasses "
                    "above a configurable field-count threshold."
                ),
                config_keys=config_keys,
            )
        case ComplexBranchRationaleRule.ID:
            return RuleDocs(
                rationale=(
                    "Highly branched functions are expensive to review; when they "
                    "cannot be simplified, maintainers need the protocol, bug, or "
                    "compatibility reason for the branch structure."
                ),
                fix_guidance=(
                    "Extract the branching logic, or add a substantive docstring or "
                    "nearby rationale comment explaining why the complexity remains."
                ),
                bad_example="A public parser function with many `if` branches and no docstring.",
                good_example=(
                    "A complex compatibility router with a docstring naming the "
                    "legacy protocol contract."
                ),
                confidence_rationale=(
                    "Medium confidence: the rule reuses existing complexity helpers "
                    "and accepts substantive docstrings or nearby rationale comments."
                ),
                config_keys=config_keys,
            )
    return None


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
    if _has_severity_thresholds(definition.default_thresholds):
        keys.extend(("threshold", "severity"))
    else:
        keys.extend(f"thresholds.{name}" for name in definition.default_thresholds)
    keys.extend(f"options.{name}" for name in definition.default_options)
    return tuple(keys)


def _threshold_direction(definition: RuleDefinition) -> str:
    if not definition.default_thresholds:
        return ""
    return _THRESHOLD_DIRECTIONS.get(definition.id, "above")


def _threshold_metadata_keys(definition: RuleDefinition) -> tuple[str, ...]:
    if not definition.default_thresholds:
        return ()
    if _has_severity_thresholds(definition.default_thresholds) or definition.pillar in {
        Pillar.SIZE,
        Pillar.COMPLEXITY,
        Pillar.MAINTAINABILITY,
    }:
        return _STANDARD_THRESHOLD_METADATA_KEYS
    return ()


def _has_severity_thresholds(thresholds: dict[str, int | float]) -> bool:
    return set(thresholds) == {"warning", "error"}


BUILTIN_RULES: tuple[BuiltInRule, ...] = (
    _entry(CognitiveComplexityRule),
    _entry(CyclomaticComplexityRule),
    _entry(HalsteadVolumeRule),
    _entry(MaintainabilityIndexRule),
    _entry(NestingDepthRule),
    _entry(NPathComplexityRule),
    _entry(UnusedPrivateAttributeRule),
    _entry(UnusedPrivateFunctionRule),
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
    _entry(TodoActionabilityRule),
    _entry(TodoDensityRule),
    _entry(UselessDocstringRule),
    _entry(AbbreviationRule),
    _entry(BooleanPrefixRule),
    _entry(ConfusingNameRule),
    _entry(GenericFunctionRule),
    _entry(HungarianNotationRule),
    _entry(IdentifierQualityRule),
    _entry(ModuleNameMismatchRule),
    _entry(ParameterTypeNameRule),
    _entry(ShortVariableRule),
    _entry(TestNamingConsistencyRule),
    _entry(DangerousFunctionCallRule),
    _entry(DisabledSslVerificationRule),
    _entry(ErrorSuppressionRule),
    _entry(ExtractCompactUserInputRule),
    _entry(HeaderInjectionRule),
    _entry(InsecureRandomRule),
    _entry(ShellInjectionRule),
    _entry(SilentExceptRule),
    _entry(SqlConcatenationRule),
    _entry(UnsafePickleRule),
    _entry(UnsafeYamlLoadRule),
    _entry(VariableImportRule),
    _entry(WeakCryptoRule),
    _entry(ApiKeyPatternRule),
    _entry(AwsAccessKeyRule),
    _entry(DatabaseUrlPasswordRule),
    _entry(HardcodedEnvValueRule),
    _entry(HighEntropyStringRule),
    _entry(JwtTokenRule),
    _entry(PhiPatternRule),
    _entry(PiiTestFixtureRule),
    _entry(PrivateKeyRule),
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
    _entry(SutNotCalledRule),
    _entry(TautologicalTypeAssertionRule),
    _entry(TestFunctionTooLongRule),
    _entry(TestLongerThanSutRule),
    _entry(TestdoxReadabilityRule),
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
