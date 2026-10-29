"""Curated documentation metadata for built-in rules (`RuleDocs` and overrides).

Split from :mod:`gruffpy.rule.catalog` to keep that module within its own
file-length rule (the `catalog_related.py` precedent): the catalog keeps the
registry wiring and generated-docs fallbacks; this module owns the `RuleDocs`
model and the hand-curated per-rule entries consumed through
``custom_docs_for``.
"""

from dataclasses import dataclass, field
from typing import Any

from gruffpy.rule.correctness.substring_vocabulary_match_rule import SubstringVocabularyMatchRule
from gruffpy.rule.correctness.unsafe_numeric_coercion_rule import UnsafeNumericCoercionRule
from gruffpy.rule.dead_code.exported_but_unreferenced_rule import ExportedButUnreferencedRule
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.design.runtime_sys_path_mutation_rule import RuntimeSysPathMutationRule
from gruffpy.rule.design.single_implementor_protocol_rule import SingleImplementorProtocolRule
from gruffpy.rule.docs.complex_branch_rationale_rule import ComplexBranchRationaleRule
from gruffpy.rule.docs.dataclass_attributes_rule import DataclassAttributesRule
from gruffpy.rule.docs.ignore_directive_reason_rule import IgnoreDirectiveReasonRule
from gruffpy.rule.naming.abbreviation_rule import AbbreviationRule
from gruffpy.rule.naming.identifier_quality_rule import IdentifierQualityRule
from gruffpy.rule.security._security_metadata import rule_security_metadata
from gruffpy.rule.security.weak_crypto_rule import WeakCryptoRule
from gruffpy.rule.sensitive_data.api_key_pattern_rule import ApiKeyPatternRule
from gruffpy.rule.sensitive_data.database_url_password_rule import DatabaseUrlPasswordRule
from gruffpy.rule.sensitive_data.gcp_service_account_key_rule import GcpServiceAccountKeyRule
from gruffpy.rule.sensitive_data.private_key_rule import PrivateKeyRule
from gruffpy.rule.sensitive_data.url_credentials_rule import UrlCredentialsRule
from gruffpy.rule.test_quality.no_assertions_rule import NoAssertionsRule
from gruffpy.rule.test_quality.static_analysis_redundant_test_rule import (
    StaticAnalysisRedundantTestRule,
)


@dataclass(frozen=True, slots=True)
class FalsePositiveShape:
    """One documented false-positive shape and its mitigation.

    Attributes:
        shape: Concise description of the false-positive pattern the rule
            catches in practice.
        mitigation: What the user can do to suppress or work around it.
    """

    shape: str
    mitigation: str


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
        option_descriptions: One-line description per public option key.
        false_positive_shapes: Documented false-positive shapes and their
            mitigations; consulted by ``list-rules <rule_id>`` explain mode.
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
    option_descriptions: dict[str, str] = field(default_factory=dict)
    false_positive_shapes: tuple[FalsePositiveShape, ...] = ()

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
        payload.update(self._optional_payload_fields())
        return payload

    def _optional_payload_fields(self) -> dict[str, Any]:
        """Collect the non-empty optional payload fields in JSON-key order.

        Driven from a table so adding a new optional field is one row and the
        cost stays linear instead of multiplicative.

        Returns:
            Optional fields keyed by their camelCase JSON name, in table order, containing only fields whose source value is truthy; tuples are copied
            to lists, dicts are copied, and false-positive shapes become shape and mitigation dicts. Empty when every optional field is empty.
        """
        candidates: tuple[tuple[str, Any, Any], ...] = (
            ("formulaProvenance", self.formula_provenance, self.formula_provenance),
            ("thresholdDirection", self.threshold_direction, self.threshold_direction),
            (
                "thresholdMetadataKeys",
                self.threshold_metadata_keys,
                list(self.threshold_metadata_keys),
            ),
            ("security", self.security_metadata, dict(self.security_metadata)),
            ("optionDescriptions", self.option_descriptions, dict(self.option_descriptions)),
            (
                "falsePositiveShapes",
                self.false_positive_shapes,
                [{"shape": fp.shape, "mitigation": fp.mitigation} for fp in self.false_positive_shapes],
            ),
        )
        return {key: value for key, present, value in candidates if present}


def custom_docs_for(
    definition: RuleDefinition,
    *,
    config_keys: tuple[str, ...],
) -> RuleDocs | None:
    """Resolve hand-curated docs for rules whose generated text would mislead.

    Deliberately a flat ``match``: literal rule-class arms keep curated entries
    greppable, while closely related rule families share branch-free dispatch
    when another arm would cross the repository complexity limit.

    Args:
        definition: Rule definition being documented.
        config_keys: Public config keys computed for the rule by the catalog.

    Returns:
        Curated ``RuleDocs`` for the rule, or ``None`` to use generated docs.
    """
    match definition.id:
        case UnsafeNumericCoercionRule.ID:
            return _unsafe_numeric_coercion_docs(config_keys)
        case SubstringVocabularyMatchRule.ID:
            return _substring_vocabulary_match_docs(config_keys)
        case WeakCryptoRule.ID:
            return _weak_crypto_docs(config_keys, definition.id)
        case RuntimeSysPathMutationRule.ID:
            return _runtime_sys_path_mutation_docs(config_keys)
        case ExportedButUnreferencedRule.ID:
            return _exported_but_unreferenced_docs(config_keys)
        case ApiKeyPatternRule.ID:
            return _api_key_pattern_docs(config_keys)
        case GcpServiceAccountKeyRule.ID:
            return _gcp_service_account_key_docs(config_keys)
        case PrivateKeyRule.ID:
            return _private_key_docs(config_keys)
        case UrlCredentialsRule.ID:
            return _url_credentials_docs(config_keys)
        case SingleImplementorProtocolRule.ID:
            return _single_implementor_protocol_docs(config_keys)
        case DatabaseUrlPasswordRule.ID:
            return _database_url_password_docs(config_keys, definition.id)
        case AbbreviationRule.ID | IdentifierQualityRule.ID:
            return _naming_rule_docs(definition.id, config_keys)
        case NoAssertionsRule.ID:
            return _no_assertions_docs(config_keys)
        case IgnoreDirectiveReasonRule.ID:
            return _ignore_directive_reason_docs(config_keys)
        case DataclassAttributesRule.ID:
            return _dataclass_attributes_docs(config_keys)
        case ComplexBranchRationaleRule.ID:
            return _complex_branch_rationale_docs(config_keys)
        case StaticAnalysisRedundantTestRule.ID:
            return _static_analysis_redundant_docs(config_keys)
    return None


def _unsafe_numeric_coercion_docs(config_keys: tuple[str, ...]) -> RuleDocs:
    """Build curated RuleDocs for UnsafeNumericCoercionRule's Unicode-digit guard and int(float(...)) shapes.

    Args:
        config_keys: Public config keys the catalog computed for the rule, stored unchanged as the returned docs' config_keys.

    Returns:
        Curated RuleDocs with one false-positive shape for input already validated upstream to ASCII digits.
    """
    return RuleDocs(
        rationale=(
            "isnumeric()/isdigit() accept characters int() rejects (superscript "
            '"²", fraction "½", Roman numeral "Ⅻ"), so guard-then-convert still '
            "crashes on real Unicode input; unchecked int(float(...)) raises on "
            "NaN and infinity."
        ),
        fix_guidance=("Convert inside try/except ValueError (and OverflowError for floats), or gate float conversions with math.isfinite()."),
        bad_example="`if x.isnumeric():\n    count = int(x)`",
        good_example=("`try:\n    count = int(x)\nexcept ValueError:\n    count = None`"),
        confidence_rationale=(
            "High confidence: exact AST shapes (guard and conversion on the "
            "same name; float() assignment feeding int()) with try/except and "
            "isfinite escapes honoured, and the float variant confined to "
            "untyped/object/Any signatures."
        ),
        config_keys=config_keys,
        false_positive_shapes=(
            FalsePositiveShape(
                shape=("Input pre-validated upstream to ASCII digits before the guarded conversion."),
                mitigation=(
                    "Suppress with `# gruff: disable=correctness.unsafe-numeric-coercion` "
                    "and a reason, or switch the guard to a try/except so the "
                    "intent is explicit."
                ),
            ),
        ),
    )


def _runtime_sys_path_mutation_docs(config_keys: tuple[str, ...]) -> RuleDocs:
    """Build curated RuleDocs for RuntimeSysPathMutationRule, including its standalone-script top-level exemption.

    Args:
        config_keys: Public config keys the catalog computed for the rule, stored unchanged as the returned docs' config_keys.

    Returns:
        Curated RuleDocs with one false-positive shape for configuration files a documentation or build tool executes, such as a Sphinx docs/conf.py.
    """
    return RuleDocs(
        rationale=(
            "sys.path mutation at import time or inside library functions makes "
            "imports depend on execution order; insert(0, ...) shadows every "
            "later top-level import for the whole process, so one colliding "
            "filename in that directory breaks the host application. A "
            "standalone script is its own host process, so a mutation at its "
            "top level is not reported; one inside a function still is."
        ),
        fix_guidance=(
            "Package the code (editable install, src layout) or set PYTHONPATH "
            "in the runner. A file that is really a standalone script may change "
            'sys.path at its top level once it has an `if __name__ == "__main__":` '
            "guard or a shebang, or lives under scripts/, bin/ or tools/."
        ),
        bad_example="`sys.path.insert(0, str(Path(__file__).parent))` at the top of an importable library module.",
        good_example="`pip install -e .`, so `from app import heuristics` resolves without touching sys.path.",
        confidence_rationale=(
            "High confidence: the receiver must be the literal sys.path "
            "attribute chain, and the top level of a standalone script (a "
            "__main__ guard, a shebang, or a scripts/, bin/ or tools/ "
            "directory), tests/ paths, and conftest.py are structurally exempt; "
            "a mutation inside a function or in a guard's else branch can run "
            "on import and still reports."
        ),
        config_keys=config_keys,
        false_positive_shapes=(
            FalsePositiveShape(
                shape=(
                    "Configuration files that a documentation or build tool executes, such as a Sphinx docs/conf.py, "
                    "bootstrapping their import path at top level without a __main__ guard or shebang."
                ),
                mitigation=("Suppress with `# gruff: disable=design.runtime-sys-path-mutation` plus the reason."),
            ),
        ),
    )


def _weak_crypto_docs(config_keys: tuple[str, ...], rule_id: str) -> RuleDocs:
    """Build curated RuleDocs for WeakCryptoRule that separates security-sensitive MD5/SHA1 use from plain digests.

    Args:
        config_keys: Public config keys the catalog computed for the rule, stored unchanged as the returned docs' config_keys.
        rule_id: Id of the matched rule, passed by custom_docs_for as definition.id and used to look up the SARIF security metadata attached to the
            docs.

    Returns:
        Curated RuleDocs carrying the rule's security metadata and three false-positive shapes: a digest_size query, a non-secret digest with
        security-sounding names, and the literal usedforsecurity=False escape.
    """
    return RuleDocs(
        rationale=(
            "MD5 and SHA1 are broken for signatures, tokens, and password "
            "material, but they remain valid for cache keys and content "
            "digests. The rule reports them only where surrounding names or "
            "arguments imply security-sensitive material, so non-security "
            "digests stay quiet without configuration."
        ),
        fix_guidance=(
            "Use a KDF (argon2, bcrypt, scrypt, pbkdf2) for passwords and "
            "SHA-256 or better for signatures and tokens. When the digest is "
            "genuinely non-security, pass the standard-library keyword "
            "`usedforsecurity=False` rather than suppressing the rule."
        ),
        bad_example="`hashlib.md5(session_token.encode()).hexdigest()`",
        good_example=(
            "`hashlib.md5(cache_key.encode(), usedforsecurity=False).hexdigest()` for a non-security digest, or a KDF for password material."
        ),
        confidence_rationale=(
            "High confidence: the call target must resolve to a literal weak "
            "algorithm, and a security-context smell in the surrounding names "
            "or arguments is required before reporting."
        ),
        config_keys=config_keys,
        security_metadata=rule_security_metadata(rule_id),
        false_positive_shapes=(
            FalsePositiveShape(
                shape="Reading `sha1().digest_size` to choose a random salt length queries a size rather than hashing security material.",
                mitigation=(
                    "No setting is needed for a no-argument MD5 or SHA1 constructor used directly for `digest_size`. "
                    "Empty constructors retained for incremental password hashing still report when enabled."
                ),
            ),
            FalsePositiveShape(
                shape=(
                    "A cache key, ETag, or content digest whose surrounding "
                    "names (token, signature, password) read as security "
                    "material even though the value is not a secret."
                ),
                mitigation=(
                    "Pass `usedforsecurity=False`, which is the standard "
                    "library's own non-security marker and suppresses the "
                    "MD5/SHA1 finding without touching rule config."
                ),
            ),
            FalsePositiveShape(
                shape=(
                    "A literal `usedforsecurity=False` on MD5 or SHA1 "
                    "suppresses the finding even when the hashed value looks "
                    "like a password. This is deliberate: the keyword is the "
                    "caller's explicit non-security declaration, and only a "
                    "literal False qualifies - True, 0, None, and dynamic "
                    "flags all keep the finding."
                ),
                mitigation=(
                    "Fast password hashing is covered separately: SHA-256 and "
                    "SHA-512 on password material still report regardless of "
                    "the keyword, because no non-security reading of that "
                    "call exists. Review `usedforsecurity=False` on MD5 in "
                    "code review rather than expecting this rule to reject it."
                ),
            ),
        ),
    )


def _exported_but_unreferenced_docs(config_keys: tuple[str, ...]) -> RuleDocs:
    """Build curated RuleDocs for ExportedButUnreferencedRule, explaining why export plumbing is not a use.

    Args:
        config_keys: Public config keys the catalog computed for the rule, stored unchanged as the returned docs' config_keys.

    Returns:
        Curated RuleDocs with one false-positive shape for public API or plugin symbols consumed outside the scan, mitigated through
        options.entryPointPatterns or the dead-code allowlists.
    """
    return RuleDocs(
        rationale=(
            "Export plumbing makes dead code look alive: a public function "
            "listed in __all__ and re-exported through __init__ has reference "
            "counters above zero while no call site exists anywhere. Audits "
            "that count exports as uses score such code clean."
        ),
        fix_guidance=(
            "Delete the symbol and its re-exports, or declare the consumer: "
            "allowlists.deadCode.symbols for one-offs, entryPointPatterns for "
            "registration conventions."
        ),
        bad_example=("`def render_legacy(...)` in __all__ and re-exported by __init__.py, with zero call sites in the project."),
        good_example="Any load of the name anywhere - call, decorator, base class, getattr string.",
        confidence_rationale=(
            "Medium confidence: the reference model is name-based rather than "
            "import-resolved (same-name symbols collapse, erring toward false "
            "negatives), and the rule only runs on full-project scans - "
            "partial scans suppress it entirely per the ADR-025 scope-honesty "
            "contract."
        ),
        config_keys=config_keys,
        false_positive_shapes=(
            FalsePositiveShape(
                shape=(
                    "Library/package public API consumed only by external "
                    "projects, or symbols loaded via entry points and plugin "
                    "registries the scan cannot see."
                ),
                mitigation=(
                    "Add the convention to options.entryPointPatterns (fnmatch "
                    "over the symbol name) or the symbol to "
                    "allowlists.deadCode.symbols; for whole public-API "
                    "modules, use allowlists.deadCode.paths."
                ),
            ),
        ),
    )


def _substring_vocabulary_match_docs(config_keys: tuple[str, ...]) -> RuleDocs:
    """Build curated RuleDocs for SubstringVocabularyMatchRule, explaining mid-word hits in free-text matching.

    Args:
        config_keys: Public config keys the catalog computed for the rule, stored unchanged as the returned docs' config_keys.

    Returns:
        Curated RuleDocs with one false-positive shape for free-text-named values where substring matching is the documented intent.
    """
    return RuleDocs(
        rationale=(
            "Substring containment over free text matches inside words - a "
            'vocabulary holding "fee"/"form"/"file" routed "coffee", '
            '"information", and "profile" to wrong deterministic answers in '
            "production copy-routing."
        ),
        fix_guidance=(
            "Tokenise the text and test set membership, or compile a "
            "word-boundary regex alternation; both keep the vocabulary but "
            "stop mid-word hits."
        ),
        bad_example="`any(term in message_lower for term in ROUTING_TERMS)`",
        good_example=('`tokens = set(re.findall(r"\\w+", message.lower())); any(term in tokens for term in ROUTING_TERMS)`'),
        confidence_rationale=(
            "Medium confidence: the scan shape is exact, but substring intent "
            "is legitimate for marker/identifier checks, so the rule fires "
            "only on parameter-derived targets whose name carries a free-text "
            "token (message, text, query, prompt, ...) and skips phrase-only "
            "vocabularies."
        ),
        config_keys=config_keys,
        false_positive_shapes=(
            FalsePositiveShape(
                shape=("Free-text-named values where substring matching is the documented intent (profanity stems, language-agnostic fragments)."),
                mitigation=(
                    "Suppress with `# gruff: disable=correctness.substring-vocabulary-match` "
                    "and the reason, or rename the value to reflect its "
                    "fragment semantics."
                ),
            ),
        ),
    )


def _single_implementor_protocol_docs(config_keys: tuple[str, ...]) -> RuleDocs:
    """Build curated RuleDocs for SingleImplementorProtocolRule on a Protocol or ABC with one concrete implementor.

    Args:
        config_keys: Public config keys the catalog computed for the rule, stored unchanged as the returned docs' config_keys.

    Returns:
        Curated RuleDocs with rationale, fix guidance, examples and confidence rationale, and no false-positive shapes.
    """
    return RuleDocs(
        rationale=(
            "A Protocol or ABC with one concrete implementor adds an abstraction layer reviewers must verify without clear substitution value."
        ),
        fix_guidance=(
            "Depend on the concrete class, add another real implementor, or keep a "
            "clear external abstraction reference through an annotation or "
            "value-position check."
        ),
        bad_example=("`class Renderer(Protocol): ...` with only `class HtmlRenderer(Renderer): ...` and no other `Renderer` usage."),
        good_example=("`Renderer` used in a factory annotation, registry value, `isinstance`, or `issubclass` check outside the implementor."),
        confidence_rationale=(
            "Medium confidence: project-scoped AST evidence counts implementors plus annotation and value-position abstraction references."
        ),
        config_keys=config_keys,
    )


def _database_url_password_docs(config_keys: tuple[str, ...], rule_id: str) -> RuleDocs:
    """Build curated RuleDocs for DatabaseUrlPasswordRule, naming placeholder passwords that examples may use.

    Args:
        config_keys: Public config keys the catalog computed for the rule, stored unchanged as the returned docs' config_keys.
        rule_id: Id of the matched rule, passed by custom_docs_for as definition.id and handed to rule_security_metadata, which has no entry for this
            id and returns an empty mapping.

    Returns:
        Curated RuleDocs with no false-positive shapes and an empty security_metadata, because rule_security_metadata has no entry for this rule id;
        the payload therefore omits the security key.
    """
    return RuleDocs(
        rationale="Credentialed database URLs in source usually expose direct data access.",
        fix_guidance=(
            "Move real passwords to environment variables or a secret manager; use "
            "exact placeholders such as `password`, `change-me`, `dummy`, `fake`, "
            "or `redacted` only in examples."
        ),
        bad_example="A database URL literal with a real password in the userinfo segment.",
        good_example='`DATABASE_URL = "postgresql://user:change-me@host/db"`',
        confidence_rationale=("High confidence: exact URL userinfo pattern with exact placeholder escapes."),
        config_keys=config_keys,
        security_metadata=rule_security_metadata(rule_id),
    )


def _naming_rule_docs(rule_id: str, config_keys: tuple[str, ...]) -> RuleDocs:
    """Dispatch one curated naming-rule card without growing catalog branching.

    Args:
        rule_id: Matched naming rule id; empty or unknown ids are never routed here.
        config_keys: Public tuning paths; empty means the rule has no user knobs.

    Returns:
        Curated documentation for the matched naming rule.
    """
    documentation_factory = {
        AbbreviationRule.ID: _abbreviation_docs,
        IdentifierQualityRule.ID: _identifier_quality_docs,
    }[rule_id]
    return documentation_factory(config_keys)


def _abbreviation_docs(config_keys: tuple[str, ...]) -> RuleDocs:
    """Explain the global project-vocabulary escape hatch without changing its seed.

    Args:
        config_keys: Per-rule tuning paths; empty because the abbreviation
            escape hatch is a global allowlist documented in prose instead.

    Returns:
        Rule guidance that separates unclear shorthand from documented domain vocabulary.
    """
    return RuleDocs(
        rationale=(
            "A curated blocklist catches shorthand that makes unfamiliar code harder "
            "to verify, while recognizing that abbreviations can be clear vocabulary "
            "inside a specific project or framework."
        ),
        fix_guidance=(
            "Rename unclear shorthand to the full domain term. When a token is "
            "intentional project vocabulary, document its meaning and add the exact "
            "token to allowlists.acceptedAbbreviations; a configured list replaces "
            "the universal seed rather than extending it."
        ),
        bad_example=("`def load_cfg(ctx): ...` uses shorthand without documenting what the configuration or context represents."),
        good_example=(
            "Use `context`, `config`, `request`, and `index`, or document exact "
            "project vocabulary with `acceptedAbbreviations: [ctx, cfg, req, idx]`."
        ),
        confidence_rationale=(
            "Medium confidence: matches come from a narrow curated token list, but "
            "tokens such as ctx, cfg, req, and idx can be idiomatic project vocabulary."
        ),
        config_keys=config_keys,
        false_positive_shapes=(
            FalsePositiveShape(
                shape=("A blocked token such as ctx, cfg, req, or idx is established project vocabulary with one documented meaning."),
                mitigation=(
                    "Add the exact token to allowlists.acceptedAbbreviations with its "
                    "project meaning; retain any universal seed values the project uses "
                    "because configured values replace the seed."
                ),
            ),
        ),
    )


def _identifier_quality_docs(config_keys: tuple[str, ...]) -> RuleDocs:
    """Explain the narrow placeholder vocabulary shown to scan users.

    Args:
        config_keys: Public tuning paths; empty means no user options exist.

    Returns:
        Rule guidance separating draft names from legitimate domain words.
    """
    return RuleDocs(
        rationale=(
            "Draft names such as temp, foo, and result1 hide the value or role a "
            "reviewer must verify; legitimate domain words such as todo do not "
            "prove unfinished work from the identifier alone."
        ),
        fix_guidance=(
            "Rename first-token or numbered placeholders for their concrete role; "
            "keep legitimate queue/domain names when they already describe the value."
        ),
        bad_example="`temp = load_tasks()` or `result1 = publish()` hides the value's role.",
        good_example=("`pending_tasks = load_tasks()` is descriptive; `todo = [...]` may be legitimate work-queue vocabulary."),
        confidence_rationale=(
            "High confidence: only reviewed first-token placeholder families and "
            "numbered base-plus-digit shapes match; exact domain words are not inferred."
        ),
        config_keys=config_keys,
    )


def _no_assertions_docs(config_keys: tuple[str, ...]) -> RuleDocs:
    """Build curated RuleDocs for NoAssertionsRule, naming the assertion forms that count in a collected test.

    Args:
        config_keys: Public config keys the catalog computed for the rule, stored unchanged as the returned docs' config_keys.

    Returns:
        Curated RuleDocs with two false-positive shapes: a matcher that raises on mismatch without an assert name, and a smoke test that passes by not
        raising.
    """
    return RuleDocs(
        rationale="Collected tests without assertions are easy to mistake for coverage.",
        fix_guidance=(
            "Assert behaviour directly, use framework assertions, or call a clear "
            "`assert_*` helper; keep pytest fixtures and conftest support code as support."
        ),
        bad_example="`def test_saves_user(): service.save(user)`",
        good_example="`def test_saves_user(): service.save(user); assert_user_saved(user)`",
        confidence_rationale=(
            "High confidence: collected-test scope with assertion statements, framework assertions, raises/warns contexts, and `assert_*` helpers."
        ),
        config_keys=config_keys,
        false_positive_shapes=(
            FalsePositiveShape(
                shape=(
                    "A test can assert through a matcher that raises on a mismatch without an `assert` name, "
                    "such as pytest's `result.stderr.fnmatch_lines([...])` in `testing/test_junitxml.py`."
                ),
                mitigation=(
                    "Call the matcher through an `assert_*` helper, or suppress the reviewed test with "
                    "`# gruff: disable=test-quality.no-assertions` and the matcher that asserts."
                ),
            ),
            FalsePositiveShape(
                shape=(
                    "A smoke test can pass by not raising, such as requests' `test_can_access_urllib3_attribute`, "
                    "whose whole body is one attribute access."
                ),
                mitigation="Assert on the value the call or access returns, or suppress the reviewed test with its does-not-raise contract.",
            ),
        ),
    )


def _ignore_directive_reason_docs(config_keys: tuple[str, ...]) -> RuleDocs:
    """Build curated RuleDocs for IgnoreDirectiveReasonRule, naming the reason markers a suppression may use.

    Args:
        config_keys: Public config keys the catalog computed for the rule, stored unchanged as the returned docs' config_keys.

    Returns:
        Curated RuleDocs with one false-positive shape for a reason written in the full-line comment above the directive rather than on the
        directive's own line.
    """
    return RuleDocs(
        rationale=(
            "Suppression comments age badly unless they explain the local "
            "compatibility, framework, or test boundary that made the suppression acceptable."
        ),
        fix_guidance=(
            "Keep the suppression precise and add a short reason after `-`, `--`, or a second `#` comment marker; "
            "an issue reference such as `mypy#4125` counts as a reason."
        ),
        bad_example="`import plugin  # noqa`",
        good_example="`import plugin  # noqa: F401 - re-exported public API`",
        confidence_rationale=(
            "High confidence: the rule only matches explicit suppression comment directives parsed from Python "
            "comment tokens, and skips a file whose header says it is generated."
        ),
        config_keys=config_keys,
        false_positive_shapes=(
            FalsePositiveShape(
                shape=(
                    "The reason can sit in a full-line comment directly above the suppressed line, as Django's "
                    "`from django.conf import SettingsReference  # NOQA` under its backwards-compatibility note, "
                    "while the rule reads only the directive's own comment."
                ),
                mitigation="Move or copy the reason onto the directive's line after `-`, `--`, or a second `#`.",
            ),
        ),
    )


def _dataclass_attributes_docs(config_keys: tuple[str, ...]) -> RuleDocs:
    """Build curated RuleDocs for DataclassAttributesRule, naming the field-documentation forms that satisfy it.

    Args:
        config_keys: Public config keys the catalog computed for the rule, stored unchanged as the returned docs' config_keys.

    Returns:
        Curated RuleDocs with rationale, fix guidance, examples and confidence rationale, and no false-positive shapes.
    """
    return RuleDocs(
        rationale=(
            "Public dataclasses often become reporter, config, or API payload contracts; "
            "field names alone rarely explain units, nullability, or stability guarantees."
        ),
        fix_guidance=("Add an `Attributes:` section, Sphinx `:ivar:` entries, or a field bullet list that explains the payload fields."),
        bad_example="`@dataclass class Report: findings: tuple[str, ...]; exit_code: int`",
        good_example="`Attributes:` section documenting `findings` and `exit_code`.",
        confidence_rationale=("Medium confidence: the rule is limited to public dataclasses above a configurable field-count threshold."),
        config_keys=config_keys,
    )


def _complex_branch_rationale_docs(config_keys: tuple[str, ...]) -> RuleDocs:
    """Build curated RuleDocs for ComplexBranchRationaleRule, asking why a highly branched function stays complex.

    Args:
        config_keys: Public config keys the catalog computed for the rule, stored unchanged as the returned docs' config_keys.

    Returns:
        Curated RuleDocs with rationale, fix guidance, examples and confidence rationale, and no false-positive shapes.
    """
    return RuleDocs(
        rationale=(
            "Highly branched functions are expensive to review; when they cannot be "
            "simplified, maintainers need the protocol, bug, or compatibility reason "
            "for the branch structure."
        ),
        fix_guidance=(
            "Extract the branching logic, or add a substantive docstring or nearby rationale comment explaining why the complexity remains."
        ),
        bad_example="A public parser function with many `if` branches and no docstring.",
        good_example="A complex compatibility router with a docstring naming the legacy protocol.",
        confidence_rationale=(
            "Medium confidence: the rule reuses existing complexity helpers and accepts substantive docstrings or nearby rationale comments."
        ),
        config_keys=config_keys,
    )


def _api_key_pattern_docs(config_keys: tuple[str, ...]) -> RuleDocs:
    """Return custom docs for the grouped provider-token rule.

    Args:
        config_keys: Public config keys the catalog computed for the rule, stored unchanged as the returned docs' config_keys.

    Returns:
        Curated RuleDocs with rationale, fix guidance, examples and confidence rationale, and no false-positive shapes.
    """
    return RuleDocs(
        rationale=(
            "Provider-prefixed API keys are high-signal credential leaks; "
            "keeping them under one rule avoids provider-specific config churn "
            "while the `vendor` metadata tells reviewers which console to rotate in."
        ),
        fix_guidance=(
            "Rotate the key with the provider, remove it from source, and load it "
            "from a secret manager or environment-specific runtime configuration."
        ),
        bad_example=('`GOOGLE_API_KEY = "AIza..."` or `SLACK_WEBHOOK = "https://hooks.slack.com/services/..."`'),
        good_example='`GOOGLE_API_KEY = os.environ["GOOGLE_API_KEY"]`',
        confidence_rationale=(
            "High confidence: each match requires a provider-specific prefix and minimum token length, with dummy/example placeholders skipped."
        ),
        config_keys=config_keys,
    )


def _gcp_service_account_key_docs(config_keys: tuple[str, ...]) -> RuleDocs:
    """Return custom docs for committed GCP service-account JSON keys.

    Args:
        config_keys: Public config keys the catalog computed for the rule, stored unchanged as the returned docs' config_keys.

    Returns:
        Curated RuleDocs with rationale, fix guidance, examples and confidence rationale, and no false-positive shapes.
    """
    return RuleDocs(
        rationale=(
            "Google service-account JSON files combine an account identity with private-key material; committed copies usually grant fleet access."
        ),
        fix_guidance=(
            "Remove the JSON key from source history, rotate it in Google Cloud IAM, and prefer Workload Identity or a runtime secret manager."
        ),
        bad_example='`{"type": "service_account", "private_key": "<redacted PEM key>"}`',
        good_example="Load Google credentials from the runtime environment or Workload Identity.",
        confidence_rationale=(
            "High confidence: the rule requires the `service_account` type marker "
            "and private-key material in the same file, while short placeholders pass."
        ),
        config_keys=config_keys,
    )


def _private_key_docs(config_keys: tuple[str, ...]) -> RuleDocs:
    """Explain which private-key headers remain reportable when this opt-in check runs.

    Args:
        config_keys: Public config keys the catalog computed for the rule, stored unchanged as the returned docs' config_keys.

    Returns:
        Curated RuleDocs with one false-positive shape for two consecutive uppercase constant assignments that hold only matching BEGIN/END markers,
        which the rule excludes.
    """
    return RuleDocs(
        rationale=(
            "Private-key headers can identify committed credentials, including incomplete or escaped key material. "
            "Two adjacent uppercase parser constants containing only matching BEGIN/END marker literals carry no key body."
        ),
        fix_guidance=(
            "Move the private key out of the repository. Rotate the key, store the new one in a secret manager, and reference it at runtime."
        ),
        bad_example="A private-key header accompanied by opaque key material in repository source.",
        good_example="Load the private key from a secret manager at runtime.",
        confidence_rationale=(
            "High confidence in the presence of a private-key header. Complete placeholder blocks and exact marker-only "
            "assignment pairs are excluded; bare headers and short opaque bodies still require review."
        ),
        config_keys=config_keys,
        false_positive_shapes=(
            FalsePositiveShape(
                shape="Two consecutive uppercase constant assignments containing only matching private-key BEGIN/END markers.",
                mitigation="The marker-only pair is excluded; opaque content between the assignments and unmatched markers still report.",
            ),
        ),
    )


def _url_credentials_docs(config_keys: tuple[str, ...]) -> RuleDocs:
    """Return custom docs for HTTP(S) userinfo credentials.

    Args:
        config_keys: Public config keys the catalog computed for the rule, stored unchanged as the returned docs' config_keys.

    Returns:
        Curated RuleDocs with rationale, fix guidance, examples and confidence rationale, and no false-positive shapes.
    """
    return RuleDocs(
        rationale=(
            "Inline HTTP(S) userinfo credentials are easy to miss in review and often end up copied into logs, package config, or deployment scripts."
        ),
        fix_guidance=("Remove `user:password@` from the URL and pass authentication via headers, environment variables, or a secret store."),
        bad_example='`REMOTE = "https://deploy:<password>@api.example.test"`',
        good_example='`REMOTE = "https://api.example.test"` plus a runtime Authorization header.',
        confidence_rationale=(
            "High confidence: the rule scopes to explicit `http(s)://user:password@` userinfo and skips common "
            "placeholder passwords and template segments such as `{}`, `%s`, or a password holding `/` or `:`."
        ),
        config_keys=config_keys,
    )


def _static_analysis_redundant_docs(config_keys: tuple[str, ...]) -> RuleDocs:
    """Return custom docs for the static-analysis-redundant-test candidate rule.

    Args:
        config_keys: Public config keys the catalog computed for the rule, stored unchanged as the returned docs' config_keys.

    Returns:
        Curated RuleDocs with one false-positive shape for a public API or compatibility contract where runtime existence is the behaviour under test.
    """
    return RuleDocs(
        rationale=(
            "A test that asserts a class or member is declared restates a fact "
            "the parser already proves; the assertion adds no behavioural "
            "coverage beyond what static analysis gives for free."
        ),
        fix_guidance=("Remove only the redundant assertion, or replace it with behavioural evidence - call the member and assert on the result."),
        bad_example="`def test_has_render(): assert hasattr(ShapeService, 'render')`",
        good_example="`def test_render(): assert ShapeService().render() == 'shape'`",
        confidence_rationale=(
            "High confidence: the rule fires only on literal references to a "
            "class declared in the same parsed file and skips every dynamic, "
            "imported, instance-bound, or private shape."
        ),
        config_keys=config_keys,
        false_positive_shapes=(
            FalsePositiveShape(
                shape=("Public API or compatibility contract where runtime existence is the behaviour under test."),
                mitigation=("Keep the test when the runtime contract is intentional; gruff reports this as a candidate, not a deletion command."),
            ),
        ),
    )
