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
from gruffpy.rule.naming.hungarian_notation_rule import HungarianNotationRule
from gruffpy.rule.security._security_metadata import rule_security_metadata
from gruffpy.rule.security.sql_concatenation_rule import SqlConcatenationRule
from gruffpy.rule.security.unsanitized_markdown_interpolation_rule import (
    UnsanitizedMarkdownInterpolationRule,
)
from gruffpy.rule.sensitive_data.api_key_pattern_rule import ApiKeyPatternRule
from gruffpy.rule.sensitive_data.database_url_password_rule import DatabaseUrlPasswordRule
from gruffpy.rule.sensitive_data.gcp_service_account_key_rule import GcpServiceAccountKeyRule
from gruffpy.rule.sensitive_data.pii_test_fixture_rule import PiiTestFixtureRule
from gruffpy.rule.sensitive_data.url_credentials_rule import UrlCredentialsRule
from gruffpy.rule.test_quality.no_assertions_rule import NoAssertionsRule
from gruffpy.rule.test_quality.static_analysis_redundant_test_rule import (
    StaticAnalysisRedundantTestRule,
)
from gruffpy.rule.waste.commented_out_code_rule import CommentedOutCodeRule


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
                [
                    {"shape": fp.shape, "mitigation": fp.mitigation}
                    for fp in self.false_positive_shapes
                ],
            ),
        )
        return {key: value for key, present, value in candidates if present}


def custom_docs_for(
    definition: RuleDefinition,
    *,
    config_keys: tuple[str, ...],
) -> RuleDocs | None:
    """Resolve hand-curated docs for rules whose generated text would mislead.

    Deliberately a flat one-arm-per-rule ``match``: the branch count tracks
    the curated-docs roster, not logic depth, and the literal rule-class arms
    keep each curated entry greppable from its rule. Extracting the table
    into a dict would trade that greppability for the same line count.

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
        case UnsanitizedMarkdownInterpolationRule.ID:
            return _unsanitized_markdown_interpolation_docs(config_keys, definition.id)
        case RuntimeSysPathMutationRule.ID:
            return _runtime_sys_path_mutation_docs(config_keys)
        case ExportedButUnreferencedRule.ID:
            return _exported_but_unreferenced_docs(config_keys)
        case ApiKeyPatternRule.ID:
            return _api_key_pattern_docs(config_keys)
        case GcpServiceAccountKeyRule.ID:
            return _gcp_service_account_key_docs(config_keys)
        case UrlCredentialsRule.ID:
            return _url_credentials_docs(config_keys)
        case SingleImplementorProtocolRule.ID:
            return _single_implementor_protocol_docs(config_keys)
        case DatabaseUrlPasswordRule.ID:
            return _database_url_password_docs(config_keys, definition.id)
        case HungarianNotationRule.ID:
            return _hungarian_notation_docs(config_keys)
        case PiiTestFixtureRule.ID:
            return _pii_test_fixture_docs(config_keys)
        case NoAssertionsRule.ID:
            return _no_assertions_docs(config_keys)
        case CommentedOutCodeRule.ID:
            return _commented_out_code_docs(config_keys)
        case SqlConcatenationRule.ID:
            return _sql_concatenation_docs(config_keys, definition.id)
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
    return RuleDocs(
        rationale=(
            "isnumeric()/isdigit() accept characters int() rejects (superscript "
            '"²", fraction "½", Roman numeral "Ⅻ"), so guard-then-convert still '
            "crashes on real Unicode input; unchecked int(float(...)) raises on "
            "NaN and infinity."
        ),
        fix_guidance=(
            "Convert inside try/except ValueError (and OverflowError for "
            "floats), or gate float conversions with math.isfinite()."
        ),
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
                shape=(
                    "Input pre-validated upstream to ASCII digits before the guarded conversion."
                ),
                mitigation=(
                    "Suppress with `# gruff: disable=correctness.unsafe-numeric-coercion` "
                    "and a reason, or switch the guard to a try/except so the "
                    "intent is explicit."
                ),
            ),
        ),
    )


def _runtime_sys_path_mutation_docs(config_keys: tuple[str, ...]) -> RuleDocs:
    return RuleDocs(
        rationale=(
            "sys.path mutation at import time or inside library functions makes "
            "imports depend on execution order; insert(0, ...) shadows every "
            "later top-level import for the whole process, so one colliding "
            "filename in that directory breaks the host application."
        ),
        fix_guidance=(
            "Package the code (editable install, src layout) or set PYTHONPATH "
            "in the runner; keep unavoidable mutations inside the script's "
            '`if __name__ == "__main__":` block.'
        ),
        bad_example="`sys.path.insert(0, str(Path(__file__).parent))` at module level.",
        good_example=(
            '`if __name__ == "__main__":\n    sys.path.insert(0, ...)` inside '
            "the launching script only."
        ),
        confidence_rationale=(
            "High confidence: the receiver must be the literal sys.path "
            "attribute chain, and __main__ blocks, tests/ paths, and "
            "conftest.py are structurally exempt."
        ),
        config_keys=config_keys,
        false_positive_shapes=(
            FalsePositiveShape(
                shape=(
                    "Build, packaging, or documentation tooling scripts that "
                    "legitimately bootstrap their import path outside a "
                    "__main__ block."
                ),
                mitigation=(
                    "Move the mutation under the __main__ guard, or suppress "
                    "with `# gruff: disable=design.runtime-sys-path-mutation` "
                    "plus the reason."
                ),
            ),
        ),
    )


def _exported_but_unreferenced_docs(config_keys: tuple[str, ...]) -> RuleDocs:
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
        bad_example=(
            "`def render_legacy(...)` in __all__ and re-exported by __init__.py, "
            "with zero call sites in the project."
        ),
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
        good_example=(
            '`tokens = set(re.findall(r"\\w+", message.lower())); '
            "any(term in tokens for term in ROUTING_TERMS)`"
        ),
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
                shape=(
                    "Free-text-named values where substring matching is the "
                    "documented intent (profanity stems, language-agnostic "
                    "fragments)."
                ),
                mitigation=(
                    "Suppress with `# gruff: disable=correctness.substring-vocabulary-match` "
                    "and the reason, or rename the value to reflect its "
                    "fragment semantics."
                ),
            ),
        ),
    )


def _unsanitized_markdown_interpolation_docs(
    config_keys: tuple[str, ...],
    rule_id: str,
) -> RuleDocs:
    return RuleDocs(
        rationale=(
            "A markdown link label of `evil](https://bad.example) trick` turns "
            "`[{label}]({url})` into markdown whose first parsed link is the "
            "injected pair, redirecting the rendered target; the rule exists "
            "to catch the one interpolation site that forgot the project's "
            "sanitiser."
        ),
        fix_guidance=(
            "Escape `]`, `(`, and `)` (or percent-encode the url) in a helper "
            "and wrap every interpolated link slot in it; any wrapping call "
            "satisfies the rule."
        ),
        bad_example='`f"[{title}]({url})"` with `title`/`url` from parameters.',
        good_example='`f"[{markdown_label(title)}]({markdown_url(url)})"`',
        confidence_rationale=(
            "Medium confidence: any wrapping call is accepted as the "
            "sanitiser proxy, so unrelated calls also satisfy the rule; the "
            "gruff-py corpus sweep found zero candidate sites, so the rule "
            "ships enabled."
        ),
        config_keys=config_keys,
        security_metadata=rule_security_metadata(rule_id),
        false_positive_shapes=(
            FalsePositiveShape(
                shape=(
                    "Link slots interpolating values already constrained "
                    "upstream (enum names, validated slugs) without a "
                    "wrapping call."
                ),
                mitigation=(
                    "Wrap the value in the sanitising helper anyway (cheap "
                    "and self-documenting), or suppress with "
                    "`# gruff: disable=security.unsanitized-markdown-interpolation` "
                    "plus the constraint."
                ),
            ),
        ),
    )


def _single_implementor_protocol_docs(config_keys: tuple[str, ...]) -> RuleDocs:
    return RuleDocs(
        rationale=(
            "A Protocol or ABC with one concrete implementor adds an abstraction "
            "layer reviewers must verify without clear substitution value."
        ),
        fix_guidance=(
            "Depend on the concrete class, add another real implementor, or keep a "
            "clear external abstraction reference through an annotation or "
            "value-position check."
        ),
        bad_example=(
            "`class Renderer(Protocol): ...` with only "
            "`class HtmlRenderer(Renderer): ...` and no other `Renderer` usage."
        ),
        good_example=(
            "`Renderer` used in a factory annotation, registry value, `isinstance`, "
            "or `issubclass` check outside the implementor."
        ),
        confidence_rationale=(
            "Medium confidence: project-scoped AST evidence counts implementors "
            "plus annotation and value-position abstraction references."
        ),
        config_keys=config_keys,
    )


def _database_url_password_docs(config_keys: tuple[str, ...], rule_id: str) -> RuleDocs:
    return RuleDocs(
        rationale="Credentialed database URLs in source usually expose direct data access.",
        fix_guidance=(
            "Move real passwords to environment variables or a secret manager; use "
            "exact placeholders such as `password`, `change-me`, `dummy`, `fake`, "
            "or `redacted` only in examples."
        ),
        bad_example="A database URL literal with a real password in the userinfo segment.",
        good_example='`DATABASE_URL = "postgresql://user:change-me@host/db"`',
        confidence_rationale=(
            "High confidence: exact URL userinfo pattern with exact placeholder escapes."
        ),
        config_keys=config_keys,
        security_metadata=rule_security_metadata(rule_id),
    )


def _hungarian_notation_docs(config_keys: tuple[str, ...]) -> RuleDocs:
    return RuleDocs(
        rationale=(
            "Type prefixes duplicate information that type hints and readable names already carry."
        ),
        fix_guidance=(
            "Drop type prefixes such as `str_`, `dict_`, or `arr_`; keep semantic "
            "count names such as `num_items` or `n_samples`."
        ),
        bad_example='`str_message = "hello"` or `dict_users = {}`',
        good_example='`message = "hello"` or `num_users = len(users)`',
        confidence_rationale=(
            "High confidence: narrow type-prefix vocabulary; count abbreviations are excluded."
        ),
        config_keys=config_keys,
    )


def _pii_test_fixture_docs(config_keys: tuple[str, ...]) -> RuleDocs:
    return RuleDocs(
        rationale="Test fixtures should use placeholders, not realistic third-party PII.",
        fix_guidance=(
            "Use reserved domains such as `example.com`, `.test`, `.local`, "
            "`.invalid`, `.localhost`, or `.example`; use `555` phone placeholders "
            "and keep epoch or reset timestamps named with timestamp context."
        ),
        bad_example='`email = "jane.doe@gmail.com"` or `phone = "4158675309"`',
        good_example='`email = "admin@app.test"` or `phone = "+1-415-555-0100"`',
        confidence_rationale="Medium confidence: raw test text scan with explicit escapes.",
        config_keys=config_keys,
    )


def _no_assertions_docs(config_keys: tuple[str, ...]) -> RuleDocs:
    return RuleDocs(
        rationale="Collected tests without assertions are easy to mistake for coverage.",
        fix_guidance=(
            "Assert behaviour directly, use framework assertions, or call a clear "
            "`assert_*` helper; keep pytest fixtures and conftest support code as support."
        ),
        bad_example="`def test_saves_user(): service.save(user)`",
        good_example="`def test_saves_user(): service.save(user); assert_user_saved(user)`",
        confidence_rationale=(
            "High confidence: collected-test scope with assertion statements, "
            "framework assertions, raises/warns contexts, and `assert_*` helpers."
        ),
        config_keys=config_keys,
    )


def _commented_out_code_docs(config_keys: tuple[str, ...]) -> RuleDocs:
    return RuleDocs(
        rationale="Tombstoned source comments make reviewers ask whether dead code still matters.",
        fix_guidance=(
            "Delete commented-out source code or turn it into prose documentation; "
            "docstring examples are ignored because only tokenizer comment tokens are scanned."
        ),
        bad_example="`# old_value = compute()`",
        good_example="`# Recompute only after the cache expires.`",
        confidence_rationale=(
            "Low confidence: source-comment tokens pass a cheap code-like prefilter "
            "and parser confirmation, but prose can still resemble Python."
        ),
        config_keys=config_keys,
    )


def _sql_concatenation_docs(config_keys: tuple[str, ...], rule_id: str) -> RuleDocs:
    return RuleDocs(
        rationale="Dynamic SQL is hard to verify safely without focused sink gates.",
        fix_guidance="Use driver parameters; validate dynamic SQL structure separately.",
        bad_example='`cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")`',
        good_example="`cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))`",
        confidence_rationale="Medium confidence: keyword, constant, and SQLAlchemy gates.",
        config_keys=config_keys,
        security_metadata=rule_security_metadata(rule_id),
    )


def _ignore_directive_reason_docs(config_keys: tuple[str, ...]) -> RuleDocs:
    return RuleDocs(
        rationale=(
            "Suppression comments age badly unless they explain the local "
            "compatibility, framework, or test boundary that made the suppression acceptable."
        ),
        fix_guidance=(
            "Keep the suppression precise and add a short reason after `-`, `--`, "
            "or a second `#` comment marker."
        ),
        bad_example="`import plugin  # noqa`",
        good_example="`import plugin  # noqa: F401 - re-exported public API`",
        confidence_rationale=(
            "High confidence: the rule only matches explicit suppression comment "
            "directives parsed from Python comment tokens."
        ),
        config_keys=config_keys,
    )


def _dataclass_attributes_docs(config_keys: tuple[str, ...]) -> RuleDocs:
    return RuleDocs(
        rationale=(
            "Public dataclasses often become reporter, config, or API payload contracts; "
            "field names alone rarely explain units, nullability, or stability guarantees."
        ),
        fix_guidance=(
            "Add an `Attributes:` section, Sphinx `:ivar:` entries, or a field "
            "bullet list that explains the payload fields."
        ),
        bad_example="`@dataclass class Report: findings: tuple[str, ...]; exit_code: int`",
        good_example="`Attributes:` section documenting `findings` and `exit_code`.",
        confidence_rationale=(
            "Medium confidence: the rule is limited to public dataclasses above a "
            "configurable field-count threshold."
        ),
        config_keys=config_keys,
    )


def _complex_branch_rationale_docs(config_keys: tuple[str, ...]) -> RuleDocs:
    return RuleDocs(
        rationale=(
            "Highly branched functions are expensive to review; when they cannot be "
            "simplified, maintainers need the protocol, bug, or compatibility reason "
            "for the branch structure."
        ),
        fix_guidance=(
            "Extract the branching logic, or add a substantive docstring or nearby "
            "rationale comment explaining why the complexity remains."
        ),
        bad_example="A public parser function with many `if` branches and no docstring.",
        good_example="A complex compatibility router with a docstring naming the legacy protocol.",
        confidence_rationale=(
            "Medium confidence: the rule reuses existing complexity helpers and accepts "
            "substantive docstrings or nearby rationale comments."
        ),
        config_keys=config_keys,
    )


def _api_key_pattern_docs(config_keys: tuple[str, ...]) -> RuleDocs:
    """Return custom docs for the grouped provider-token rule."""
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
        bad_example=(
            '`GOOGLE_API_KEY = "AIza..."` or '
            '`SLACK_WEBHOOK = "https://hooks.slack.com/services/..."`'
        ),
        good_example='`GOOGLE_API_KEY = os.environ["GOOGLE_API_KEY"]`',
        confidence_rationale=(
            "High confidence: each match requires a provider-specific prefix and "
            "minimum token length, with dummy/example placeholders skipped."
        ),
        config_keys=config_keys,
    )


def _gcp_service_account_key_docs(config_keys: tuple[str, ...]) -> RuleDocs:
    """Return custom docs for committed GCP service-account JSON keys."""
    return RuleDocs(
        rationale=(
            "Google service-account JSON files combine an account identity with "
            "private-key material; committed copies usually grant fleet access."
        ),
        fix_guidance=(
            "Remove the JSON key from source history, rotate it in Google Cloud IAM, "
            "and prefer Workload Identity or a runtime secret manager."
        ),
        bad_example='`{"type": "service_account", "private_key": "<redacted PEM key>"}`',
        good_example="Load Google credentials from the runtime environment or Workload Identity.",
        confidence_rationale=(
            "High confidence: the rule requires the `service_account` type marker "
            "and private-key material in the same file, while short placeholders pass."
        ),
        config_keys=config_keys,
    )


def _url_credentials_docs(config_keys: tuple[str, ...]) -> RuleDocs:
    """Return custom docs for HTTP(S) userinfo credentials."""
    return RuleDocs(
        rationale=(
            "Inline HTTP(S) userinfo credentials are easy to miss in review and "
            "often end up copied into logs, package config, or deployment scripts."
        ),
        fix_guidance=(
            "Remove `user:password@` from the URL and pass authentication via "
            "headers, environment variables, or a secret store."
        ),
        bad_example='`REMOTE = "https://deploy:<password>@api.example.test"`',
        good_example='`REMOTE = "https://api.example.test"` plus a runtime Authorization header.',
        confidence_rationale=(
            "High confidence: the rule scopes to explicit `http(s)://user:password@` "
            "userinfo and skips common placeholder passwords."
        ),
        config_keys=config_keys,
    )


def _static_analysis_redundant_docs(config_keys: tuple[str, ...]) -> RuleDocs:
    """Return custom docs for the static-analysis-redundant-test candidate rule."""
    return RuleDocs(
        rationale=(
            "A test that asserts a class or member is declared restates a fact "
            "the parser already proves; the assertion adds no behavioural "
            "coverage beyond what static analysis gives for free."
        ),
        fix_guidance=(
            "Remove only the redundant assertion, or replace it with behavioural "
            "evidence - call the member and assert on the result."
        ),
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
                shape=(
                    "Public API or compatibility contract where runtime "
                    "existence is the behaviour under test."
                ),
                mitigation=(
                    "Keep the test when the runtime contract is intentional; "
                    "gruff reports this as a candidate, not a deletion command."
                ),
            ),
        ),
    )
