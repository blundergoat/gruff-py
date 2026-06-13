# Rules

gruff-py `0.4.0` registers 130 rules in `RuleRegistry.defaults()`.

This file is generated from the first-party built-in rule catalog.
Run `uv run python -m gruffpy.command.rule_docs --check docs/rules.md` to verify it.

## Pillar Summary

| Pillar | Rule count | Notes |
|---|---:|---|
| `size` | 7 | File, class, function, parameter, method, and attribute size |
| `complexity` | 4 | Cyclomatic, cognitive, Halstead, and nesting |
| `maintainability` | 1 | Maintainability index rule emits under this pillar |
| `correctness` | 2 | Mechanically detectable runtime-defect shapes |
| `dead-code` | 11 | Unused and waste-oriented rules |
| `modernisation` | 1 | Python syntax and library modernisation opportunities |
| `naming` | 9 | Intent-layer names; PEP 8 case style stays with ruff |
| `documentation` | 13 | Docstring presence and quality, stale docs, TODO density, README presence |
| `security` | 35 | Heuristic AST-level dangerous patterns |
| `sensitive-data` | 11 | Secret, key, PII, and PHI patterns |
| `test-quality` | 34 | Pytest-aware test smells and project config checks |
| `design` | 2 | Project-level abstraction and runtime import-path checks |

## Rule IDs

### Size

- `size.attribute-count`
- `size.average-function-length`
- `size.class-length`
- `size.file-length`
- `size.function-length`
- `size.parameter-count`
- `size.public-method-count`

### Complexity And Maintainability

- `complexity.cognitive`
- `complexity.cyclomatic`
- `complexity.halstead-volume`
- `complexity.maintainability-index`
- `complexity.nesting-depth`

### Correctness

- `correctness.substring-vocabulary-match`
- `correctness.unsafe-numeric-coercion`

### Dead Code And Waste

- `dead-code.exported-but-unreferenced`
- `dead-code.unused-private-attribute`
- `dead-code.unused-private-function`
- `waste.commented-out-code`
- `waste.empty-class`
- `waste.empty-function`
- `waste.one-line-function`
- `waste.redundant-variable`
- `waste.unreachable-code`
- `waste.unused-import`
- `waste.unused-parameter`

### Modernisation

- `modernisation.f-string-candidate`

### Naming

- `naming.abbreviation`
- `naming.boolean-prefix`
- `naming.confusing-name`
- `naming.generic-function`
- `naming.hungarian-notation`
- `naming.identifier-quality`
- `naming.module-name-mismatch`
- `naming.short-variable`
- `naming.test-naming-consistency`

### Documentation

- `docs.complex-branch-rationale`
- `docs.dataclass-attributes`
- `docs.ignore-directive-reason`
- `docs.missing-class-docstring`
- `docs.missing-function-docstring`
- `docs.missing-module-docstring`
- `docs.missing-param-doc`
- `docs.missing-raises-doc`
- `docs.missing-readme`
- `docs.missing-return-doc`
- `docs.stale-param-doc`
- `docs.todo-density`
- `docs.useless-docstring`

### Security

- `security.cors-wildcard-with-credentials`
- `security.dangerous-function-call`
- `security.dependency-git-reference`
- `security.dependency-local-path`
- `security.dependency-url-reference`
- `security.disabled-ssl-verification`
- `security.django-mark-safe`
- `security.django-raw-sql`
- `security.error-suppression`
- `security.extract-compact-user-input`
- `security.flask-debug-enabled`
- `security.github-actions-broad-permissions`
- `security.github-actions-pull-request-target`
- `security.github-actions-remote-shell`
- `security.github-actions-secrets-in-pr`
- `security.github-actions-unpinned-action`
- `security.hardcoded-bind-all-interfaces`
- `security.hardcoded-framework-secret-key`
- `security.header-injection`
- `security.insecure-random`
- `security.insecure-temp-file`
- `security.insecure-tls-protocol`
- `security.jinja2-autoescape-off`
- `security.paramiko-no-host-key-check`
- `security.path-traversal`
- `security.shell-injection`
- `security.silent-except`
- `security.sql-concatenation`
- `security.ssrf`
- `security.unsafe-pickle`
- `security.unsafe-yaml-load`
- `security.unsanitized-markdown-interpolation`
- `security.variable-import`
- `security.weak-crypto`
- `security.xxe`

### Sensitive Data

- `sensitive-data.api-key-pattern`
- `sensitive-data.aws-access-key`
- `sensitive-data.database-url-password`
- `sensitive-data.gcp-service-account-key`
- `sensitive-data.hardcoded-env-value`
- `sensitive-data.high-entropy-string`
- `sensitive-data.jwt-token`
- `sensitive-data.phi-pattern`
- `sensitive-data.pii-test-fixture`
- `sensitive-data.private-key`
- `sensitive-data.url-credentials`

### Test Quality

- `test-quality.conditional-logic`
- `test-quality.eager-test`
- `test-quality.empty-parametrize`
- `test-quality.exception-type-only`
- `test-quality.excessive-mocking`
- `test-quality.extends-production-class`
- `test-quality.global-state-mutation`
- `test-quality.loop-assertion-without-message`
- `test-quality.loop-in-test`
- `test-quality.magic-number-assertion`
- `test-quality.mock-only-test`
- `test-quality.mock-without-expectation`
- `test-quality.mocking-domain-object`
- `test-quality.multiple-aaa-cycles`
- `test-quality.mystery-guest`
- `test-quality.naming-consistency`
- `test-quality.no-assertions`
- `test-quality.parametrize-annotation`
- `test-quality.private-reflection`
- `test-quality.pytest-coverage-source-missing`
- `test-quality.pytest-deprecations-not-fatal`
- `test-quality.pytest-strict-config-missing`
- `test-quality.repeated-structure-missing-parametrize`
- `test-quality.setup-bloat`
- `test-quality.skipped-without-reason`
- `test-quality.sleep-in-test`
- `test-quality.static-analysis-redundant-test`
- `test-quality.sut-not-called`
- `test-quality.tautological-type-assertion`
- `test-quality.test-function-too-long`
- `test-quality.test-longer-than-sut`
- `test-quality.trivial-assertion`
- `test-quality.trivial-snapshot`
- `test-quality.unused-mock`

### Design

- `design.runtime-sys-path-mutation`
- `design.single-implementor-protocol`

## Rule Details

Each rule detail includes the runtime defaults, documentation metadata, and threshold contract where applicable.

### `complexity.cognitive`

- Name: Cognitive complexity
- Pillar: `complexity`
- Tier: `v0.1`
- Default severity: `error`
- Confidence: `high`
- Default enabled: yes
- Rationale: `complexity.cognitive` protects the complexity pillar by flagging cognitive complexity before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported cognitive complexity directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Config threshold: `threshold` = `30`, `severity` = `error`
- Threshold metadata: `measuredValue`, `threshold`, `thresholdDirection`, `thresholdType`
- Threshold direction: `above`
- Bad example: Code that triggers `complexity.cognitive` leaves cognitive complexity unaddressed.
- Good example: Code that satisfies `complexity.cognitive` makes cognitive complexity explicit or simpler.

### `complexity.cyclomatic`

- Name: Cyclomatic complexity
- Pillar: `complexity`
- Tier: `v0.1`
- Default severity: `error`
- Confidence: `high`
- Default enabled: yes
- Rationale: `complexity.cyclomatic` protects the complexity pillar by flagging cyclomatic complexity before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported cyclomatic complexity directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Config threshold: `threshold` = `20`, `severity` = `error`
- Threshold metadata: `measuredValue`, `threshold`, `thresholdDirection`, `thresholdType`
- Threshold direction: `above`
- Formula provenance: Radon-aligned decision-point counting.
- Bad example: Code that triggers `complexity.cyclomatic` leaves cyclomatic complexity unaddressed.
- Good example: Code that satisfies `complexity.cyclomatic` makes cyclomatic complexity explicit or simpler.

### `complexity.halstead-volume`

- Name: Halstead volume
- Pillar: `complexity`
- Tier: `v0.1`
- Default severity: `error`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `complexity.halstead-volume` protects the complexity pillar by flagging halstead volume before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported halstead volume directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Config threshold: `threshold` = `400`, `severity` = `error`
- Threshold metadata: `measuredValue`, `threshold`, `thresholdDirection`, `thresholdType`
- Threshold direction: `above`
- Formula provenance: Radon-inspired Halstead volume with documented Python AST deltas. The dogfood rubric uses one configured threshold, `>400` at error severity; the legacy built-in fallback came from Java/PHP-tuned gruff defaults. 2026-05-18 metric-calibration on `src/` and `tests/` observed p50=4.75, p90=38.04, p99=96.0, max=283.39.
- Bad example: Code that triggers `complexity.halstead-volume` leaves halstead volume unaddressed.
- Good example: Code that satisfies `complexity.halstead-volume` makes halstead volume explicit or simpler.

### `complexity.maintainability-index`

- Name: Maintainability index
- Pillar: `maintainability`
- Tier: `v0.1`
- Default severity: `error`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `complexity.maintainability-index` protects the maintainability pillar by flagging maintainability index before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported maintainability index directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Config threshold: `threshold` = `70`, `severity` = `error`
- Threshold metadata: `measuredValue`, `threshold`, `thresholdDirection`, `thresholdType`
- Threshold direction: `below`
- Formula provenance: gruff per-function maintainability heuristic based on Halstead volume, cyclomatic complexity, and raw function lines. The dogfood rubric uses one configured threshold, `<70` at error severity; the legacy built-in fallback came from Java/PHP-tuned gruff defaults. 2026-05-18 metric-calibration on `src/` and `tests/` observed min=78.78, p50=100, p90=100, p99=100. Radon 6.0.1 ranks maintainability index 20-100 as A/very high, 10-19 as B/medium, and 0-9 as C/extremely low: https://radon.readthedocs.io/en/stable/commandline.html#the-mi-command.
- Bad example: Code that triggers `complexity.maintainability-index` leaves maintainability index unaddressed.
- Good example: Code that satisfies `complexity.maintainability-index` makes maintainability index explicit or simpler.

### `complexity.nesting-depth`

- Name: Nesting depth
- Pillar: `complexity`
- Tier: `v0.1`
- Default severity: `error`
- Confidence: `high`
- Default enabled: yes
- Rationale: `complexity.nesting-depth` protects the complexity pillar by flagging nesting depth before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported nesting depth directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Config threshold: `threshold` = `6`, `severity` = `error`
- Threshold metadata: `measuredValue`, `threshold`, `thresholdDirection`, `thresholdType`
- Threshold direction: `above`
- Bad example: Code that triggers `complexity.nesting-depth` leaves nesting depth unaddressed.
- Good example: Code that satisfies `complexity.nesting-depth` makes nesting depth explicit or simpler.

### `correctness.substring-vocabulary-match`

- Name: Substring vocabulary match
- Pillar: `correctness`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: Substring containment over free text matches inside words - a vocabulary holding "fee"/"form"/"file" routed "coffee", "information", and "profile" to wrong deterministic answers in production copy-routing.
- Fix guidance: Tokenise the text and test set membership, or compile a word-boundary regex alternation; both keep the vocabulary but stop mid-word hits.
- Confidence rationale: Medium confidence: the scan shape is exact, but substring intent is legitimate for marker/identifier checks, so the rule fires only on parameter-derived targets whose name carries a free-text token (message, text, query, prompt, ...) and skips phrase-only vocabularies.
- Bad example: `any(term in message_lower for term in ROUTING_TERMS)`
- Good example: `tokens = set(re.findall(r"\w+", message.lower())); any(term in tokens for term in ROUTING_TERMS)`

### `correctness.unsafe-numeric-coercion`

- Name: Unsafe numeric coercion
- Pillar: `correctness`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `high`
- Default enabled: yes
- Rationale: isnumeric()/isdigit() accept characters int() rejects (superscript "²", fraction "½", Roman numeral "Ⅻ"), so guard-then-convert still crashes on real Unicode input; unchecked int(float(...)) raises on NaN and infinity.
- Fix guidance: Convert inside try/except ValueError (and OverflowError for floats), or gate float conversions with math.isfinite().
- Confidence rationale: High confidence: exact AST shapes (guard and conversion on the same name; float() assignment feeding int()) with try/except and isfinite escapes honoured, and the float variant confined to untyped/object/Any signatures.
- Bad example: `if x.isnumeric():
    count = int(x)`
- Good example: `try:
    count = int(x)
except ValueError:
    count = None`

### `dead-code.exported-but-unreferenced`

- Name: Exported but unreferenced
- Pillar: `dead-code`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: Export plumbing makes dead code look alive: a public function listed in __all__ and re-exported through __init__ has reference counters above zero while no call site exists anywhere. Audits that count exports as uses score such code clean.
- Fix guidance: Delete the symbol and its re-exports, or declare the consumer: allowlists.deadCode.symbols for one-offs, entryPointPatterns for registration conventions.
- Confidence rationale: Medium confidence: the reference model is name-based rather than import-resolved (same-name symbols collapse, erring toward false negatives), and the rule only runs on full-project scans - partial scans suppress it entirely per the ADR-025 scope-honesty contract.
- Options: `entryPointPatterns` = `[]`
- Bad example: `def render_legacy(...)` in __all__ and re-exported by __init__.py, with zero call sites in the project.
- Good example: Any load of the name anywhere - call, decorator, base class, getattr string.

### `dead-code.unused-private-attribute`

- Name: Unused private attribute
- Pillar: `dead-code`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `dead-code.unused-private-attribute` protects the dead-code pillar by flagging unused private attribute before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported unused private attribute directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Bad example: Code that triggers `dead-code.unused-private-attribute` leaves unused private attribute unaddressed.
- Good example: Code that satisfies `dead-code.unused-private-attribute` makes unused private attribute explicit or simpler.

### `dead-code.unused-private-function`

- Name: Unused private function
- Pillar: `dead-code`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `dead-code.unused-private-function` protects the dead-code pillar by flagging unused private function before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported unused private function directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Bad example: Code that triggers `dead-code.unused-private-function` leaves unused private function unaddressed.
- Good example: Code that satisfies `dead-code.unused-private-function` makes unused private function explicit or simpler.

### `design.runtime-sys-path-mutation`

- Name: Runtime sys.path mutation
- Pillar: `design`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `high`
- Default enabled: yes
- Rationale: sys.path mutation at import time or inside library functions makes imports depend on execution order; insert(0, ...) shadows every later top-level import for the whole process, so one colliding filename in that directory breaks the host application.
- Fix guidance: Package the code (editable install, src layout) or set PYTHONPATH in the runner; keep unavoidable mutations inside the script's `if __name__ == "__main__":` block.
- Confidence rationale: High confidence: the receiver must be the literal sys.path attribute chain, and __main__ blocks, tests/ paths, and conftest.py are structurally exempt.
- Bad example: `sys.path.insert(0, str(Path(__file__).parent))` at module level.
- Good example: `if __name__ == "__main__":
    sys.path.insert(0, ...)` inside the launching script only.

### `design.single-implementor-protocol`

- Name: Single-implementor Protocol/ABC
- Pillar: `design`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: A Protocol or ABC with one concrete implementor adds an abstraction layer reviewers must verify without clear substitution value.
- Fix guidance: Depend on the concrete class, add another real implementor, or keep a clear external abstraction reference through an annotation or value-position check.
- Confidence rationale: Medium confidence: project-scoped AST evidence counts implementors plus annotation and value-position abstraction references.
- Options: `additionalExcludedPaths` = `[]`, `externalProtocolBases` = `['Sized', 'Iterable', 'Iterator', 'Collection', 'Container', 'Sequence', 'Mapping', 'MutableMapping', 'Callable', 'ContextManager', 'AsyncContextManager']`
- Bad example: `class Renderer(Protocol): ...` with only `class HtmlRenderer(Renderer): ...` and no other `Renderer` usage.
- Good example: `Renderer` used in a factory annotation, registry value, `isinstance`, or `issubclass` check outside the implementor.

### `docs.complex-branch-rationale`

- Name: Complex branch rationale
- Pillar: `documentation`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: Highly branched functions are expensive to review; when they cannot be simplified, maintainers need the protocol, bug, or compatibility reason for the branch structure.
- Fix guidance: Extract the branching logic, or add a substantive docstring or nearby rationale comment explaining why the complexity remains.
- Confidence rationale: Medium confidence: the rule reuses existing complexity helpers and accepts substantive docstrings or nearby rationale comments.
- Options: `cognitive_warning` = `15`, `cyclomatic_warning` = `10`, `private_cognitive_warning` = `20`, `private_cyclomatic_warning` = `15`
- Bad example: A public parser function with many `if` branches and no docstring.
- Good example: A complex compatibility router with a docstring naming the legacy protocol.

### `docs.dataclass-attributes`

- Name: Dataclass attributes
- Pillar: `documentation`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `medium`
- Default enabled: yes
- Rationale: Public dataclasses often become reporter, config, or API payload contracts; field names alone rarely explain units, nullability, or stability guarantees.
- Fix guidance: Add an `Attributes:` section, Sphinx `:ivar:` entries, or a field bullet list that explains the payload fields.
- Confidence rationale: Medium confidence: the rule is limited to public dataclasses above a configurable field-count threshold.
- Options: `allow_bullets` = `True`, `min_fields` = `3`, `require_all_fields` = `False`
- Bad example: `@dataclass class Report: findings: tuple[str, ...]; exit_code: int`
- Good example: `Attributes:` section documenting `findings` and `exit_code`.

### `docs.ignore-directive-reason`

- Name: Ignore directive reason
- Pillar: `documentation`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `high`
- Default enabled: yes
- Rationale: Suppression comments age badly unless they explain the local compatibility, framework, or test boundary that made the suppression acceptable.
- Fix guidance: Keep the suppression precise and add a short reason after `-`, `--`, or a second `#` comment marker.
- Confidence rationale: High confidence: the rule only matches explicit suppression comment directives parsed from Python comment tokens.
- Bad example: `import plugin  # noqa`
- Good example: `import plugin  # noqa: F401 - re-exported public API`

### `docs.missing-class-docstring`

- Name: Missing class docstring
- Pillar: `documentation`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `high`
- Default enabled: yes
- Rationale: `docs.missing-class-docstring` protects the documentation pillar by flagging missing class docstring before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported missing class docstring directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Options: `class_dataclass_exempt` = `False`
- Bad example: Code that triggers `docs.missing-class-docstring` leaves missing class docstring unaddressed.
- Good example: Code that satisfies `docs.missing-class-docstring` makes missing class docstring explicit or simpler.

### `docs.missing-function-docstring`

- Name: Missing function docstring
- Pillar: `documentation`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `high`
- Default enabled: yes
- Rationale: `docs.missing-function-docstring` protects the documentation pillar by flagging missing function docstring before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported missing function docstring directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Bad example: Code that triggers `docs.missing-function-docstring` leaves missing function docstring unaddressed.
- Good example: Code that satisfies `docs.missing-function-docstring` makes missing function docstring explicit or simpler.

### `docs.missing-module-docstring`

- Name: Missing module docstring
- Pillar: `documentation`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `docs.missing-module-docstring` protects the documentation pillar by flagging missing module docstring before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported missing module docstring directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Bad example: Code that triggers `docs.missing-module-docstring` leaves missing module docstring unaddressed.
- Good example: Code that satisfies `docs.missing-module-docstring` makes missing module docstring explicit or simpler.

### `docs.missing-param-doc`

- Name: Missing parameter documentation
- Pillar: `documentation`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `docs.missing-param-doc` protects the documentation pillar by flagging missing parameter documentation before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported missing parameter documentation directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Bad example: Code that triggers `docs.missing-param-doc` leaves missing parameter documentation unaddressed.
- Good example: Code that satisfies `docs.missing-param-doc` makes missing parameter documentation explicit or simpler.

### `docs.missing-raises-doc`

- Name: Missing raises documentation
- Pillar: `documentation`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `low`
- Default enabled: yes
- Rationale: `docs.missing-raises-doc` protects the documentation pillar by flagging missing raises documentation before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported missing raises documentation directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Low confidence: the rule is intentionally conservative and may need tuning.
- Bad example: Code that triggers `docs.missing-raises-doc` leaves missing raises documentation unaddressed.
- Good example: Code that satisfies `docs.missing-raises-doc` makes missing raises documentation explicit or simpler.

### `docs.missing-readme`

- Name: Missing README
- Pillar: `documentation`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `docs.missing-readme` protects the documentation pillar by flagging missing readme before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported missing readme directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Bad example: Code that triggers `docs.missing-readme` leaves missing readme unaddressed.
- Good example: Code that satisfies `docs.missing-readme` makes missing readme explicit or simpler.

### `docs.missing-return-doc`

- Name: Missing return documentation
- Pillar: `documentation`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `docs.missing-return-doc` protects the documentation pillar by flagging missing return documentation before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported missing return documentation directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Bad example: Code that triggers `docs.missing-return-doc` leaves missing return documentation unaddressed.
- Good example: Code that satisfies `docs.missing-return-doc` makes missing return documentation explicit or simpler.

### `docs.stale-param-doc`

- Name: Stale parameter documentation
- Pillar: `documentation`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `high`
- Default enabled: yes
- Rationale: `docs.stale-param-doc` protects the documentation pillar by flagging stale parameter documentation before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported stale parameter documentation directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Bad example: Code that triggers `docs.stale-param-doc` leaves stale parameter documentation unaddressed.
- Good example: Code that satisfies `docs.stale-param-doc` makes stale parameter documentation explicit or simpler.

### `docs.todo-density`

- Name: TODO density
- Pillar: `documentation`
- Tier: `v0.1`
- Default severity: `error`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `docs.todo-density` protects the documentation pillar by flagging todo density before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported todo density directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Config threshold: `threshold` = `10`, `severity` = `error`
- Threshold metadata: `measuredValue`, `threshold`, `thresholdDirection`, `thresholdType`
- Threshold direction: `above`
- Bad example: Code that triggers `docs.todo-density` leaves todo density unaddressed.
- Good example: Code that satisfies `docs.todo-density` makes todo density explicit or simpler.

### `docs.useless-docstring`

- Name: Useless docstring
- Pillar: `documentation`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `docs.useless-docstring` protects the documentation pillar by flagging useless docstring before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported useless docstring directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Options: `min_summary_words` = `{'module': 6, 'class': 4, 'function': 4}`
- Bad example: Code that triggers `docs.useless-docstring` leaves useless docstring unaddressed.
- Good example: Code that satisfies `docs.useless-docstring` makes useless docstring explicit or simpler.

### `modernisation.f-string-candidate`

- Name: F-string candidate
- Pillar: `modernisation`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `modernisation.f-string-candidate` protects the modernisation pillar by flagging f-string candidate before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported f-string candidate directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Bad example: Code that triggers `modernisation.f-string-candidate` leaves f-string candidate unaddressed.
- Good example: Code that satisfies `modernisation.f-string-candidate` makes f-string candidate explicit or simpler.

### `naming.abbreviation`

- Name: Abbreviation
- Pillar: `naming`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `naming.abbreviation` protects the naming pillar by flagging abbreviation before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported abbreviation directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Bad example: Code that triggers `naming.abbreviation` leaves abbreviation unaddressed.
- Good example: Code that satisfies `naming.abbreviation` makes abbreviation explicit or simpler.

### `naming.boolean-prefix`

- Name: Boolean prefix
- Pillar: `naming`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `naming.boolean-prefix` protects the naming pillar by flagging boolean prefix before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported boolean prefix directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Options: `acceptedBooleanNames` = `['all', 'apply', 'check', 'dev', 'enabled', 'force', 'fresh', 'harness', 'json', 'ok', 'verbose', 'yes']`
- Bad example: Code that triggers `naming.boolean-prefix` leaves boolean prefix unaddressed.
- Good example: Code that satisfies `naming.boolean-prefix` makes boolean prefix explicit or simpler.

### `naming.confusing-name`

- Name: Confusing class name
- Pillar: `naming`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `naming.confusing-name` protects the naming pillar by flagging confusing class name before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported confusing class name directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Options: `confusingNames` = `['Handler', 'Processor', 'Manager', 'Util', 'Utils', 'Helper', 'Helpers', 'Data', 'Info', 'Service', 'Stuff', 'Thing', 'Object', 'Item']`
- Bad example: Code that triggers `naming.confusing-name` leaves confusing class name unaddressed.
- Good example: Code that satisfies `naming.confusing-name` makes confusing class name explicit or simpler.

### `naming.generic-function`

- Name: Generic function name
- Pillar: `naming`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `naming.generic-function` protects the naming pillar by flagging generic function name before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported generic function name directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Options: `genericFunctions` = `['process', 'handle', 'do', 'run', 'execute', 'perform', 'apply', 'manage', 'operate']`
- Bad example: Code that triggers `naming.generic-function` leaves generic function name unaddressed.
- Good example: Code that satisfies `naming.generic-function` makes generic function name explicit or simpler.

### `naming.hungarian-notation`

- Name: Hungarian notation
- Pillar: `naming`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `high`
- Default enabled: yes
- Rationale: Type prefixes duplicate information that type hints and readable names already carry.
- Fix guidance: Drop type prefixes such as `str_`, `dict_`, or `arr_`; keep semantic count names such as `num_items` or `n_samples`.
- Confidence rationale: High confidence: narrow type-prefix vocabulary; count abbreviations are excluded.
- Bad example: `str_message = "hello"` or `dict_users = {}`
- Good example: `message = "hello"` or `num_users = len(users)`

### `naming.identifier-quality`

- Name: Identifier quality
- Pillar: `naming`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `high`
- Default enabled: yes
- Rationale: `naming.identifier-quality` protects the naming pillar by flagging identifier quality before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported identifier quality directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Bad example: Code that triggers `naming.identifier-quality` leaves identifier quality unaddressed.
- Good example: Code that satisfies `naming.identifier-quality` makes identifier quality explicit or simpler.

### `naming.module-name-mismatch`

- Name: Module name mismatch
- Pillar: `naming`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `naming.module-name-mismatch` protects the naming pillar by flagging module name mismatch before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported module name mismatch directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Options: `conventionalModuleNames` = `['constants', 'exceptions', 'helpers', 'protocols', 'types']`
- Bad example: Code that triggers `naming.module-name-mismatch` leaves module name mismatch unaddressed.
- Good example: Code that satisfies `naming.module-name-mismatch` makes module name mismatch explicit or simpler.

### `naming.short-variable`

- Name: Short variable name
- Pillar: `naming`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `low`
- Default enabled: yes
- Rationale: `naming.short-variable` protects the naming pillar by flagging short variable name before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported short variable name directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Low confidence: the rule is intentionally conservative and may need tuning.
- Options: `acceptedShortNames` = `['i', 'j', 'k', 'n', 'm', 'x', 'y', 'z', 'e', '_', 'f']`
- Bad example: Code that triggers `naming.short-variable` leaves short variable name unaddressed.
- Good example: Code that satisfies `naming.short-variable` makes short variable name explicit or simpler.

### `naming.test-naming-consistency`

- Name: Test naming consistency
- Pillar: `naming`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `naming.test-naming-consistency` protects the naming pillar by flagging test naming consistency before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported test naming consistency directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Bad example: Code that triggers `naming.test-naming-consistency` leaves test naming consistency unaddressed.
- Good example: Code that satisfies `naming.test-naming-consistency` makes test naming consistency explicit or simpler.

### `security.cors-wildcard-with-credentials`

- Name: CORS wildcard origin with credentials
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `error`
- Confidence: `high`
- Default enabled: yes
- Rationale: `security.cors-wildcard-with-credentials` protects the security pillar by flagging cors wildcard origin with credentials before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported cors wildcard origin with credentials directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Security metadata: `cwe` = `['CWE-942', 'CWE-346']`, `owasp` = `['A05:2021-Security Misconfiguration']`, `securitySeverity` = `'high'`
- Bad example: Code that triggers `security.cors-wildcard-with-credentials` leaves cors wildcard origin with credentials unaddressed.
- Good example: Code that satisfies `security.cors-wildcard-with-credentials` makes cors wildcard origin with credentials explicit or simpler.

### `security.dangerous-function-call`

- Name: Dangerous function call
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `error`
- Confidence: `high`
- Default enabled: yes
- Rationale: `security.dangerous-function-call` protects the security pillar by flagging dangerous function call before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported dangerous function call directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Bad example: Code that triggers `security.dangerous-function-call` leaves dangerous function call unaddressed.
- Good example: Code that satisfies `security.dangerous-function-call` makes dangerous function call explicit or simpler.

### `security.dependency-git-reference`

- Name: Dependency installed from Git reference
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `high`
- Default enabled: yes
- Rationale: `security.dependency-git-reference` protects the security pillar by flagging dependency installed from git reference before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported dependency installed from git reference directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Security metadata: `cwe` = `['CWE-829', 'CWE-1357']`, `owasp` = `['A08:2021-Software and Data Integrity Failures']`, `securitySeverity` = `'medium'`
- Bad example: Code that triggers `security.dependency-git-reference` leaves dependency installed from git reference unaddressed.
- Good example: Code that satisfies `security.dependency-git-reference` makes dependency installed from git reference explicit or simpler.

### `security.dependency-local-path`

- Name: Dependency installed from local path
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `high`
- Default enabled: yes
- Rationale: `security.dependency-local-path` protects the security pillar by flagging dependency installed from local path before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported dependency installed from local path directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Security metadata: `cwe` = `['CWE-829']`, `owasp` = `['A08:2021-Software and Data Integrity Failures']`, `securitySeverity` = `'medium'`
- Bad example: Code that triggers `security.dependency-local-path` leaves dependency installed from local path unaddressed.
- Good example: Code that satisfies `security.dependency-local-path` makes dependency installed from local path explicit or simpler.

### `security.dependency-url-reference`

- Name: Dependency installed from direct URL
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `high`
- Default enabled: yes
- Rationale: `security.dependency-url-reference` protects the security pillar by flagging dependency installed from direct url before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported dependency installed from direct url directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Security metadata: `cwe` = `['CWE-494', 'CWE-829']`, `owasp` = `['A08:2021-Software and Data Integrity Failures']`, `securitySeverity` = `'medium'`
- Bad example: Code that triggers `security.dependency-url-reference` leaves dependency installed from direct url unaddressed.
- Good example: Code that satisfies `security.dependency-url-reference` makes dependency installed from direct url explicit or simpler.

### `security.disabled-ssl-verification`

- Name: Disabled SSL verification
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `error`
- Confidence: `high`
- Default enabled: yes
- Rationale: `security.disabled-ssl-verification` protects the security pillar by flagging disabled ssl verification before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported disabled ssl verification directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Security metadata: `cwe` = `['CWE-295']`, `owasp` = `['A02:2021-Cryptographic Failures']`, `securitySeverity` = `'high'`
- Bad example: Code that triggers `security.disabled-ssl-verification` leaves disabled ssl verification unaddressed.
- Good example: Code that satisfies `security.disabled-ssl-verification` makes disabled ssl verification explicit or simpler.

### `security.django-mark-safe`

- Name: Django mark_safe on dynamic content
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `security.django-mark-safe` protects the security pillar by flagging django mark_safe on dynamic content before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported django mark_safe on dynamic content directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Security metadata: `cwe` = `['CWE-79']`, `owasp` = `['A03:2021-Injection']`, `securitySeverity` = `'medium'`
- Bad example: Code that triggers `security.django-mark-safe` leaves django mark_safe on dynamic content unaddressed.
- Good example: Code that satisfies `security.django-mark-safe` makes django mark_safe on dynamic content explicit or simpler.

### `security.django-raw-sql`

- Name: Django raw SQL with dynamic string
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `high`
- Default enabled: yes
- Rationale: `security.django-raw-sql` protects the security pillar by flagging django raw sql with dynamic string before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported django raw sql with dynamic string directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Security metadata: `cwe` = `['CWE-89']`, `owasp` = `['A03:2021-Injection']`, `securitySeverity` = `'high'`
- Bad example: Code that triggers `security.django-raw-sql` leaves django raw sql with dynamic string unaddressed.
- Good example: Code that satisfies `security.django-raw-sql` makes django raw sql with dynamic string explicit or simpler.

### `security.error-suppression`

- Name: Wide error suppression
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `security.error-suppression` protects the security pillar by flagging wide error suppression before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported wide error suppression directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Bad example: Code that triggers `security.error-suppression` leaves wide error suppression unaddressed.
- Good example: Code that satisfies `security.error-suppression` makes wide error suppression explicit or simpler.

### `security.extract-compact-user-input`

- Name: Splat-unpacked user input
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `security.extract-compact-user-input` protects the security pillar by flagging splat-unpacked user input before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported splat-unpacked user input directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Bad example: Code that triggers `security.extract-compact-user-input` leaves splat-unpacked user input unaddressed.
- Good example: Code that satisfies `security.extract-compact-user-input` makes splat-unpacked user input explicit or simpler.

### `security.flask-debug-enabled`

- Name: Flask debug enabled
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `error`
- Confidence: `high`
- Default enabled: yes
- Rationale: `security.flask-debug-enabled` protects the security pillar by flagging flask debug enabled before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported flask debug enabled directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Security metadata: `cwe` = `['CWE-489', 'CWE-215']`, `owasp` = `['A05:2021-Security Misconfiguration']`, `securitySeverity` = `'high'`
- Bad example: Code that triggers `security.flask-debug-enabled` leaves flask debug enabled unaddressed.
- Good example: Code that satisfies `security.flask-debug-enabled` makes flask debug enabled explicit or simpler.

### `security.github-actions-broad-permissions`

- Name: Broad GitHub Actions token permissions
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `high`
- Default enabled: yes
- Rationale: `security.github-actions-broad-permissions` protects the security pillar by flagging broad github actions token permissions before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported broad github actions token permissions directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Security metadata: `cwe` = `['CWE-272', 'CWE-732']`, `owasp` = `['A01:2021-Broken Access Control']`, `securitySeverity` = `'medium'`
- Bad example: Code that triggers `security.github-actions-broad-permissions` leaves broad github actions token permissions unaddressed.
- Good example: Code that satisfies `security.github-actions-broad-permissions` makes broad github actions token permissions explicit or simpler.

### `security.github-actions-pull-request-target`

- Name: Risky pull_request_target workflow
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `error`
- Confidence: `high`
- Default enabled: yes
- Rationale: `security.github-actions-pull-request-target` protects the security pillar by flagging risky pull_request_target workflow before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported risky pull_request_target workflow directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Security metadata: `cwe` = `['CWE-94', 'CWE-829']`, `owasp` = `['A08:2021-Software and Data Integrity Failures']`, `securitySeverity` = `'high'`
- Bad example: Code that triggers `security.github-actions-pull-request-target` leaves risky pull_request_target workflow unaddressed.
- Good example: Code that satisfies `security.github-actions-pull-request-target` makes risky pull_request_target workflow explicit or simpler.

### `security.github-actions-remote-shell`

- Name: Remote script piped into a shell in CI
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `high`
- Default enabled: yes
- Rationale: `security.github-actions-remote-shell` protects the security pillar by flagging remote script piped into a shell in ci before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported remote script piped into a shell in ci directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Security metadata: `cwe` = `['CWE-494', 'CWE-829']`, `owasp` = `['A08:2021-Software and Data Integrity Failures']`, `securitySeverity` = `'high'`
- Bad example: Code that triggers `security.github-actions-remote-shell` leaves remote script piped into a shell in ci unaddressed.
- Good example: Code that satisfies `security.github-actions-remote-shell` makes remote script piped into a shell in ci explicit or simpler.

### `security.github-actions-secrets-in-pr`

- Name: Repository secret in a PR-triggered workflow
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `security.github-actions-secrets-in-pr` protects the security pillar by flagging repository secret in a pr-triggered workflow before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported repository secret in a pr-triggered workflow directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Security metadata: `cwe` = `['CWE-200', 'CWE-522']`, `owasp` = `['A05:2021-Security Misconfiguration']`, `securitySeverity` = `'medium'`
- Bad example: Code that triggers `security.github-actions-secrets-in-pr` leaves repository secret in a pr-triggered workflow unaddressed.
- Good example: Code that satisfies `security.github-actions-secrets-in-pr` makes repository secret in a pr-triggered workflow explicit or simpler.

### `security.github-actions-unpinned-action`

- Name: Unpinned GitHub Actions reference
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `high`
- Default enabled: yes
- Rationale: `security.github-actions-unpinned-action` protects the security pillar by flagging unpinned github actions reference before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported unpinned github actions reference directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Security metadata: `cwe` = `['CWE-1357', 'CWE-829']`, `owasp` = `['A08:2021-Software and Data Integrity Failures']`, `securitySeverity` = `'medium'`
- Bad example: Code that triggers `security.github-actions-unpinned-action` leaves unpinned github actions reference unaddressed.
- Good example: Code that satisfies `security.github-actions-unpinned-action` makes unpinned github actions reference explicit or simpler.

### `security.hardcoded-bind-all-interfaces`

- Name: Hardcoded bind to all interfaces
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `security.hardcoded-bind-all-interfaces` protects the security pillar by flagging hardcoded bind to all interfaces before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported hardcoded bind to all interfaces directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Security metadata: `cwe` = `['CWE-668']`, `owasp` = `['A05:2021-Security Misconfiguration']`, `securitySeverity` = `'medium'`
- Bad example: Code that triggers `security.hardcoded-bind-all-interfaces` leaves hardcoded bind to all interfaces unaddressed.
- Good example: Code that satisfies `security.hardcoded-bind-all-interfaces` makes hardcoded bind to all interfaces explicit or simpler.

### `security.hardcoded-framework-secret-key`

- Name: Hardcoded framework SECRET_KEY
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `error`
- Confidence: `high`
- Default enabled: yes
- Rationale: `security.hardcoded-framework-secret-key` protects the security pillar by flagging hardcoded framework secret_key before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported hardcoded framework secret_key directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Security metadata: `cwe` = `['CWE-798', 'CWE-321']`, `owasp` = `['A02:2021-Cryptographic Failures']`, `securitySeverity` = `'high'`
- Bad example: Code that triggers `security.hardcoded-framework-secret-key` leaves hardcoded framework secret_key unaddressed.
- Good example: Code that satisfies `security.hardcoded-framework-secret-key` makes hardcoded framework secret_key explicit or simpler.

### `security.header-injection`

- Name: Header injection
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `security.header-injection` protects the security pillar by flagging header injection before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported header injection directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Bad example: Code that triggers `security.header-injection` leaves header injection unaddressed.
- Good example: Code that satisfies `security.header-injection` makes header injection explicit or simpler.

### `security.insecure-random`

- Name: Insecure random source
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `security.insecure-random` protects the security pillar by flagging insecure random source before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported insecure random source directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Bad example: Code that triggers `security.insecure-random` leaves insecure random source unaddressed.
- Good example: Code that satisfies `security.insecure-random` makes insecure random source explicit or simpler.

### `security.insecure-temp-file`

- Name: Insecure temporary file
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `security.insecure-temp-file` protects the security pillar by flagging insecure temporary file before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported insecure temporary file directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Security metadata: `cwe` = `['CWE-377', 'CWE-379']`, `owasp` = `['A05:2021-Security Misconfiguration']`, `securitySeverity` = `'medium'`
- Bad example: Code that triggers `security.insecure-temp-file` leaves insecure temporary file unaddressed.
- Good example: Code that satisfies `security.insecure-temp-file` makes insecure temporary file explicit or simpler.

### `security.insecure-tls-protocol`

- Name: Insecure TLS protocol
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `error`
- Confidence: `high`
- Default enabled: yes
- Rationale: `security.insecure-tls-protocol` protects the security pillar by flagging insecure tls protocol before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported insecure tls protocol directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Security metadata: `cwe` = `['CWE-326', 'CWE-327']`, `owasp` = `['A02:2021-Cryptographic Failures']`, `securitySeverity` = `'high'`
- Bad example: Code that triggers `security.insecure-tls-protocol` leaves insecure tls protocol unaddressed.
- Good example: Code that satisfies `security.insecure-tls-protocol` makes insecure tls protocol explicit or simpler.

### `security.jinja2-autoescape-off`

- Name: Jinja2 autoescape disabled
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `error`
- Confidence: `high`
- Default enabled: yes
- Rationale: `security.jinja2-autoescape-off` protects the security pillar by flagging jinja2 autoescape disabled before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported jinja2 autoescape disabled directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Security metadata: `cwe` = `['CWE-79']`, `owasp` = `['A03:2021-Injection']`, `securitySeverity` = `'high'`
- Bad example: Code that triggers `security.jinja2-autoescape-off` leaves jinja2 autoescape disabled unaddressed.
- Good example: Code that satisfies `security.jinja2-autoescape-off` makes jinja2 autoescape disabled explicit or simpler.

### `security.paramiko-no-host-key-check`

- Name: Paramiko accepts unknown host keys
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `error`
- Confidence: `high`
- Default enabled: yes
- Rationale: `security.paramiko-no-host-key-check` protects the security pillar by flagging paramiko accepts unknown host keys before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported paramiko accepts unknown host keys directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Security metadata: `cwe` = `['CWE-295', 'CWE-322']`, `owasp` = `['A07:2021-Identification and Authentication Failures']`, `securitySeverity` = `'high'`
- Bad example: Code that triggers `security.paramiko-no-host-key-check` leaves paramiko accepts unknown host keys unaddressed.
- Good example: Code that satisfies `security.paramiko-no-host-key-check` makes paramiko accepts unknown host keys explicit or simpler.

### `security.path-traversal`

- Name: Path traversal
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `error`
- Confidence: `high`
- Default enabled: yes
- Rationale: `security.path-traversal` protects the security pillar by flagging path traversal before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported path traversal directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Security metadata: `cwe` = `['CWE-22']`, `owasp` = `['A01:2021-Broken Access Control']`, `securitySeverity` = `'high'`
- Bad example: Code that triggers `security.path-traversal` leaves path traversal unaddressed.
- Good example: Code that satisfies `security.path-traversal` makes path traversal explicit or simpler.

### `security.shell-injection`

- Name: Shell injection
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `error`
- Confidence: `high`
- Default enabled: yes
- Rationale: `security.shell-injection` protects the security pillar by flagging shell injection before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported shell injection directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Bad example: Code that triggers `security.shell-injection` leaves shell injection unaddressed.
- Good example: Code that satisfies `security.shell-injection` makes shell injection explicit or simpler.

### `security.silent-except`

- Name: Silent except
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `high`
- Default enabled: yes
- Rationale: `security.silent-except` protects the security pillar by flagging silent except before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported silent except directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Bad example: Code that triggers `security.silent-except` leaves silent except unaddressed.
- Good example: Code that satisfies `security.silent-except` makes silent except explicit or simpler.

### `security.sql-concatenation`

- Name: SQL concatenation
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `medium`
- Default enabled: yes
- Rationale: Dynamic SQL is hard to verify safely without focused sink gates.
- Fix guidance: Use driver parameters; validate dynamic SQL structure separately.
- Confidence rationale: Medium confidence: keyword, constant, and SQLAlchemy gates.
- Security metadata: `cwe` = `['CWE-89']`, `owasp` = `['A03:2021-Injection']`, `securitySeverity` = `'high'`
- Bad example: `cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")`
- Good example: `cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))`

### `security.ssrf`

- Name: Server-side request forgery (SSRF)
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `error`
- Confidence: `high`
- Default enabled: yes
- Rationale: `security.ssrf` protects the security pillar by flagging server-side request forgery (ssrf) before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported server-side request forgery (ssrf) directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Security metadata: `cwe` = `['CWE-918']`, `owasp` = `['A10:2021-Server-Side Request Forgery']`, `securitySeverity` = `'high'`
- Bad example: Code that triggers `security.ssrf` leaves server-side request forgery (ssrf) unaddressed.
- Good example: Code that satisfies `security.ssrf` makes server-side request forgery (ssrf) explicit or simpler.

### `security.unsafe-pickle`

- Name: Unsafe pickle deserialisation
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `error`
- Confidence: `high`
- Default enabled: yes
- Rationale: `security.unsafe-pickle` protects the security pillar by flagging unsafe pickle deserialisation before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported unsafe pickle deserialisation directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Bad example: Code that triggers `security.unsafe-pickle` leaves unsafe pickle deserialisation unaddressed.
- Good example: Code that satisfies `security.unsafe-pickle` makes unsafe pickle deserialisation explicit or simpler.

### `security.unsafe-yaml-load`

- Name: Unsafe YAML load
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `error`
- Confidence: `high`
- Default enabled: yes
- Rationale: `security.unsafe-yaml-load` protects the security pillar by flagging unsafe yaml load before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported unsafe yaml load directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Security metadata: `cwe` = `['CWE-502']`, `owasp` = `['A08:2021-Software and Data Integrity Failures']`, `securitySeverity` = `'high'`
- Bad example: Code that triggers `security.unsafe-yaml-load` leaves unsafe yaml load unaddressed.
- Good example: Code that satisfies `security.unsafe-yaml-load` makes unsafe yaml load explicit or simpler.

### `security.unsanitized-markdown-interpolation`

- Name: Unsanitized markdown interpolation
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: A markdown link label of `evil](https://bad.example) trick` turns `[{label}]({url})` into markdown whose first parsed link is the injected pair, redirecting the rendered target; the rule exists to catch the one interpolation site that forgot the project's sanitiser.
- Fix guidance: Escape `]`, `(`, and `)` (or percent-encode the url) in a helper and wrap every interpolated link slot in it; any wrapping call satisfies the rule.
- Confidence rationale: Medium confidence: any wrapping call is accepted as the sanitiser proxy, so unrelated calls also satisfy the rule; the gruff-py corpus sweep found zero candidate sites, so the rule ships enabled.
- Bad example: `f"[{title}]({url})"` with `title`/`url` from parameters.
- Good example: `f"[{markdown_label(title)}]({markdown_url(url)})"`

### `security.variable-import`

- Name: Variable import
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `security.variable-import` protects the security pillar by flagging variable import before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported variable import directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Bad example: Code that triggers `security.variable-import` leaves variable import unaddressed.
- Good example: Code that satisfies `security.variable-import` makes variable import explicit or simpler.

### `security.weak-crypto`

- Name: Weak cryptographic hash
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `high`
- Default enabled: yes
- Rationale: `security.weak-crypto` protects the security pillar by flagging weak cryptographic hash before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported weak cryptographic hash directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Security metadata: `cwe` = `['CWE-327', 'CWE-916']`, `owasp` = `['A02:2021-Cryptographic Failures']`, `securitySeverity` = `'medium'`
- Bad example: Code that triggers `security.weak-crypto` leaves weak cryptographic hash unaddressed.
- Good example: Code that satisfies `security.weak-crypto` makes weak cryptographic hash explicit or simpler.

### `security.xxe`

- Name: XML external entity (XXE)
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `error`
- Confidence: `high`
- Default enabled: yes
- Rationale: `security.xxe` protects the security pillar by flagging xml external entity (xxe) before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported xml external entity (xxe) directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Security metadata: `cwe` = `['CWE-611', 'CWE-776']`, `owasp` = `['A05:2021-Security Misconfiguration']`, `securitySeverity` = `'high'`
- Bad example: Code that triggers `security.xxe` leaves xml external entity (xxe) unaddressed.
- Good example: Code that satisfies `security.xxe` makes xml external entity (xxe) explicit or simpler.

### `sensitive-data.api-key-pattern`

- Name: API key pattern
- Pillar: `sensitive-data`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `high`
- Default enabled: yes
- Rationale: Provider-prefixed API keys are high-signal credential leaks; keeping them under one rule avoids provider-specific config churn while the `vendor` metadata tells reviewers which console to rotate in.
- Fix guidance: Rotate the key with the provider, remove it from source, and load it from a secret manager or environment-specific runtime configuration.
- Confidence rationale: High confidence: each match requires a provider-specific prefix and minimum token length, with dummy/example placeholders skipped.
- Bad example: `GOOGLE_API_KEY = "AIza..."` or `SLACK_WEBHOOK = "https://hooks.slack.com/services/..."`
- Good example: `GOOGLE_API_KEY = os.environ["GOOGLE_API_KEY"]`

### `sensitive-data.aws-access-key`

- Name: AWS access key
- Pillar: `sensitive-data`
- Tier: `v0.1`
- Default severity: `error`
- Confidence: `high`
- Default enabled: yes
- Rationale: `sensitive-data.aws-access-key` protects the sensitive-data pillar by flagging aws access key before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported aws access key directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Bad example: Code that triggers `sensitive-data.aws-access-key` leaves aws access key unaddressed.
- Good example: Code that satisfies `sensitive-data.aws-access-key` makes aws access key explicit or simpler.

### `sensitive-data.database-url-password`

- Name: Database URL with password
- Pillar: `sensitive-data`
- Tier: `v0.1`
- Default severity: `error`
- Confidence: `high`
- Default enabled: yes
- Rationale: Credentialed database URLs in source usually expose direct data access.
- Fix guidance: Move real passwords to environment variables or a secret manager; use exact placeholders such as `password`, `change-me`, `dummy`, `fake`, or `redacted` only in examples.
- Confidence rationale: High confidence: exact URL userinfo pattern with exact placeholder escapes.
- Bad example: A database URL literal with a real password in the userinfo segment.
- Good example: `DATABASE_URL = "postgresql://user:change-me@host/db"`

### `sensitive-data.gcp-service-account-key`

- Name: GCP service-account key
- Pillar: `sensitive-data`
- Tier: `v0.1`
- Default severity: `error`
- Confidence: `high`
- Default enabled: yes
- Rationale: Google service-account JSON files combine an account identity with private-key material; committed copies usually grant fleet access.
- Fix guidance: Remove the JSON key from source history, rotate it in Google Cloud IAM, and prefer Workload Identity or a runtime secret manager.
- Confidence rationale: High confidence: the rule requires the `service_account` type marker and private-key material in the same file, while short placeholders pass.
- Bad example: `{"type": "service_account", "private_key": "<redacted PEM key>"}`
- Good example: Load Google credentials from the runtime environment or Workload Identity.

### `sensitive-data.hardcoded-env-value`

- Name: Hardcoded env-file secret
- Pillar: `sensitive-data`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `sensitive-data.hardcoded-env-value` protects the sensitive-data pillar by flagging hardcoded env-file secret before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported hardcoded env-file secret directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Bad example: Code that triggers `sensitive-data.hardcoded-env-value` leaves hardcoded env-file secret unaddressed.
- Good example: Code that satisfies `sensitive-data.hardcoded-env-value` makes hardcoded env-file secret explicit or simpler.

### `sensitive-data.high-entropy-string`

- Name: High-entropy string
- Pillar: `sensitive-data`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `low`
- Default enabled: yes
- Rationale: `sensitive-data.high-entropy-string` protects the sensitive-data pillar by flagging high-entropy string before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported high-entropy string directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Low confidence: the rule is intentionally conservative and may need tuning.
- Bad example: Code that triggers `sensitive-data.high-entropy-string` leaves high-entropy string unaddressed.
- Good example: Code that satisfies `sensitive-data.high-entropy-string` makes high-entropy string explicit or simpler.

### `sensitive-data.jwt-token`

- Name: JWT token
- Pillar: `sensitive-data`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `high`
- Default enabled: yes
- Rationale: `sensitive-data.jwt-token` protects the sensitive-data pillar by flagging jwt token before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported jwt token directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Bad example: Code that triggers `sensitive-data.jwt-token` leaves jwt token unaddressed.
- Good example: Code that satisfies `sensitive-data.jwt-token` makes jwt token explicit or simpler.

### `sensitive-data.phi-pattern`

- Name: PHI pattern
- Pillar: `sensitive-data`
- Tier: `v0.1`
- Default severity: `error`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `sensitive-data.phi-pattern` protects the sensitive-data pillar by flagging phi pattern before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported phi pattern directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Bad example: Code that triggers `sensitive-data.phi-pattern` leaves phi pattern unaddressed.
- Good example: Code that satisfies `sensitive-data.phi-pattern` makes phi pattern explicit or simpler.

### `sensitive-data.pii-test-fixture`

- Name: PII in test fixture
- Pillar: `sensitive-data`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `medium`
- Default enabled: yes
- Rationale: Test fixtures should use placeholders, not realistic third-party PII.
- Fix guidance: Use reserved domains such as `example.com`, `.test`, `.local`, `.invalid`, `.localhost`, or `.example`; use `555` phone placeholders and keep epoch or reset timestamps named with timestamp context.
- Confidence rationale: Medium confidence: raw test text scan with explicit escapes.
- Bad example: `email = "jane.doe@gmail.com"` or `phone = "4158675309"`
- Good example: `email = "admin@app.test"` or `phone = "+1-415-555-0100"`

### `sensitive-data.private-key`

- Name: Private key
- Pillar: `sensitive-data`
- Tier: `v0.1`
- Default severity: `error`
- Confidence: `high`
- Default enabled: yes
- Rationale: `sensitive-data.private-key` protects the sensitive-data pillar by flagging private key before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported private key directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Bad example: Code that triggers `sensitive-data.private-key` leaves private key unaddressed.
- Good example: Code that satisfies `sensitive-data.private-key` makes private key explicit or simpler.

### `sensitive-data.url-credentials`

- Name: URL embedded credentials
- Pillar: `sensitive-data`
- Tier: `v0.1`
- Default severity: `error`
- Confidence: `high`
- Default enabled: yes
- Rationale: Inline HTTP(S) userinfo credentials are easy to miss in review and often end up copied into logs, package config, or deployment scripts.
- Fix guidance: Remove `user:password@` from the URL and pass authentication via headers, environment variables, or a secret store.
- Confidence rationale: High confidence: the rule scopes to explicit `http(s)://user:password@` userinfo and skips common placeholder passwords.
- Bad example: `REMOTE = "https://deploy:<password>@api.example.test"`
- Good example: `REMOTE = "https://api.example.test"` plus a runtime Authorization header.

### `size.attribute-count`

- Name: Attribute count
- Pillar: `size`
- Tier: `v0.1`
- Default severity: `error`
- Confidence: `high`
- Default enabled: yes
- Rationale: `size.attribute-count` protects the size pillar by flagging attribute count before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported attribute count directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Config threshold: `threshold` = `15`, `severity` = `error`
- Threshold metadata: `measuredValue`, `threshold`, `thresholdDirection`, `thresholdType`
- Threshold direction: `above`
- Bad example: Code that triggers `size.attribute-count` leaves attribute count unaddressed.
- Good example: Code that satisfies `size.attribute-count` makes attribute count explicit or simpler.

### `size.average-function-length`

- Name: Average function length per class
- Pillar: `size`
- Tier: `v0.1`
- Default severity: `error`
- Confidence: `high`
- Default enabled: yes
- Rationale: `size.average-function-length` protects the size pillar by flagging average function length per class before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported average function length per class directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Config threshold: `threshold` = `100`, `severity` = `error`
- Threshold metadata: `measuredValue`, `threshold`, `thresholdDirection`, `thresholdType`
- Threshold direction: `above`
- Bad example: Code that triggers `size.average-function-length` leaves average function length per class unaddressed.
- Good example: Code that satisfies `size.average-function-length` makes average function length per class explicit or simpler.

### `size.class-length`

- Name: Class length
- Pillar: `size`
- Tier: `v0.1`
- Default severity: `error`
- Confidence: `high`
- Default enabled: yes
- Rationale: `size.class-length` protects the size pillar by flagging class length before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported class length directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Config threshold: `threshold` = `1000`, `severity` = `error`
- Threshold metadata: `measuredValue`, `threshold`, `thresholdDirection`, `thresholdType`
- Threshold direction: `above`
- Bad example: Code that triggers `size.class-length` leaves class length unaddressed.
- Good example: Code that satisfies `size.class-length` makes class length explicit or simpler.

### `size.file-length`

- Name: File length
- Pillar: `size`
- Tier: `v0.1`
- Default severity: `error`
- Confidence: `high`
- Default enabled: yes
- Rationale: `size.file-length` protects the size pillar by flagging file length before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported file length directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Config threshold: `threshold` = `1000`, `severity` = `error`
- Threshold metadata: `measuredValue`, `threshold`, `thresholdDirection`, `thresholdType`
- Threshold direction: `above`
- Bad example: Code that triggers `size.file-length` leaves file length unaddressed.
- Good example: Code that satisfies `size.file-length` makes file length explicit or simpler.

### `size.function-length`

- Name: Function length
- Pillar: `size`
- Tier: `v0.1`
- Default severity: `error`
- Confidence: `high`
- Default enabled: yes
- Rationale: `size.function-length` protects the size pillar by flagging function length before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported function length directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Config threshold: `threshold` = `100`, `severity` = `error`
- Threshold metadata: `measuredValue`, `threshold`, `thresholdDirection`, `thresholdType`
- Threshold direction: `above`
- Bad example: Code that triggers `size.function-length` leaves function length unaddressed.
- Good example: Code that satisfies `size.function-length` makes function length explicit or simpler.

### `size.parameter-count`

- Name: Parameter count
- Pillar: `size`
- Tier: `v0.1`
- Default severity: `error`
- Confidence: `high`
- Default enabled: yes
- Rationale: `size.parameter-count` protects the size pillar by flagging parameter count before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported parameter count directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Config threshold: `threshold` = `10`, `severity` = `error`
- Threshold metadata: `measuredValue`, `threshold`, `thresholdDirection`, `thresholdType`
- Threshold direction: `above`
- Bad example: Code that triggers `size.parameter-count` leaves parameter count unaddressed.
- Good example: Code that satisfies `size.parameter-count` makes parameter count explicit or simpler.

### `size.public-method-count`

- Name: Public method count
- Pillar: `size`
- Tier: `v0.1`
- Default severity: `error`
- Confidence: `high`
- Default enabled: yes
- Rationale: `size.public-method-count` protects the size pillar by flagging public method count before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported public method count directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Config threshold: `threshold` = `10`, `severity` = `error`
- Threshold metadata: `measuredValue`, `threshold`, `thresholdDirection`, `thresholdType`
- Threshold direction: `above`
- Bad example: Code that triggers `size.public-method-count` leaves public method count unaddressed.
- Good example: Code that satisfies `size.public-method-count` makes public method count explicit or simpler.

### `test-quality.conditional-logic`

- Name: Conditional logic in test
- Pillar: `test-quality`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `test-quality.conditional-logic` protects the test-quality pillar by flagging conditional logic in test before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported conditional logic in test directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Bad example: Code that triggers `test-quality.conditional-logic` leaves conditional logic in test unaddressed.
- Good example: Code that satisfies `test-quality.conditional-logic` makes conditional logic in test explicit or simpler.

### `test-quality.eager-test`

- Name: Eager test
- Pillar: `test-quality`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `test-quality.eager-test` protects the test-quality pillar by flagging eager test before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported eager test directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Named thresholds: `maxAssertions` = `5`
- Bad example: Code that triggers `test-quality.eager-test` leaves eager test unaddressed.
- Good example: Code that satisfies `test-quality.eager-test` makes eager test explicit or simpler.

### `test-quality.empty-parametrize`

- Name: Empty parametrize
- Pillar: `test-quality`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `high`
- Default enabled: yes
- Rationale: `test-quality.empty-parametrize` protects the test-quality pillar by flagging empty parametrize before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported empty parametrize directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Bad example: Code that triggers `test-quality.empty-parametrize` leaves empty parametrize unaddressed.
- Good example: Code that satisfies `test-quality.empty-parametrize` makes empty parametrize explicit or simpler.

### `test-quality.exception-type-only`

- Name: Exception type-only assertion
- Pillar: `test-quality`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `test-quality.exception-type-only` protects the test-quality pillar by flagging exception type-only assertion before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported exception type-only assertion directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Bad example: Code that triggers `test-quality.exception-type-only` leaves exception type-only assertion unaddressed.
- Good example: Code that satisfies `test-quality.exception-type-only` makes exception type-only assertion explicit or simpler.

### `test-quality.excessive-mocking`

- Name: Excessive mocking
- Pillar: `test-quality`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `test-quality.excessive-mocking` protects the test-quality pillar by flagging excessive mocking before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported excessive mocking directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Named thresholds: `maxMocks` = `4`
- Bad example: Code that triggers `test-quality.excessive-mocking` leaves excessive mocking unaddressed.
- Good example: Code that satisfies `test-quality.excessive-mocking` makes excessive mocking explicit or simpler.

### `test-quality.extends-production-class`

- Name: Test class extends production class
- Pillar: `test-quality`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `high`
- Default enabled: yes
- Rationale: `test-quality.extends-production-class` protects the test-quality pillar by flagging test class extends production class before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported test class extends production class directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Options: `additionalTestBases` = `[]`
- Bad example: Code that triggers `test-quality.extends-production-class` leaves test class extends production class unaddressed.
- Good example: Code that satisfies `test-quality.extends-production-class` makes test class extends production class explicit or simpler.

### `test-quality.global-state-mutation`

- Name: Global state mutation in test
- Pillar: `test-quality`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `test-quality.global-state-mutation` protects the test-quality pillar by flagging global state mutation in test before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported global state mutation in test directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Bad example: Code that triggers `test-quality.global-state-mutation` leaves global state mutation in test unaddressed.
- Good example: Code that satisfies `test-quality.global-state-mutation` makes global state mutation in test explicit or simpler.

### `test-quality.loop-assertion-without-message`

- Name: Loop assertion without message
- Pillar: `test-quality`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `test-quality.loop-assertion-without-message` protects the test-quality pillar by flagging loop assertion without message before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported loop assertion without message directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Bad example: Code that triggers `test-quality.loop-assertion-without-message` leaves loop assertion without message unaddressed.
- Good example: Code that satisfies `test-quality.loop-assertion-without-message` makes loop assertion without message explicit or simpler.

### `test-quality.loop-in-test`

- Name: Loop in test
- Pillar: `test-quality`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `test-quality.loop-in-test` protects the test-quality pillar by flagging loop in test before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported loop in test directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Bad example: Code that triggers `test-quality.loop-in-test` leaves loop in test unaddressed.
- Good example: Code that satisfies `test-quality.loop-in-test` makes loop in test explicit or simpler.

### `test-quality.magic-number-assertion`

- Name: Magic-number assertion
- Pillar: `test-quality`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `test-quality.magic-number-assertion` protects the test-quality pillar by flagging magic-number assertion before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported magic-number assertion directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Options: `allowed_numbers` = `[-1, 0, 1, 2, 3, 200, 201, 204, 301, 302, 400, 401, 403, 404, 409, 422, 429, 500, 502, 503, 504]`
- Bad example: Code that triggers `test-quality.magic-number-assertion` leaves magic-number assertion unaddressed.
- Good example: Code that satisfies `test-quality.magic-number-assertion` makes magic-number assertion explicit or simpler.

### `test-quality.mock-only-test`

- Name: Mock-only test
- Pillar: `test-quality`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `test-quality.mock-only-test` protects the test-quality pillar by flagging mock-only test before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported mock-only test directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Bad example: Code that triggers `test-quality.mock-only-test` leaves mock-only test unaddressed.
- Good example: Code that satisfies `test-quality.mock-only-test` makes mock-only test explicit or simpler.

### `test-quality.mock-without-expectation`

- Name: Mock without expectation
- Pillar: `test-quality`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `test-quality.mock-without-expectation` protects the test-quality pillar by flagging mock without expectation before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported mock without expectation directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Bad example: Code that triggers `test-quality.mock-without-expectation` leaves mock without expectation unaddressed.
- Good example: Code that satisfies `test-quality.mock-without-expectation` makes mock without expectation explicit or simpler.

### `test-quality.mocking-domain-object`

- Name: Mocking domain object
- Pillar: `test-quality`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `test-quality.mocking-domain-object` protects the test-quality pillar by flagging mocking domain object before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported mocking domain object directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Options: `domain_namespaces` = `[]`
- Bad example: Code that triggers `test-quality.mocking-domain-object` leaves mocking domain object unaddressed.
- Good example: Code that satisfies `test-quality.mocking-domain-object` makes mocking domain object explicit or simpler.

### `test-quality.multiple-aaa-cycles`

- Name: Multiple AAA cycles
- Pillar: `test-quality`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `low`
- Default enabled: yes
- Rationale: `test-quality.multiple-aaa-cycles` protects the test-quality pillar by flagging multiple aaa cycles before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported multiple aaa cycles directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Low confidence: the rule is intentionally conservative and may need tuning.
- Named thresholds: `maxCycles` = `2`
- Bad example: Code that triggers `test-quality.multiple-aaa-cycles` leaves multiple aaa cycles unaddressed.
- Good example: Code that satisfies `test-quality.multiple-aaa-cycles` makes multiple aaa cycles explicit or simpler.

### `test-quality.mystery-guest`

- Name: Mystery guest in test
- Pillar: `test-quality`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `test-quality.mystery-guest` protects the test-quality pillar by flagging mystery guest in test before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported mystery guest in test directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Bad example: Code that triggers `test-quality.mystery-guest` leaves mystery guest in test unaddressed.
- Good example: Code that satisfies `test-quality.mystery-guest` makes mystery guest in test explicit or simpler.

### `test-quality.naming-consistency`

- Name: Test-naming consistency
- Pillar: `test-quality`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `test-quality.naming-consistency` protects the test-quality pillar by flagging test-naming consistency before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported test-naming consistency directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Bad example: Code that triggers `test-quality.naming-consistency` leaves test-naming consistency unaddressed.
- Good example: Code that satisfies `test-quality.naming-consistency` makes test-naming consistency explicit or simpler.

### `test-quality.no-assertions`

- Name: Test without assertions
- Pillar: `test-quality`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `high`
- Default enabled: yes
- Rationale: Collected tests without assertions are easy to mistake for coverage.
- Fix guidance: Assert behaviour directly, use framework assertions, or call a clear `assert_*` helper; keep pytest fixtures and conftest support code as support.
- Confidence rationale: High confidence: collected-test scope with assertion statements, framework assertions, raises/warns contexts, and `assert_*` helpers.
- Bad example: `def test_saves_user(): service.save(user)`
- Good example: `def test_saves_user(): service.save(user); assert_user_saved(user)`

### `test-quality.parametrize-annotation`

- Name: Parametrize without `ids`
- Pillar: `test-quality`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `test-quality.parametrize-annotation` protects the test-quality pillar by flagging parametrize without `ids` before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported parametrize without `ids` directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Named thresholds: `maxCasesWithoutIds` = `2`
- Bad example: Code that triggers `test-quality.parametrize-annotation` leaves parametrize without `ids` unaddressed.
- Good example: Code that satisfies `test-quality.parametrize-annotation` makes parametrize without `ids` explicit or simpler.

### `test-quality.private-reflection`

- Name: Private reflection in test
- Pillar: `test-quality`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `test-quality.private-reflection` protects the test-quality pillar by flagging private reflection in test before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported private reflection in test directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Bad example: Code that triggers `test-quality.private-reflection` leaves private reflection in test unaddressed.
- Good example: Code that satisfies `test-quality.private-reflection` makes private reflection in test explicit or simpler.

### `test-quality.pytest-coverage-source-missing`

- Name: Coverage source missing
- Pillar: `test-quality`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `test-quality.pytest-coverage-source-missing` protects the test-quality pillar by flagging coverage source missing before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported coverage source missing directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Bad example: Code that triggers `test-quality.pytest-coverage-source-missing` leaves coverage source missing unaddressed.
- Good example: Code that satisfies `test-quality.pytest-coverage-source-missing` makes coverage source missing explicit or simpler.

### `test-quality.pytest-deprecations-not-fatal`

- Name: Pytest deprecations not fatal
- Pillar: `test-quality`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `test-quality.pytest-deprecations-not-fatal` protects the test-quality pillar by flagging pytest deprecations not fatal before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported pytest deprecations not fatal directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Bad example: Code that triggers `test-quality.pytest-deprecations-not-fatal` leaves pytest deprecations not fatal unaddressed.
- Good example: Code that satisfies `test-quality.pytest-deprecations-not-fatal` makes pytest deprecations not fatal explicit or simpler.

### `test-quality.pytest-strict-config-missing`

- Name: Pytest strict-config missing
- Pillar: `test-quality`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `test-quality.pytest-strict-config-missing` protects the test-quality pillar by flagging pytest strict-config missing before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported pytest strict-config missing directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Bad example: Code that triggers `test-quality.pytest-strict-config-missing` leaves pytest strict-config missing unaddressed.
- Good example: Code that satisfies `test-quality.pytest-strict-config-missing` makes pytest strict-config missing explicit or simpler.

### `test-quality.repeated-structure-missing-parametrize`

- Name: Repeated structure without parametrize
- Pillar: `test-quality`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `test-quality.repeated-structure-missing-parametrize` protects the test-quality pillar by flagging repeated structure without parametrize before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported repeated structure without parametrize directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Named thresholds: `minGroupSize` = `3`
- Bad example: Code that triggers `test-quality.repeated-structure-missing-parametrize` leaves repeated structure without parametrize unaddressed.
- Good example: Code that satisfies `test-quality.repeated-structure-missing-parametrize` makes repeated structure without parametrize explicit or simpler.

### `test-quality.setup-bloat`

- Name: Setup bloat
- Pillar: `test-quality`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `test-quality.setup-bloat` protects the test-quality pillar by flagging setup bloat before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported setup bloat directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Named thresholds: `maxSetupLines` = `30`
- Bad example: Code that triggers `test-quality.setup-bloat` leaves setup bloat unaddressed.
- Good example: Code that satisfies `test-quality.setup-bloat` makes setup bloat explicit or simpler.

### `test-quality.skipped-without-reason`

- Name: Skipped without reason
- Pillar: `test-quality`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `high`
- Default enabled: yes
- Rationale: `test-quality.skipped-without-reason` protects the test-quality pillar by flagging skipped without reason before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported skipped without reason directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Bad example: Code that triggers `test-quality.skipped-without-reason` leaves skipped without reason unaddressed.
- Good example: Code that satisfies `test-quality.skipped-without-reason` makes skipped without reason explicit or simpler.

### `test-quality.sleep-in-test`

- Name: Sleep in test
- Pillar: `test-quality`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `high`
- Default enabled: yes
- Rationale: `test-quality.sleep-in-test` protects the test-quality pillar by flagging sleep in test before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported sleep in test directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Bad example: Code that triggers `test-quality.sleep-in-test` leaves sleep in test unaddressed.
- Good example: Code that satisfies `test-quality.sleep-in-test` makes sleep in test explicit or simpler.

### `test-quality.static-analysis-redundant-test`

- Name: Static-analysis-redundant test candidate
- Pillar: `test-quality`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `high`
- Default enabled: yes
- Rationale: A test that asserts a class or member is declared restates a fact the parser already proves; the assertion adds no behavioural coverage beyond what static analysis gives for free.
- Fix guidance: Remove only the redundant assertion, or replace it with behavioural evidence - call the member and assert on the result.
- Confidence rationale: High confidence: the rule fires only on literal references to a class declared in the same parsed file and skips every dynamic, imported, instance-bound, or private shape.
- Bad example: `def test_has_render(): assert hasattr(ShapeService, 'render')`
- Good example: `def test_render(): assert ShapeService().render() == 'shape'`

### `test-quality.sut-not-called`

- Name: System under test never called
- Pillar: `test-quality`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `test-quality.sut-not-called` protects the test-quality pillar by flagging system under test never called before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported system under test never called directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Bad example: Code that triggers `test-quality.sut-not-called` leaves system under test never called unaddressed.
- Good example: Code that satisfies `test-quality.sut-not-called` makes system under test never called explicit or simpler.

### `test-quality.tautological-type-assertion`

- Name: Tautological type assertion
- Pillar: `test-quality`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `test-quality.tautological-type-assertion` protects the test-quality pillar by flagging tautological type assertion before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported tautological type assertion directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Bad example: Code that triggers `test-quality.tautological-type-assertion` leaves tautological type assertion unaddressed.
- Good example: Code that satisfies `test-quality.tautological-type-assertion` makes tautological type assertion explicit or simpler.

### `test-quality.test-function-too-long`

- Name: Test function too long
- Pillar: `test-quality`
- Tier: `v0.1`
- Default severity: `error`
- Confidence: `high`
- Default enabled: yes
- Rationale: `test-quality.test-function-too-long` protects the test-quality pillar by flagging test function too long before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported test function too long directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Config threshold: `threshold` = `100`, `severity` = `error`
- Threshold metadata: `measuredValue`, `threshold`, `thresholdDirection`, `thresholdType`
- Threshold direction: `above`
- Bad example: Code that triggers `test-quality.test-function-too-long` leaves test function too long unaddressed.
- Good example: Code that satisfies `test-quality.test-function-too-long` makes test function too long explicit or simpler.

### `test-quality.test-longer-than-sut`

- Name: Test longer than SUT
- Pillar: `test-quality`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `test-quality.test-longer-than-sut` protects the test-quality pillar by flagging test longer than sut before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported test longer than sut directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Options: `ratio` = `2.0`
- Bad example: Code that triggers `test-quality.test-longer-than-sut` leaves test longer than sut unaddressed.
- Good example: Code that satisfies `test-quality.test-longer-than-sut` makes test longer than sut explicit or simpler.

### `test-quality.trivial-assertion`

- Name: Trivial assertion
- Pillar: `test-quality`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `high`
- Default enabled: yes
- Rationale: `test-quality.trivial-assertion` protects the test-quality pillar by flagging trivial assertion before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported trivial assertion directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Bad example: Code that triggers `test-quality.trivial-assertion` leaves trivial assertion unaddressed.
- Good example: Code that satisfies `test-quality.trivial-assertion` makes trivial assertion explicit or simpler.

### `test-quality.trivial-snapshot`

- Name: Trivial snapshot assertion
- Pillar: `test-quality`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `test-quality.trivial-snapshot` protects the test-quality pillar by flagging trivial snapshot assertion before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported trivial snapshot assertion directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Bad example: Code that triggers `test-quality.trivial-snapshot` leaves trivial snapshot assertion unaddressed.
- Good example: Code that satisfies `test-quality.trivial-snapshot` makes trivial snapshot assertion explicit or simpler.

### `test-quality.unused-mock`

- Name: Unused mock
- Pillar: `test-quality`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `high`
- Default enabled: yes
- Rationale: `test-quality.unused-mock` protects the test-quality pillar by flagging unused mock before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported unused mock directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Bad example: Code that triggers `test-quality.unused-mock` leaves unused mock unaddressed.
- Good example: Code that satisfies `test-quality.unused-mock` makes unused mock explicit or simpler.

### `waste.commented-out-code`

- Name: Commented-out code
- Pillar: `dead-code`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `low`
- Default enabled: yes
- Rationale: Tombstoned source comments make reviewers ask whether dead code still matters.
- Fix guidance: Delete commented-out source code or turn it into prose documentation; docstring examples are ignored because only tokenizer comment tokens are scanned.
- Confidence rationale: Low confidence: source-comment tokens pass a cheap code-like prefilter and parser confirmation, but prose can still resemble Python.
- Bad example: `# old_value = compute()`
- Good example: `# Recompute only after the cache expires.`

### `waste.empty-class`

- Name: Empty class
- Pillar: `dead-code`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `high`
- Default enabled: yes
- Rationale: `waste.empty-class` protects the dead-code pillar by flagging empty class before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported empty class directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Bad example: Code that triggers `waste.empty-class` leaves empty class unaddressed.
- Good example: Code that satisfies `waste.empty-class` makes empty class explicit or simpler.

### `waste.empty-function`

- Name: Empty function
- Pillar: `dead-code`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `high`
- Default enabled: yes
- Rationale: `waste.empty-function` protects the dead-code pillar by flagging empty function before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported empty function directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Bad example: Code that triggers `waste.empty-function` leaves empty function unaddressed.
- Good example: Code that satisfies `waste.empty-function` makes empty function explicit or simpler.

### `waste.one-line-function`

- Name: One-line function wrapper
- Pillar: `dead-code`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `waste.one-line-function` protects the dead-code pillar by flagging one-line function wrapper before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported one-line function wrapper directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Bad example: Code that triggers `waste.one-line-function` leaves one-line function wrapper unaddressed.
- Good example: Code that satisfies `waste.one-line-function` makes one-line function wrapper explicit or simpler.

### `waste.redundant-variable`

- Name: Redundant variable
- Pillar: `dead-code`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `high`
- Default enabled: yes
- Rationale: `waste.redundant-variable` protects the dead-code pillar by flagging redundant variable before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported redundant variable directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Bad example: Code that triggers `waste.redundant-variable` leaves redundant variable unaddressed.
- Good example: Code that satisfies `waste.redundant-variable` makes redundant variable explicit or simpler.

### `waste.unreachable-code`

- Name: Unreachable code
- Pillar: `dead-code`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `high`
- Default enabled: yes
- Rationale: `waste.unreachable-code` protects the dead-code pillar by flagging unreachable code before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported unreachable code directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Bad example: Code that triggers `waste.unreachable-code` leaves unreachable code unaddressed.
- Good example: Code that satisfies `waste.unreachable-code` makes unreachable code explicit or simpler.

### `waste.unused-import`

- Name: Unused import
- Pillar: `dead-code`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `high`
- Default enabled: yes
- Rationale: `waste.unused-import` protects the dead-code pillar by flagging unused import before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported unused import directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Bad example: Code that triggers `waste.unused-import` leaves unused import unaddressed.
- Good example: Code that satisfies `waste.unused-import` makes unused import explicit or simpler.

### `waste.unused-parameter`

- Name: Unused parameter
- Pillar: `dead-code`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `waste.unused-parameter` protects the dead-code pillar by flagging unused parameter before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported unused parameter directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Bad example: Code that triggers `waste.unused-parameter` leaves unused parameter unaddressed.
- Good example: Code that satisfies `waste.unused-parameter` makes unused parameter explicit or simpler.

## Suppressing Findings

Use explicit gruff rule ids when a finding is a known false positive.
Suppressions are applied after rule execution and before scoring/reporting.

Suppress one rule on the same line:

```python
import os  # gruff: disable=waste.unused-import
```

Suppress one or more rules on the next physical line:

```python
# gruff: disable-next=security.dangerous-function-call,security.variable-import
eval(payload)
```

Suppress one or more rules for the current file:

```python
# gruff: disable-file=size.file-length
```

`# noqa` remains rule-local compatibility behavior and is not a global gruff suppression.

## Choosing Rules

Run all defaults:

```bash
gruff-py analyse src/
```

Disable a rule:

```yaml
rules:
  docs.missing-function-docstring:
    enabled: false
```

Set one threshold for a metric rule:

```yaml
rules:
  size.file-length:
    threshold: 900
    severity: error
```

Adjust a named threshold knob:

```yaml
rules:
  test-quality.eager-test:
    thresholds:
      maxAssertions: 5
```
