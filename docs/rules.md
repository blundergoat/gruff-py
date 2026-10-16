# Rules

gruff-py `0.6.0` registers 96 rules across 10 pillars in `RuleRegistry.defaults()`.

This file is generated from the first-party built-in rule catalog.
Run `uv run python -m gruffpy.command.rule_docs --check docs/rules.md` to verify it.

## Pillar Summary

| Pillar | Rule count | Notes |
|---|---:|---|
| `size` | 7 | File, class, function, parameter, method, and attribute size |
| `complexity` | 3 | Cyclomatic, cognitive, and nesting |
| `correctness` | 2 | Mechanically detectable runtime-defect shapes |
| `dead-code` | 4 | Unused and waste-oriented rules |
| `naming` | 5 | Intent-layer names; PEP 8 case style stays with ruff |
| `documentation` | 12 | Docstring presence and quality, stale docs, TODO density, README presence |
| `security` | 32 | Heuristic AST-level dangerous patterns |
| `sensitive-data` | 9 | Secret, key, PII, and PHI patterns |
| `test-quality` | 20 | Pytest-aware test smells and project config checks |
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
- `complexity.cyclomatic` (default off)
- `complexity.nesting-depth`

### Correctness

- `correctness.substring-vocabulary-match`
- `correctness.unsafe-numeric-coercion`

### Dead Code And Waste

- `dead-code.exported-but-unreferenced` (default off)
- `dead-code.unused-private-attribute`
- `waste.empty-function`
- `waste.unreachable-code`

### Naming

- `naming.abbreviation`
- `naming.generic-function`
- `naming.identifier-quality`
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

### Security

- `security.cors-wildcard-with-credentials`
- `security.dangerous-function-call` (default off)
- `security.dependency-git-reference`
- `security.dependency-local-path`
- `security.dependency-url-reference`
- `security.disabled-ssl-verification`
- `security.django-raw-sql` (default off)
- `security.error-suppression`
- `security.extract-compact-user-input`
- `security.flask-debug-enabled`
- `security.github-actions-broad-permissions`
- `security.github-actions-pull-request-target`
- `security.github-actions-remote-shell`
- `security.github-actions-secrets-in-pr` (default off)
- `security.github-actions-unpinned-action`
- `security.hardcoded-bind-all-interfaces`
- `security.hardcoded-framework-secret-key`
- `security.header-injection` (default off)
- `security.insecure-random`
- `security.insecure-temp-file`
- `security.insecure-tls-protocol`
- `security.jinja2-autoescape-off`
- `security.paramiko-no-host-key-check`
- `security.path-traversal`
- `security.shell-injection` (default off)
- `security.silent-except`
- `security.ssrf`
- `security.unsafe-pickle`
- `security.unsafe-yaml-load` (default off)
- `security.variable-import` (default off)
- `security.weak-crypto`
- `security.xxe` (default off)

### Sensitive Data

- `sensitive-data.api-key-pattern` (default off)
- `sensitive-data.aws-access-key`
- `sensitive-data.database-url-password` (default off)
- `sensitive-data.gcp-service-account-key`
- `sensitive-data.hardcoded-env-value`
- `sensitive-data.jwt-token`
- `sensitive-data.phi-pattern`
- `sensitive-data.private-key`
- `sensitive-data.url-credentials` (default off)

### Test Quality

- `test-quality.empty-parametrize`
- `test-quality.excessive-mocking`
- `test-quality.global-state-mutation`
- `test-quality.loop-assertion-without-message` (default off)
- `test-quality.mock-only-test`
- `test-quality.mocking-domain-object`
- `test-quality.naming-consistency`
- `test-quality.no-assertions` (default off)
- `test-quality.private-reflection`
- `test-quality.pytest-coverage-source-missing`
- `test-quality.pytest-deprecations-not-fatal`
- `test-quality.pytest-strict-config-missing`
- `test-quality.repeated-structure-missing-parametrize`
- `test-quality.setup-bloat`
- `test-quality.static-analysis-redundant-test`
- `test-quality.sut-not-called` (default off)
- `test-quality.test-function-too-long`
- `test-quality.test-longer-than-sut`
- `test-quality.trivial-assertion` (default off)
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
- Default enabled: no
- Rationale: `complexity.cyclomatic` protects the complexity pillar by flagging cyclomatic complexity before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported cyclomatic complexity directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Default-off reason: Remains opt-in after M14's bounded repair: 26 of 50 judged upper-band findings were worth acting on, below its 0.60 precision floor.
- Config threshold: `threshold` = `20`, `severity` = `error`
- Threshold metadata: `measuredValue`, `threshold`, `thresholdDirection`, `thresholdType`
- Threshold direction: `above`
- Formula provenance: Radon-aligned decision-point counting.
- Bad example: Code that triggers `complexity.cyclomatic` leaves cyclomatic complexity unaddressed.
- Good example: Code that satisfies `complexity.cyclomatic` makes cyclomatic complexity explicit or simpler.

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
- Common false-positive shapes:
  - Free-text-named values where substring matching is the documented intent (profanity stems, language-agnostic fragments).
    Mitigation: Suppress with `# gruff: disable=correctness.substring-vocabulary-match` and the reason, or rename the value to reflect its fragment semantics.
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
- Common false-positive shapes:
  - Input pre-validated upstream to ASCII digits before the guarded conversion.
    Mitigation: Suppress with `# gruff: disable=correctness.unsafe-numeric-coercion` and a reason, or switch the guard to a try/except so the intent is explicit.
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
- Default enabled: no
- Rationale: Export plumbing makes dead code look alive: a public function listed in __all__ and re-exported through __init__ has reference counters above zero while no call site exists anywhere. Audits that count exports as uses score such code clean.
- Fix guidance: Delete the symbol and its re-exports, or declare the consumer: allowlists.deadCode.symbols for one-offs, entryPointPatterns for registration conventions.
- Confidence rationale: Medium confidence: the reference model is name-based rather than import-resolved (same-name symbols collapse, erring toward false negatives), and the rule only runs on full-project scans - partial scans suppress it entirely per the ADR-025 scope-honesty contract.
- Options: `entryPointPatterns` = `[]`
- Common false-positive shapes:
  - Library/package public API consumed only by external projects, or symbols loaded via entry points and plugin registries the scan cannot see.
    Mitigation: Add the convention to options.entryPointPatterns (fnmatch over the symbol name) or the symbol to allowlists.deadCode.symbols; for whole public-API modules, use allowlists.deadCode.paths.
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
- Common false-positive shapes:
  - A private attribute read through `getattr`, serialization, or framework reflection has no parser-visible load.
    Mitigation: Keep an explicit read when practical, or suppress `dead-code.unused-private-attribute` with a reason at the reviewed declaration.
- Bad example: Code that triggers `dead-code.unused-private-attribute` leaves unused private attribute unaddressed.
- Good example: Code that satisfies `dead-code.unused-private-attribute` makes unused private attribute explicit or simpler.

### `design.runtime-sys-path-mutation`

- Name: Runtime sys.path mutation
- Pillar: `design`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `high`
- Default enabled: yes
- Rationale: sys.path mutation at import time or inside library functions makes imports depend on execution order; insert(0, ...) shadows every later top-level import for the whole process, so one colliding filename in that directory breaks the host application. A standalone script is its own host process, so a mutation at its top level is not reported; one inside a function still is.
- Fix guidance: Package the code (editable install, src layout) or set PYTHONPATH in the runner. A file that is really a standalone script may change sys.path at its top level once it has an `if __name__ == "__main__":` guard or a shebang, or lives under scripts/, bin/ or tools/.
- Confidence rationale: High confidence: the receiver must be the literal sys.path attribute chain, and the top level of a standalone script (a __main__ guard, a shebang, or a scripts/, bin/ or tools/ directory), tests/ paths, and conftest.py are structurally exempt; a mutation inside a function or in a guard's else branch can run on import and still reports.
- Common false-positive shapes:
  - Configuration files that a documentation or build tool executes, such as a Sphinx docs/conf.py, bootstrapping their import path at top level without a __main__ guard or shebang.
    Mitigation: Suppress with `# gruff: disable=design.runtime-sys-path-mutation` plus the reason.
- Bad example: `sys.path.insert(0, str(Path(__file__).parent))` at the top of an importable library module.
- Good example: `pip install -e .`, so `from app import heuristics` resolves without touching sys.path.

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
- Common false-positive shapes:
  - A public Protocol or ABC can have downstream implementations or consumers outside the scanned project while only one local implementation is visible.
    Mitigation: Keep the abstraction when it is an external contract; exclude the reviewed path with `options.additionalExcludedPaths` or suppress the finding with that reason.
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
- Common false-positive shapes:
  - A complex function's rationale can live in an architecture record or issue rather than in the nearby docstring or branch comment this rule inspects.
    Mitigation: Add a substantive local rationale, or tune the public/private cyclomatic and cognitive warning options to the project's documented policy.
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
- Common false-positive shapes:
  - Dataclass fields documented by an inherited schema or external generator are not visible in the class's local docstring.
    Mitigation: Add a local Attributes section, or tune `options.min_fields`, `options.require_all_fields`, and `options.allow_bullets` to match the docs policy.
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
- Fix guidance: Keep the suppression precise and add a short reason after `-`, `--`, or a second `#` comment marker; an issue reference such as `mypy#4125` counts as a reason.
- Confidence rationale: High confidence: the rule only matches explicit suppression comment directives parsed from Python comment tokens, and skips a file whose header says it is generated.
- Common false-positive shapes:
  - The reason can sit in a full-line comment directly above the suppressed line, as Django's `from django.conf import SettingsReference  # NOQA` under its backwards-compatibility note, while the rule reads only the directive's own comment.
    Mitigation: Move or copy the reason onto the directive's line after `-`, `--`, or a second `#`.
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
- Options: `everyCallable` = `False`
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
- Common false-positive shapes:
  - A generated or deliberately single-purpose production module can be documented by its package reference instead of a module docstring.
    Mitigation: Add the local module summary, exclude generated paths from analysis, or suppress the rule for the reviewed module with a reason.
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
- Options: `everyCallable` = `False`
- Common false-positive shapes:
  - An override can inherit its parameter contract from a documented interface even though its local docstring has no Args or Parameters section.
    Mitigation: Repeat the parameter contract locally, or suppress the rule on the reviewed override when inherited documentation is the project convention.
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
- Options: `everyCallable` = `False`
- Common false-positive shapes:
  - A wrapper can re-raise an exception whose contract is documented on the interface it implements rather than in its local docstring.
    Mitigation: Add a local Raises section, or suppress the rule on the reviewed wrapper when the inherited exception contract is authoritative.
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
- Common false-positive shapes:
  - A package can use `docs/index.md` or another generated landing page as its maintained entry point instead of a root README.
    Mitigation: Add a root README that points to the maintained documentation, or disable this rule for the project after documenting the alternate entry point.
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
- Options: `everyCallable` = `False`
- Common false-positive shapes:
  - An override can inherit its return contract from a documented Protocol or base class while omitting a local Returns section.
    Mitigation: Repeat the return contract locally, or suppress the rule on the reviewed override when inherited documentation is authoritative.
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
- Common false-positive shapes:
  - A planning or migration module can intentionally carry several tracked TODO markers while the work remains bounded and owned.
    Mitigation: Move the work to the issue tracker or tune this rule's `threshold` and `severity` for the reviewed planning surface.
- Bad example: Code that triggers `docs.todo-density` leaves todo density unaddressed.
- Good example: Code that satisfies `docs.todo-density` makes todo density explicit or simpler.

### `naming.abbreviation`

- Name: Abbreviation
- Pillar: `naming`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: yes
- Rationale: A curated blocklist catches shorthand that makes unfamiliar code harder to verify, while recognizing that abbreviations can be clear vocabulary inside a specific project or framework.
- Fix guidance: Rename unclear shorthand to the full domain term. When a token is intentional project vocabulary, document its meaning and add the exact token to allowlists.acceptedAbbreviations; a configured list replaces the universal seed rather than extending it.
- Confidence rationale: Medium confidence: matches come from a narrow curated token list, but tokens such as ctx, cfg, req, and idx can be idiomatic project vocabulary.
- Common false-positive shapes:
  - A blocked token such as ctx, cfg, req, or idx is established project vocabulary with one documented meaning.
    Mitigation: Add the exact token to allowlists.acceptedAbbreviations with its project meaning; retain any universal seed values the project uses because configured values replace the seed.
- Bad example: `def load_cfg(ctx): ...` uses shorthand without documenting what the configuration or context represents.
- Good example: Use `context`, `config`, `request`, and `index`, or document exact project vocabulary with `acceptedAbbreviations: [ctx, cfg, req, idx]`.

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
- Common false-positive shapes:
  - A framework hook or protocol can require a generic function name such as `run` or `handle` even when the implementation has one clear responsibility.
    Mitigation: Remove the required hook name from `options.genericFunctions` or suppress the finding at the reviewed implementation.
- Bad example: Code that triggers `naming.generic-function` leaves generic function name unaddressed.
- Good example: Code that satisfies `naming.generic-function` makes generic function name explicit or simpler.

### `naming.identifier-quality`

- Name: Identifier quality
- Pillar: `naming`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `high`
- Default enabled: yes
- Rationale: Draft names such as temp, foo, and result1 hide the value or role a reviewer must verify; legitimate domain words such as todo do not prove unfinished work from the identifier alone.
- Fix guidance: Rename first-token or numbered placeholders for their concrete role; keep legitimate queue/domain names when they already describe the value.
- Confidence rationale: High confidence: only reviewed first-token placeholder families and numbered base-plus-digit shapes match; exact domain words are not inferred.
- Bad example: `temp = load_tasks()` or `result1 = publish()` hides the value's role.
- Good example: `pending_tasks = load_tasks()` is descriptive; `todo = [...]` may be legitimate work-queue vocabulary.

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
- Common false-positive shapes:
  - A one-character domain or mathematical symbol can be conventional even when it is not one of the built-in loop, axis, or exception names.
    Mitigation: Add the exact symbol to `options.acceptedShortNames` with the project's convention, or rename it where the short form is not load-bearing.
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
- Common false-positive shapes:
  - A compatibility or migration test file can intentionally preserve both unittest-style camelCase names and pytest-style snake_case names.
    Mitigation: Finish the rename when compatibility permits, or suppress the file-level advisory with the migration reason.
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
- Default enabled: no
- Rationale: `security.dangerous-function-call` protects the security pillar by flagging dangerous function call before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported dangerous function call directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Default-off reason: Opt-in after M02's blind provenance review remained insufficient: 10 right of 15 judged, with 10 unresolved labels.
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

### `security.django-raw-sql`

- Name: Django raw SQL with dynamic string
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `high`
- Default enabled: no
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
- Common false-positive shapes:
  - A best-effort cleanup or telemetry path can deliberately suppress every exception because failure must not replace the primary result.
    Mitigation: Catch the narrow expected exceptions, or suppress this rule at the reviewed boundary with the reason the fallback is intentionally fail-open.
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
- Common false-positive shapes:
  - A request mapping splat can contain only allowlisted keys after validation performed outside the expression this rule sees.
    Mitigation: Copy validated keys into an explicit dictionary before `**` expansion, or suppress the reviewed call with the validation contract.
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

- Name: Repository secret in a pull_request_target workflow
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `medium`
- Default enabled: no
- Rationale: `security.github-actions-secrets-in-pr` protects the security pillar by flagging repository secret in a pull_request_target workflow before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported repository secret in a pull_request_target workflow directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Security metadata: `cwe` = `['CWE-200', 'CWE-522']`, `owasp` = `['A05:2021-Security Misconfiguration']`, `securitySeverity` = `'medium'`
- Common false-positive shapes:
  - A secret reference can sit behind a trusted-actor gate, an unsupported event condition, or ambiguous YAML ownership that the source scan cannot prove.
    Mitigation: An own job or step guard with bounded event-name comparisons can prove PR unreachability; otherwise move the secret-bearing job to a trusted workflow or review the unsupported boundary.
- Bad example: Code that triggers `security.github-actions-secrets-in-pr` leaves repository secret in a pull_request_target workflow unaddressed.
- Good example: Code that satisfies `security.github-actions-secrets-in-pr` makes repository secret in a pull_request_target workflow explicit or simpler.

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
- Common false-positive shapes:
  - A containerized service can deliberately bind to all interfaces while an external network policy prevents public exposure.
    Mitigation: Read the bind address from deployment configuration, or suppress the reviewed literal with the network-boundary reason.
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
- Default enabled: no
- Rationale: `security.header-injection` protects the security pillar by flagging header injection before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported header injection directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Default-off reason: Opt-in after M02's blind provenance review remained insufficient: neither of two judged findings was right, and one label remained unresolved.
- Common false-positive shapes:
  - A dynamic Flask header name can be selected from an internal allowlist or enum before the assignment, which this local AST check cannot prove.
    Mitigation: Map the validated choice to literal header assignments, or suppress the reviewed sink with the allowlist evidence.
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
- Common false-positive shapes:
  - A non-secret simulation value or opaque identifier can use `random` inside a function whose token- or password-like name suggests a security context.
    Mitigation: Use `secrets` when unpredictability matters; otherwise rename the non-security value or suppress the reviewed call with its purpose.
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
- Common false-positive shapes:
  - A fixed temporary path can be process-private inside an isolated sandbox even though that exclusivity is not visible at the call site.
    Mitigation: Use `mkstemp` or `NamedTemporaryFile`, or suppress the reviewed path with evidence of the containing permission and lifecycle controls.
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
- Default enabled: no
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
- Default enabled: no
- Rationale: `security.unsafe-yaml-load` protects the security pillar by flagging unsafe yaml load before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported unsafe yaml load directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Default-off reason: Opt-in after M02's blind provenance review remained insufficient: two right of three judged, with one unresolved label.
- Security metadata: `cwe` = `['CWE-502']`, `owasp` = `['A08:2021-Software and Data Integrity Failures']`, `securitySeverity` = `'high'`
- Bad example: Code that triggers `security.unsafe-yaml-load` leaves unsafe yaml load unaddressed.
- Good example: Code that satisfies `security.unsafe-yaml-load` makes unsafe yaml load explicit or simpler.

### `security.variable-import`

- Name: Variable import
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `medium`
- Default enabled: no
- Rationale: `security.variable-import` protects the security pillar by flagging variable import before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported variable import directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Default-off reason: Opt-in after M02's blind provenance review remained insufficient: three right of eleven judged, with eight unresolved labels.
- Common false-positive shapes:
  - A dynamic module name can come from a closed plugin registry or internal allowlist that the import expression does not expose.
    Mitigation: Map allowed names to explicit imports, or suppress the reviewed import with the registry boundary that prevents user control.
- Bad example: Code that triggers `security.variable-import` leaves variable import unaddressed.
- Good example: Code that satisfies `security.variable-import` makes variable import explicit or simpler.

### `security.weak-crypto`

- Name: Weak cryptographic hash
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `high`
- Default enabled: yes
- Rationale: MD5 and SHA1 are broken for signatures, tokens, and password material, but they remain valid for cache keys and content digests. The rule reports them only where surrounding names or arguments imply security-sensitive material, so non-security digests stay quiet without configuration.
- Fix guidance: Use a KDF (argon2, bcrypt, scrypt, pbkdf2) for passwords and SHA-256 or better for signatures and tokens. When the digest is genuinely non-security, pass the standard-library keyword `usedforsecurity=False` rather than suppressing the rule.
- Confidence rationale: High confidence: the call target must resolve to a literal weak algorithm, and a security-context smell in the surrounding names or arguments is required before reporting.
- Security metadata: `cwe` = `['CWE-327', 'CWE-916']`, `owasp` = `['A02:2021-Cryptographic Failures']`, `securitySeverity` = `'medium'`
- Common false-positive shapes:
  - A cache key, ETag, or content digest whose surrounding names (token, signature, password) read as security material even though the value is not a secret.
    Mitigation: Pass `usedforsecurity=False`, which is the standard library's own non-security marker and suppresses the MD5/SHA1 finding without touching rule config.
  - A literal `usedforsecurity=False` on MD5 or SHA1 suppresses the finding even when the hashed value looks like a password. This is deliberate: the keyword is the caller's explicit non-security declaration, and only a literal False qualifies - True, 0, None, and dynamic flags all keep the finding.
    Mitigation: Fast password hashing is covered separately: SHA-256 and SHA-512 on password material still report regardless of the keyword, because no non-security reading of that call exists. Review `usedforsecurity=False` on MD5 in code review rather than expecting this rule to reject it.
- Bad example: `hashlib.md5(session_token.encode()).hexdigest()`
- Good example: `hashlib.md5(cache_key.encode(), usedforsecurity=False).hexdigest()` for a non-security digest, or a KDF for password material.

### `security.xxe`

- Name: XML external entity (XXE)
- Pillar: `security`
- Tier: `v0.1`
- Default severity: `error`
- Confidence: `high`
- Default enabled: no
- Rationale: `security.xxe` protects the security pillar by flagging xml external entity (xxe) before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported xml external entity (xxe) directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Default-off reason: Opt-in after M02: only three default findings, two right and one unresolved, leave too little evidence for the precision floor.
- Security metadata: `cwe` = `['CWE-611', 'CWE-776']`, `owasp` = `['A05:2021-Security Misconfiguration']`, `securitySeverity` = `'high'`
- Bad example: Code that triggers `security.xxe` leaves xml external entity (xxe) unaddressed.
- Good example: Code that satisfies `security.xxe` makes xml external entity (xxe) explicit or simpler.

### `sensitive-data.api-key-pattern`

- Name: API key pattern
- Pillar: `sensitive-data`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `high`
- Default enabled: no
- Rationale: Provider-prefixed API keys are high-signal credential leaks; keeping them under one rule avoids provider-specific config churn while the `vendor` metadata tells reviewers which console to rotate in.
- Fix guidance: Rotate the key with the provider, remove it from source, and load it from a secret manager or environment-specific runtime configuration.
- Confidence rationale: High confidence: each match requires a provider-specific prefix and minimum token length, with dummy/example placeholders skipped.
- Bad example: `GOOGLE_API_KEY = "AIza..."` or `SLACK_WEBHOOK = "https://hooks.slack.com/services/..."`
- Good example: `GOOGLE_API_KEY = os.environ["GOOGLE_API_KEY"]`

### `sensitive-data.aws-access-key`

- Name: AWS access key
- Pillar: `sensitive-data`
- Tier: `v0.1`
- Default severity: `warning`
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
- Default severity: `warning`
- Confidence: `high`
- Default enabled: no
- Rationale: Credentialed database URLs in source usually expose direct data access.
- Fix guidance: Move real passwords to environment variables or a secret manager; use exact placeholders such as `password`, `change-me`, `dummy`, `fake`, or `redacted` only in examples.
- Confidence rationale: High confidence: exact URL userinfo pattern with exact placeholder escapes.
- Default-off reason: Opt-in after M02: none of seven judged findings was right, but only eight default findings were available, too few for deletion.
- Bad example: A database URL literal with a real password in the userinfo segment.
- Good example: `DATABASE_URL = "postgresql://user:change-me@host/db"`

### `sensitive-data.gcp-service-account-key`

- Name: GCP service-account key
- Pillar: `sensitive-data`
- Tier: `v0.1`
- Default severity: `warning`
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
- Common false-positive shapes:
  - A non-secret value can use a key containing PASS, TOKEN, or SECRET while its length and entropy resemble a credential.
    Mitigation: Rename the non-secret key or move the value to runtime configuration so the env-file assignment no longer resembles committed secret material.
- Bad example: Code that triggers `sensitive-data.hardcoded-env-value` leaves hardcoded env-file secret unaddressed.
- Good example: Code that satisfies `sensitive-data.hardcoded-env-value` makes hardcoded env-file secret explicit or simpler.

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
- Default severity: `warning`
- Confidence: `medium`
- Default enabled: yes
- Rationale: `sensitive-data.phi-pattern` protects the sensitive-data pillar by flagging phi pattern before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported phi pattern directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Common false-positive shapes:
  - A structurally valid synthetic SSN or labelled MRN outside the placeholder set can look like real health data.
    Mitigation: Use a recognized placeholder, or add a reasoned `sensitiveExclusions` entry for the exact reviewed rule and fixture path.
- Bad example: Code that triggers `sensitive-data.phi-pattern` leaves phi pattern unaddressed.
- Good example: Code that satisfies `sensitive-data.phi-pattern` makes phi pattern explicit or simpler.

### `sensitive-data.private-key`

- Name: Private key
- Pillar: `sensitive-data`
- Tier: `v0.1`
- Default severity: `warning`
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
- Default severity: `warning`
- Confidence: `high`
- Default enabled: no
- Rationale: Inline HTTP(S) userinfo credentials are easy to miss in review and often end up copied into logs, package config, or deployment scripts.
- Fix guidance: Remove `user:password@` from the URL and pass authentication via headers, environment variables, or a secret store.
- Confidence rationale: High confidence: the rule scopes to explicit `http(s)://user:password@` userinfo and skips common placeholder passwords and template segments such as `{}`, `%s`, or a password holding `/` or `:`.
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
- Common false-positive shapes:
  - A coordinator test can legitimately isolate several collaborators because orchestration is the production responsibility under test.
    Mitigation: Use a higher-level test or tune `thresholds.maxMocks` for suites whose reviewed subject is an orchestrator.
- Bad example: Code that triggers `test-quality.excessive-mocking` leaves excessive mocking unaddressed.
- Good example: Code that satisfies `test-quality.excessive-mocking` makes excessive mocking explicit or simpler.

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
- Common false-positive shapes:
  - A test can restore a `global` binding in a fixture or `finally` block, but this rule reports the declaration without evaluating cleanup.
    Mitigation: Use `monkeypatch` or a fixture-owned state boundary, or suppress the reviewed test with the cleanup guarantee.
- Bad example: Code that triggers `test-quality.global-state-mutation` leaves global state mutation in test unaddressed.
- Good example: Code that satisfies `test-quality.global-state-mutation` makes global state mutation in test explicit or simpler.

### `test-quality.loop-assertion-without-message`

- Name: Loop assertion without message
- Pillar: `test-quality`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: no
- Rationale: `test-quality.loop-assertion-without-message` protects the test-quality pillar by flagging loop assertion without message before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported loop assertion without message directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Common false-positive shapes:
  - The compared item can already have a stable, descriptive repr that identifies the failing iteration without a custom assertion message.
    Mitigation: Add an iteration-specific message or parametrize the cases; otherwise suppress the reviewed loop when failure output is already unambiguous.
- Bad example: Code that triggers `test-quality.loop-assertion-without-message` leaves loop assertion without message unaddressed.
- Good example: Code that satisfies `test-quality.loop-assertion-without-message` makes loop assertion without message explicit or simpler.

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
- Common false-positive shapes:
  - An interaction can be the complete contract, such as proving an event was dispatched or a boundary received a mapped payload.
    Mitigation: Keep an explicit mock expectation and suppress the reviewed test, or add an assertion on an observable result when the contract is not purely interaction-based.
- Bad example: Code that triggers `test-quality.mock-only-test` leaves mock-only test unaddressed.
- Good example: Code that satisfies `test-quality.mock-only-test` makes mock-only test explicit or simpler.

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
- Common false-positive shapes:
  - A configured domain namespace can also contain ports or interfaces that are appropriate mock boundaries.
    Mitigation: Narrow `options.domain_namespaces` to concrete domain-object packages or use a small fake for the reviewed port.
- Bad example: Code that triggers `test-quality.mocking-domain-object` leaves mocking domain object unaddressed.
- Good example: Code that satisfies `test-quality.mocking-domain-object` makes mocking domain object explicit or simpler.

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
- Common false-positive shapes:
  - A compatibility or staged migration suite can intentionally mix pytest function names with unittest-style function or class names.
    Mitigation: Complete the rename when compatibility permits, or suppress the file-level advisory with the migration reason.
- Bad example: Code that triggers `test-quality.naming-consistency` leaves test-naming consistency unaddressed.
- Good example: Code that satisfies `test-quality.naming-consistency` makes test-naming consistency explicit or simpler.

### `test-quality.no-assertions`

- Name: Test without assertions
- Pillar: `test-quality`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `high`
- Default enabled: no
- Rationale: Collected tests without assertions are easy to mistake for coverage.
- Fix guidance: Assert behaviour directly, use framework assertions, or call a clear `assert_*` helper; keep pytest fixtures and conftest support code as support.
- Confidence rationale: High confidence: collected-test scope with assertion statements, framework assertions, raises/warns contexts, and `assert_*` helpers.
- Default-off reason: Remains opt-in under M02's accepted table: seven right of 36 judged findings do not establish its 0.70 precision floor.
- Common false-positive shapes:
  - A test can assert through a matcher that raises on a mismatch without an `assert` name, such as pytest's `result.stderr.fnmatch_lines([...])` in `testing/test_junitxml.py`.
    Mitigation: Call the matcher through an `assert_*` helper, or suppress the reviewed test with `# gruff: disable=test-quality.no-assertions` and the matcher that asserts.
  - A smoke test can pass by not raising, such as requests' `test_can_access_urllib3_attribute`, whose whole body is one attribute access.
    Mitigation: Assert on the value the call or access returns, or suppress the reviewed test with its does-not-raise contract.
- Bad example: `def test_saves_user(): service.save(user)`
- Good example: `def test_saves_user(): service.save(user); assert_user_saved(user)`

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
- Common false-positive shapes:
  - A compatibility, serialization, or migration test can deliberately verify a private attribute as the persisted contract.
    Mitigation: Prefer public behavior, or suppress the reviewed access with the compatibility contract it protects.
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
- Common false-positive shapes:
  - Coverage source can be supplied by CI arguments, `.coveragerc`, or environment settings that the pyproject-only check does not read.
    Mitigation: Declare `[tool.coverage.run]` source, or suppress the project finding after checking the external coverage command.
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
- Common false-positive shapes:
  - CI can turn deprecations into errors through command-line warning flags or environment settings that the pyproject-only check does not read.
    Mitigation: Declare the error filter in `[tool.pytest.ini_options].filterwarnings`, or suppress the project finding after verifying the external gate.
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
- Common false-positive shapes:
  - CI can pass pytest strict flags on the command line while pyproject omits them, or a plugin compatibility shim can require permissive markers.
    Mitigation: Add both flags to `[tool.pytest.ini_options].addopts`, or suppress the finding with the verified external gate or compatibility reason.
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
- Common false-positive shapes:
  - Three named scenarios can share one AST shape while their separate names and failures are the contract, especially when only literal values differ.
    Mitigation: Parametrize the cases or tune `thresholds.minGroupSize`; suppress the group when separate scenario identities are intentionally retained.
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
- Common false-positive shapes:
  - A costly domain fixture can be longer than its deliberately small focused tests without representing accidental shared state.
    Mitigation: Extract factories or tune `thresholds.maxSetupLines` after confirming the shared setup is the reviewed suite boundary.
- Bad example: Code that triggers `test-quality.setup-bloat` leaves setup bloat unaddressed.
- Good example: Code that satisfies `test-quality.setup-bloat` makes setup bloat explicit or simpler.

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
- Common false-positive shapes:
  - Public API or compatibility contract where runtime existence is the behaviour under test.
    Mitigation: Keep the test when the runtime contract is intentional; gruff reports this as a candidate, not a deletion command.
- Bad example: `def test_has_render(): assert hasattr(ShapeService, 'render')`
- Good example: `def test_render(): assert ShapeService().render() == 'shape'`

### `test-quality.sut-not-called`

- Name: System under test never called
- Pillar: `test-quality`
- Tier: `v0.1`
- Default severity: `advisory`
- Confidence: `medium`
- Default enabled: no
- Rationale: `test-quality.sut-not-called` protects the test-quality pillar by flagging system under test never called before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported system under test never called directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: Medium confidence: the rule uses bounded heuristics with known safe escapes.
- Default-off reason: Remains opt-in under M02's accepted table: nine right of 28 judged findings do not establish its 0.70 precision floor.
- Common false-positive shapes:
  - A contract test can validate module constants or metadata using only builtins and test helpers, with no callable system under test.
    Mitigation: Assert through the public contract where possible, or suppress the reviewed test with the declarative surface it verifies.
- Bad example: Code that triggers `test-quality.sut-not-called` leaves system under test never called unaddressed.
- Good example: Code that satisfies `test-quality.sut-not-called` makes system under test never called explicit or simpler.

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
- Common false-positive shapes:
  - A table-driven contract test can need many scenarios around one short same-file function, so line ratio overstates duplication.
    Mitigation: Split or extract setup, or tune `options.ratio` after reviewing the scenario coverage.
- Bad example: Code that triggers `test-quality.test-longer-than-sut` leaves test longer than sut unaddressed.
- Good example: Code that satisfies `test-quality.test-longer-than-sut` makes test longer than sut explicit or simpler.

### `test-quality.trivial-assertion`

- Name: Trivial assertion
- Pillar: `test-quality`
- Tier: `v0.1`
- Default severity: `warning`
- Confidence: `high`
- Default enabled: no
- Rationale: `test-quality.trivial-assertion` protects the test-quality pillar by flagging trivial assertion before it becomes costly to review, maintain, or trust.
- Fix guidance: Address the reported trivial assertion directly, or tune this rule with an explicit project configuration override when the project has a documented exception.
- Confidence rationale: High confidence: the rule matches precise AST or source patterns.
- Bad example: Code that triggers `test-quality.trivial-assertion` leaves trivial assertion unaddressed.
- Good example: Code that satisfies `test-quality.trivial-assertion` makes trivial assertion explicit or simpler.

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
  test-quality.excessive-mocking:
    thresholds:
      maxMocks: 4
```
