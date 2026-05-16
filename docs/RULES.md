# Rules

gruff-py `0.1` registers 98 rules in `RuleRegistry.defaults()`.

## Pillar Summary

| Pillar | Rule count | Notes |
|---|---:|---|
| `size` | 7 | File, class, function, parameter, method, and attribute size |
| `complexity` | 5 | Cyclomatic, cognitive, Halstead, nesting, and NPATH |
| `maintainability` | 1 | Maintainability index rule emits under this pillar |
| `dead-code` | 10 | Unused and waste-oriented rules |
| `naming` | 9 | Intent-layer names; PEP 8 case style stays with ruff |
| `documentation` | 10 | Docstring presence, stale docs, TODO density, README presence |
| `security` | 12 | Heuristic AST-level dangerous patterns |
| `sensitive-data` | 9 | Secret, key, PII, and PHI patterns |
| `test-quality` | 34 | Pytest-aware test smells and project config checks |
| `design` | 1 | Project-level design rule |

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
- `complexity.npath`

### Dead Code And Waste

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

### Naming

- `naming.boolean-prefix`
- `naming.confusing-name`
- `naming.generic-function`
- `naming.hungarian-notation`
- `naming.identifier-quality`
- `naming.module-name-mismatch`
- `naming.parameter-type-name`
- `naming.short-variable`
- `naming.test-naming-consistency`

### Documentation

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

- `security.dangerous-function-call`
- `security.disabled-ssl-verification`
- `security.error-suppression`
- `security.extract-compact-user-input`
- `security.header-injection`
- `security.insecure-random`
- `security.shell-injection`
- `security.silent-except`
- `security.sql-concatenation`
- `security.unsafe-pickle`
- `security.variable-import`
- `security.weak-crypto`

### Sensitive Data

- `sensitive-data.api-key-pattern`
- `sensitive-data.aws-access-key`
- `sensitive-data.database-url-password`
- `sensitive-data.hardcoded-env-value`
- `sensitive-data.high-entropy-string`
- `sensitive-data.jwt-token`
- `sensitive-data.phi-pattern`
- `sensitive-data.pii-test-fixture`
- `sensitive-data.private-key`

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
- `test-quality.mocking-domain-object` (default off)
- `test-quality.multiple-aaa-cycles` (default off)
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
- `test-quality.sut-not-called`
- `test-quality.tautological-type-assertion`
- `test-quality.test-function-too-long`
- `test-quality.test-longer-than-sut`
- `test-quality.testdox-readability` (default off)
- `test-quality.trivial-assertion`
- `test-quality.trivial-snapshot`
- `test-quality.unused-mock`

### Design

- `design.single-implementor-protocol`
- `design.god-method` is synthesized after rule execution when size and
  complexity findings overlap on a symbol.

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

Enable an opt-in rule:

```yaml
rules:
  test-quality.testdox-readability:
    enabled: true
```

Adjust thresholds:

```yaml
rules:
  size.file-length:
    thresholds:
      warning: 500
      error: 900
```
