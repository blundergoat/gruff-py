# Glossary

Last reviewed 2026-05-14.

- AnalysisConfig = immutable-style runtime configuration derived from rule defaults plus `.gruff.yaml` or `[tool.gruff]` overrides.
- AnalysisReport = complete run result containing schema version, inputs, summary counts, diagnostics, findings, optional score, and exit code.
- AnalysisUnit = parsed source payload for one discovered file; Python units may carry an AST, text units do not.
- Baseline = cross-implementation finding identity contract using `gruff.baseline.v1` and 16-character fingerprints.
- Gruff config = project config loaded from explicit `--config`, `.gruff.yaml`, or `[tool.gruff]` in `pyproject.toml`. Shared keys are `minimumPythonVersion`, `paths.ignore`, `allowlists.acceptedAbbreviations`, `allowlists.secretPreviews`, `selection`, and `rules`.
- FailThreshold = CLI setting that decides which finding severities produce exit code `1`.
- Finding = one rule result with rule id, file position, severity, pillar, confidence, remediation, metadata, and fingerprint.
- Fingerprint = SHA-256-derived 16-character identifier that must match gruff-php byte-for-byte for equivalent finding identity fields.
- Pillar = quality category such as `size`, `complexity`, `security`, or `test-quality`.
- Rule ID = stable public rule identifier using the gruff-family `<namespace>.<rule-slug>` convention, for example `size.file-length`, `docs.missing-function-docstring`, and `sensitive-data.high-entropy-string`. Documentation rules use `docs.*` while their pillar is `documentation`.
- RuleDefinition = static metadata for a rule: id, name, pillar, tier, default severity, thresholds, options, and enablement.
- RuleRegistry = registry that owns available rules, enabled-rule filtering, rule execution, deduplication, and stable finding ordering.
- SourceTextRule = marker base class for rules that should also run on non-Python text files.
- gruff-php = sibling implementation whose baseline and report compatibility constrains this Python port.
