# Glossary

Last reviewed 2026-05-14.

- AnalysisConfig = immutable-style runtime configuration derived from rule defaults plus `.gruff.yaml` or `[tool.gruff-py]` overrides.
- AnalysisReport = complete run result containing schema version, inputs, summary counts, diagnostics, findings, optional score, and exit code. `AnalysisReport.to_dict()` is the canonical JSON payload, byte-equivalent to the PHP reference for shared keys.
- AnalysisUnit = parsed source payload for one discovered file; Python units may carry an AST, text units do not.
- Baseline = cross-implementation finding identity contract using `gruff-py.baseline.v1` and 16-character fingerprints.
- Composite finding = a finding synthesised post-pass when multiple per-unit findings overlap on a symbol (currently `design.god-method`); built by `CompositeFindingFactory`.
- Confidence = StrEnum on `Finding` with three values that scale the penalty applied by `ScoreCalculator`: `high` (weight 1.0), `medium` (0.75), `low` (0.5).
- Diagnostic = non-finding analyser output for parse errors, config errors, and unexpected runtime conditions; forces exit code `2` when present.
- FailThreshold = CLI setting that decides which finding severities produce exit code `1`. Values: `error`, `warning`, `advisory`, `none`.
- Finding = one rule result with rule id, file position, severity, pillar, confidence, remediation, metadata, and fingerprint.
- Fingerprint = SHA-256-derived 16-character identifier that must match gruff-php byte-for-byte for equivalent finding identity fields.
- Gruff config = project config loaded from explicit `--config`, `.gruff.yaml`, or `[tool.gruff-py]` in `pyproject.toml`. Shared keys are `minimumPythonVersion`, `paths.ignore`, `allowlists.acceptedAbbreviations`, `allowlists.secretPreviews`, `selection`, and `rules`.
- gruff-py.analysis.v1 = schema string in `AnalysisReport.to_dict()`; the analyse-output contract shared with the PHP/TS/Rust ports.
- gruff-py.baseline.v1 = schema string for the baseline format (finding-identity ignore list).
- gruff-py.hotspot.v1 = schema string declared for future hotspot reports; the reporter has not yet shipped.
- gruff-php = sibling implementation whose baseline and report compatibility constrain this Python port.
- Pillar = quality category such as `size`, `complexity`, `security`, or `test-quality`. The `Pillar` enum declares 14 values; 9 ship populated catalogues in 0.1.0-dev (`size`, `complexity`, `maintainability`, `dead-code`, `naming`, `documentation`, `security`, `sensitive-data`, `test-quality`); `design` is composite-only; `modernisation`, `coupling`, `architecture`, and `mutation` are declared placeholders pending future rule work.
- Rule ID = stable public rule identifier using the gruff-family `<namespace>.<rule-slug>` convention, for example `size.file-length`, `docs.missing-function-docstring`, and `sensitive-data.high-entropy-string`. Documentation rules use `docs.*` while their pillar is `documentation`.
- RuleDefinition = static metadata for a rule: id, name, pillar, tier, default severity, thresholds, options, and enablement.
- RuleRegistry = registry that owns available rules, enabled-rule filtering, rule execution, deduplication, and stable finding ordering.
- RuleTier = StrEnum tagging the catalogue version a rule belongs to on `RuleDefinition`. Single value in 0.1.0-dev: `v0.1`. Later releases may add tiers as the catalogue grows.
- ScoreCalculator = component that converts findings into composite, per-pillar, and top-offender file grades using the two-axis severity × confidence weight model (severity weights 12/4/1, confidence weights 1.0/0.75/0.5, pillar multiplier ×4, file multiplier ×5). Grades A/B/C/D/F at 90/80/70/60.
- Severity = StrEnum on `Finding` with three values that drive `FailThreshold` matching and `ScoreCalculator` penalty weighting: `error` (weight 12), `warning` (4), `advisory` (1).
- SourceFile = frozen dataclass produced by `SourceDiscovery` with `absolute_path`, `display_path`, and `type` (`"python"` or `"text"`). The parser reads file contents when building the `AnalysisUnit`.
- SourceTextRule = marker base class for rules that should also run on non-Python text files.
- text files = the non-Python files included in discovery: `.env`, `.toml`, `.yaml`/`.yml`, `.json`, `.ini`, `.conf`. Rules subclassing `SourceTextRule` analyse these; rules requiring an AST do not.
