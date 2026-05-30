# ADR-021: Reviewability Profile And Agent-Hook Severity Policy

**Status:** Proposed
**Date:** 2026-05-30
**Author(s):** Matthew Hansen
**Depends on:** ADR-022 (mission charter) for the governing premise; ADR-009 (rule profiles and confidence filtering) for the preset mechanism; ADR-014 (single-severity threshold rubrics) for the threshold shape; ADR-019 (per-command minimum severity) for the gate.
**Ticket/Context:** the gruff-py mission now in `.goat-flow/architecture.md` (`## Mission`) and `README.md` (`## Mission`) — "govern AI-generated code so a human reviewer can sign off on it." This ADR turns that mission into a concrete tuning policy.

## Context

The mission fixes the optimisation target: a coding agent wrote the change, and a reviewer who did **not** write it must read, review, and trust it. That target implies a selection rule for *which* findings should **force** the agent (gate, counted by `--fail-on`) versus merely **guide** it (advisory). A rule earns a gate only when it scores high on both:

1. **Verification-proxy strength** — does the metric track the effort a reviewer spends to be *sure* the code does what was asked?
2. **Goodhart-resistance** — under a hard gate an agent does the *minimum* to make the number pass; a gate is only safe when "minimum to pass" ≈ "genuinely more verifiable." A gate an agent can satisfy by mechanical edits that *add* indirection is counter-productive.

Applying that rule surfaces a mismatch in today's defaults, where the six complexity rubrics are treated as co-equal error-tier gates:

- **`complexity.npath` is the weakest verification proxy and is Goodhart-fragile.** NPATH is multiplicative by Nejmeh's definition (`src/gruffpy/rule/complexity/npath_complexity_rule.py`, `_npath_of` multiplies sequential statements; capped at `_NPATH_CAP = 5000`). It counts the structural cross-product of branches as if all combinations were reachable, so it over-counts exactly the early-return guard-clause / validation-chain idiom — the idiom gruff's own `cyclomatic` and `nesting-depth` remediation strings tell agents to adopt ("replace nested conditionals with early returns", "flatten with guard clauses, early returns"). Concretely, the highest-NPATH function in gruff-py's own source is `existing_config_source` (`src/gruffpy/command/init_config.py:208`) at **432** (86% of the 500 gate) — flat guards, nesting ~2, cyclomatic ~9, and unambiguously clean. Raising the threshold does not help: each additional readable guard costs roughly ×3 (`3^6 = 729`, `3^7 = 2187`), so the whole above-gate range up to the 5000 cap is ~2 extra guards. And NPATH is gamed by extracting one guard into a helper — indirection that *lowers* reviewability while the number drops. It already runs at `Confidence.MEDIUM`, so the design already encodes "trust this less"; this ADR finishes the thought. (Superseded by 1.0.0 milestone M01, which deletes `complexity.npath` outright rather than demoting it to advisory.)
- **`complexity.cognitive` is the strongest verification proxy** — SonarSource designed it (per ADR-003) as the "how hard to *understand*" counterpart to cyclomatic's "how hard to *test*." It runs at `Confidence.HIGH` (cognitive rule line 48) and is Goodhart-resistant: you lower it by genuinely flattening. Yet its active threshold is 30/error (`.gruff-py.yaml`), calibrated to "very hard," not "needs a careful read."
- **`complexity.maintainability-index` diverges from canonical gruff-php by *scale*, not policy.** gruff-py uses the raw SEI value clamped to `[0, 100]` (`src/gruffpy/rule/complexity/maintainability_index_rule.py:126-127`); gruff-php normalises `× 100 / 171` (`gruff-php/src/Rule/Complexity/MaintainabilityIndexRule.php:127`). So gruff-py's 70 and gruff-php's 35 are not comparable numbers — any MI gating decision must wait on a computation reconciliation (its own follow-up). (Halstead py 400 vs php 2000 is *expected* — language-specific operator/operand counting — not a divergence to fix.)

The four headline complexity defaults already match canonical gruff-php exactly (cyclomatic 20, npath 500, cognitive 30, nesting 6 — all severity error), so this is not a "the numbers are wrong" ADR. It is a "the *posture* should differ for the agent-hook use case" ADR.

Empirically, gruff-py's own source is a poor calibration target: a full `analyse src/` over 216 files / 1395 functions yields **5 findings total** (3 advisory, 2 error) and **0 complexity-pillar findings**. The population this policy governs is agent-generated diffs, which trip very different rules than hand-curated code.

## Decision

Add a named, **opt-in** `reviewability` profile (via ADR-009's preset layer) that re-weights rule severity, confidence floor, and severity-bearing thresholds for the coding-agent-hook use case. The built-in `default` profile is **unchanged** and stays in lockstep with gruff-php for cross-implementation parity. The profile changes only enablement, severity, confidence, and thresholds — never a metric *computation*, fingerprint, or score-math input — so baselines remain interoperable across ports.

Selection rule: **gate (error/warning) on rules that are both a strong verification proxy and Goodhart-resistant; everything else is advisory.** Severity-bearing thresholds keep the ADR-014 single-`threshold`-plus-`severity` shape (never warning/error tiers). Confidence posture: the profile gates only `high` (and selectively `medium`) confidence findings and demotes `low`-confidence findings to advisory, so the forcing signal stays precise.

Proposed posture (numbers marked *provisional* are finalised by the calibration step below; the exhaustive per-rule map is an implementation task, not part of this decision):

| Rule / group | `reviewability` posture | vs `default` | Why |
| --- | --- | --- | --- |
| `security.*` | **gate, error**, high confidence | confirm | "Secure where the eye fails" — review is worst at catching these; a false negative is the worst outcome of the whole system. |
| `sensitive-data.*` | **gate, error** | confirm | Leaked secrets/keys the eye skips. |
| `complexity.cognitive` | **gate (primary)**, threshold *~15–20* (provisional), severity error, HIGH conf | tighten from 30 | Best proxy for reviewer-understanding effort; Goodhart-resistant. |
| `complexity.nesting-depth` | **gate**, threshold *~4* (provisional), HIGH conf | tighten from 6 | Held mental context. |
| `complexity.cyclomatic` | **gate**, threshold 20, HIGH conf | keep | Decision count = basis test cases ⇒ proxy for "how much testing to trust it"; ties to `test-quality`. |
| `documentation` intent/drift rules (`docs.missing-*-docstring`, `docs.stale-param-doc`, `docs.useless-docstring`) | **gate** | strict | The reviewer's prose contract; a doc/code mismatch is the "look closer" signal. |
| `test-quality` anti-bloat (`no-assertions`, `trivial-assertion`, `tautological-type-assertion`, `mock-only-test`, `excessive-mocking`, `trivial-snapshot`, `eager-test`, `magic-number-assertion`, `sut-not-called`) | **gate**, enabled | strict; enable default-off members | "Tested for real" — here the false negative (fake coverage a reviewer trusts) is the enemy. |
| `complexity.npath` | **removed** (deleted in M01) | removed from the catalogue | Weakest proxy; multiplicative FP on the recommended guard style; threshold-raising futile; Goodhart-gameable — the maintainer chose full deletion over advisory. |
| `complexity.halstead-volume` | **advisory** | demote | Volume proxy, weak for verification; language-calibrated. |
| `complexity.maintainability-index` | **advisory, frozen** pending scale reconciliation | demote | py/php scales differ; gate only after the computation is reconciled. |
| Additive size-length rules (`size.function-length`, `size.average-function-length`, `size.class-length`, `size.file-length`) | **advisory** (most debatable) | demote-leaning | Gamed by mechanical extraction ⇒ indirection; `cognitive`/`nesting` are the Goodhart-resistant proxies for the same "too much to hold at once" concern. |
| `size.parameter-count` | **gate** | keep | High arity genuinely raises verification cost and is not fixed by splitting. |

A subset of this is buildable **today** without ADR-009's preset layer: per-rule `severity` overrides and `--fail-on` already exist (the loader accepts `threshold`/`severity`/`enabled`). The profile is the durable packaging; an interim shipped `reviewability`-flavoured example config can carry the same posture until the preset layer lands.

**Calibration is part of the decision, not an afterthought:** the provisional thresholds (cognitive ~15–20, nesting ~4) and the size-rule demotions must be set against a corpus of *agent-generated* diffs, not gruff-py's near-pristine self-source. No provisional number is binding until that calibration runs.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Opt-in `reviewability` profile layered on ADR-009; `default` unchanged (accepted) | Adds config surface; another profile to test as a matrix; the severity map becomes compatibility-sensitive once public. | **Accepted (proposed).** Additive and parity-safe; expresses the agent-hook posture without imposing it on every user or breaking gruff-php-aligned defaults. |
| Change the built-in `default` complexity severities globally | Breaks parity with gruff-php's defaults and silently changes gating for every existing user's CI. | Rejected — the agent-hook posture is a *use case*, not the universal default. |
| Just raise the NPATH threshold | NPATH is exponential; +1 readable guard needs ~×3 threshold, and the cap is 5000 — a linear bump relocates the cliff by ~nothing and still mis-fires on guard style. | Rejected — wrong lever for a multiplicative metric. |
| Keep NPATH/length as error gates | Penalises the early-return/guard idiom gruff's own remediation recommends; gameable by extraction that lowers reviewability. | Rejected — fails the Goodhart test. |
| Re-implement NPATH to not multiply independent guards | Diverges from Nejmeh and from gruff-php's NPATH values; breaks cross-impl metric agreement. | Rejected — computation is contract-aligned; tune posture, not the algorithm. |
| Gate on `maintainability-index` now | py (raw clamped) and php (×100/171) compute different MI scales, so the gate would fire on incomparable numbers. | Rejected for now — reconcile the computation first (separate ADR), then revisit. |

## Consequences

**Mechanism / config:**
- Requires ADR-009's preset layer to ship for the full named-profile form; until then, an interim example config (`reviewability`-flavoured) carries the posture via per-rule `severity`/`enabled` plus a documented `--fail-on`. Exact rule configuration still wins over the profile (ADR-009 precedence).
- Adds a confidence-floor posture (gate `high`/selective `medium`; `low` → advisory), exercising ADR-009's confidence filter.

**Rule severity map:** the per-rule severity/enablement/threshold assignments in the table above are finalised in implementation against the live catalogue (some `test-quality` members ship default-off and the profile enables them). No metric computation, fingerprint input, or score-math weight changes — only policy.

**Docs:** `docs/configuration.md` documents the profile and its posture; the `## Mission` sections in `README.md` and `.goat-flow/architecture.md` already supply the rationale this profile implements.

**Cross-implementation:** threshold/severity/confidence are per-impl *policy*, not part of the byte-for-byte contract (fingerprints, score math, grade bands, schema strings, exit codes, rule IDs are). The `default` profile stays aligned with gruff-php. The `reviewability` profile *concept* should ideally be shared across gruff-php/-ts/-rs/-go so cross-impl users get consistent agent-hook behaviour; gruff-py can ship first (as ADR-020 did) and siblings adopt the same profile name and posture. Until then this is a deliberate, documented per-impl profile, not accidental drift.

**Follow-ups (not decided here):** (1) the maintainability-index scale reconciliation with gruff-php; (2) ADR-009 promotion from `Proposed` to `Accepted`; (3) the agent-generated calibration corpus and its threshold outputs (a `.goat-flow/tasks/` milestone, not an ADR).

## Reversibility

**Two-way door while `reviewability` is undocumented/unshipped** — it is an additive, opt-in profile; the `default` profile and all metric computations are untouched, so nothing baseline- or fingerprint-breaking is at stake.

**Compatibility-sensitive once public** — after the profile is documented and adopted, changing which rules it gates alters users' CI pass/fail, so its severity map should then move only as a coordinated, release-noted change (and, ideally, in step with sibling ports).

**Revisit triggers:**
- The agent-generated calibration corpus contradicts a provisional number (cognitive ~15–20, nesting ~4) or a size-rule demotion.
- The maintainability-index computation is reconciled with gruff-php — then MI can move from advisory-frozen to a gate with a comparable threshold.
- A sibling port adopts or declines the `reviewability` profile — coordinate the name and posture, or record the divergence.
- ADR-009's preset layer does not land — keep the interim per-rule-override config as the long-term carrier and note it here.
- Evidence that an advisory NPATH/length signal is missing real verification hazards the gated rules don't catch — reconsider the gate/advisory split for that rule.
