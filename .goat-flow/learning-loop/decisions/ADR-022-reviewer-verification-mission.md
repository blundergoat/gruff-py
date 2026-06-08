# ADR-022: Mission — Optimise For Reviewer Verification Of AI-Generated Code

**Status:** Accepted
**Date:** 2026-05-30
**Author(s):** Matthew Hansen
**Ticket/Context:** establishes the governing purpose referenced by `README.md` (`## Mission`), `.goat-flow/architecture.md` (`## Mission`), and `docs/mission.md`, mirrored in the agent instruction files, and cited as the premise of ADR-021.

## Context

gruff-py could have been positioned as a general-purpose Python quality linter tuned to industry maintainability norms. It is not. Its reason for being is narrower and load-bearing: it is built to **govern code produced by a coding agent so that a human who did not write it can review, verify, and trust it** — most directly when wired in as a coding-agent hook.

This framing is a real, contestable choice, and it constrains every downstream decision: which rules exist, which gate versus guide, how thresholds are set, how findings are scored, and what the docs emphasise. Recording it prevents a future maintainer or agent from silently "correcting" gruff-py back into a generic linter — for example by re-tuning thresholds to general-code norms, dropping the mandatory-doc-comment rule as "too strict," or treating `test-quality` and `documentation` as optional style pillars — none of which serve the actual mission.

## Decision

gruff-py optimises for **a reviewer's ability to verify AI-generated code**, not for abstract code quality. This premise governs the project:

1. **Justification test.** Any rule, severity, threshold, or score change must make it more likely that a reviewer correctly signs off on agent-written code. "Matches an industry default" or "is conventionally clean" is not, by itself, a justification.
2. **Guide vs force is expressed through severity + `--fail-on`** (ADR-019): advisory findings *guide*; `--fail-on`-gated warning/error findings *force*. A rule earns the forcing setting only when acting on it reliably increases verifiability (the per-rule policy is ADR-021's `reviewability` profile).
3. **Three outcomes the catalogue serves:** legible enough to verify (`size`, `complexity`, `naming`); secure where human review is weakest (`security`, `sensitive-data` — the strictest gates, because a false negative is the worst outcome); and tested for real rather than padded with low-signal ceremony (`test-quality` — where a false negative, fake coverage that gets trusted, is the failure to avoid).
4. **The `documentation` pillar is core, not cosmetic.** Doc comments are required even on private one-liners because forcing the agent to state intent, usage, contract, and failure behaviour gives the reviewer a prose contract to check the implementation against; a doc/code mismatch is itself a "look closer" signal. The mission is also why the severity order is `SECURITY` > `CORRECTNESS` > `INTEGRATION` > `PERFORMANCE` > `STYLE`.
5. **Scope honesty.** gruff-py remains heuristic static analysis that complements `ruff`, `mypy`, `pytest`, dedicated scanners, and human review; it does not replace them or execute analysed code.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Record the mission as the governing decision (accepted) | Adds a charter-style ADR broader than a single implementation choice. | **Accepted.** It constrains all future rule/threshold/scoring decisions, prevents incorrect "fixes," and is the cited premise of ADR-021 and the reason for the severity order and the docs/test-quality posture. |
| Leave the mission in README/architecture prose only | Prose framing is easy to override or drift from; no decision record explains *why* tuning departs from industry norms, so a future agent re-tunes toward them. | Rejected — the mission needs a durable decision home, not just descriptive copy. |
| Fold the mission into ADR-021 | Conflates the premise (why gruff exists) with one application (the tuning profile); future non-tuning decisions would have no charter to cite. | Rejected — the premise outlives and governs more than the profile. |
| Reposition gruff-py as a general-purpose linter | Drops the differentiator and the reason the doc/test/security posture is shaped the way it is; duplicates ruff and industry linters. | Rejected — that is a different product. |

## Reversibility

**One-way-ish for the product's identity.** Reversing the mission (becoming a general-purpose linter) would invalidate the rationale for the documentation, test-quality, and complexity posture and reshape the catalogue; it is a deliberate product pivot, not a config change.

**Two-way for expression.** How the mission is phrased across `README.md`, `.goat-flow/architecture.md`, and `docs/mission.md` is freely editable as long as the governing premise is preserved.

**Revisit triggers:**
- The primary use case shifts away from governing agent-generated code (e.g. predominantly human authors adopt it as a general linter) — re-evaluate the justification test.
- A sibling implementation (gruff-php/-ts/-rs/-go) records a different mission — reconcile, since cross-impl users expect consistent intent.
- Evidence that the doc-comment-mandatory or test-quality-strict posture harms reviewer verification more than it helps — revisit that specific posture (and ADR-021), not necessarily the mission.
