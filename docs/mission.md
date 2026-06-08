# Mission

gruff-py exists to **govern AI-generated code so a human reviewer can sign off on it**.

The premise: a coding agent wrote the change, and a person who did *not* write it has to read, review, and trust it. gruff-py optimises for that reviewer's confidence — every rule, severity, threshold, and score is justified by how much it helps a reviewer verify that the code does what was asked, not by abstract style.

## Guide or force

Wired in as a coding-agent hook, gruff-py works on two settings, both driven by finding severity and `--fail-on`:

- **Guide** — advisory findings inform the agent and the reviewer without blocking.
- **Force** — warning and error findings gated by `--fail-on` fail the run until the agent fixes them.

A finding earns the *force* setting only when acting on it reliably makes the code more verifiable; lower-signal checks stay advisory. The concrete per-rule policy is set out in the proposed `reviewability` profile — see [ADR-021](../.goat-flow/learning-loop/decisions/ADR-021-reviewability-profile.md).

## What it optimises for

- **Legible enough to verify.** A reviewer can follow the control flow and confirm intent without holding the whole function in their head. This is what the `complexity`, `size`, and `naming` pillars protect — and why `complexity.cognitive` (how hard the code is to *understand*) is the load-bearing complexity signal rather than raw path counts.
- **Secure where the eye fails.** Human review is worst at catching dangerous calls, misconfiguration, and leaked secrets, so the `security` and `sensitive-data` pillars are the strictest gates — a missed finding here is the worst outcome of the whole system.
- **Tested for real, not padded.** The `test-quality` pillar rewards tests that exercise behaviour and flags low-signal ceremony — assertion-free tests, tautologies, mock-only theatre — that inflates coverage without earning a reviewer's trust. Here a false negative (fake coverage that gets trusted) is the failure to avoid.

## Why doc comments are mandatory, even on a private one-liner

Coding agents routinely produce code that superficially works while misunderstanding the requirement. Forcing the agent to state **intent, usage, contract, and failure behaviour** in prose gives the reviewer something to check the implementation against — and a mismatch between the doc comment and the code is itself a signal that the change needs a deeper look. That is why the `documentation` pillar is core to the mission rather than a style nicety.

## Scope

gruff-py is heuristic static analysis. It complements `ruff`, `mypy`, `pytest`, dedicated security scanners, and human review — it does not replace them, and it does not execute the code it analyses.

## Decision records

- **Charter:** [ADR-022 — Mission: optimise for reviewer verification of AI-generated code](../.goat-flow/learning-loop/decisions/ADR-022-reviewer-verification-mission.md)
- **Tuning policy:** [ADR-021 — Reviewability profile and agent-hook severity policy](../.goat-flow/learning-loop/decisions/ADR-021-reviewability-profile.md)
- **Design rationale:** [`.goat-flow/architecture.md` (`## Mission`)](../.goat-flow/architecture.md)
