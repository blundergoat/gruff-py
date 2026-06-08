# ADR-020: Additive `stableIdentity` Field On Findings

**Status:** Accepted
**Date:** 2026-05-27
**Cross-implementation pair:** `gruff-php/.goat-flow/tasks/0.1.4/M05-stable-identity-field-for-diffs.md` (pending; identical field name, input set, and 16-char SHA-256 prefix — adopting this contract on the Python side first lets gruff-php land verbatim).
**Ticket/Context:** `.goat-flow/tasks/0.1.2/M02-stable-identity-field-for-cross-impl-diffs-v0.1.2.md`; `.goat-flow/footguns/compatibility.md` "Finding fingerprints depend on PHP-style JSON bytes".

## Decision

Add an **additive** field `"stableIdentity"` to `Finding.to_dict()`, adjacent to the existing `"fingerprint"` key. The existing `fingerprint()` formula is **unchanged**; baselines, SARIF `partialFingerprints`, and every other line-precise downstream identity continues to consume `fingerprint`.

```python
# pseudo-shape
finding.to_dict() == {
    # ...existing keys unchanged...
    "fingerprint":    "<16 hex chars: line-precise identity>",
    "stableIdentity": "<16 hex chars: line-insensitive identity>",
    # ...
}
```

**Input set for `stableIdentity`:**

- When `symbol is not None`: hash `[ruleId, file, symbol]`.
- When `symbol is None`: hash `[ruleId, file, message]`.
- **No `line`, `endLine`, or `column` ever** — that is the entire point.

**Hashing algorithm:** the same PHP-compatible canonical JSON encoding used by `fingerprint_for()` (`json.dumps(..., separators=(",", ":"), ensure_ascii=True)` then `/` → `\/`), SHA-256, first 16 hex chars. The encoding is byte-shared so gruff-py and gruff-php (and any other port adopting the same field) produce identical digests for identical inputs.

**Surface:**

- `Finding.stable_identity()` method on `Finding`.
- `stable_identity_for(...)` module-level helper sibling to `fingerprint_for()` in `src/gruffpy/finding/fingerprint.py`.
- `"stableIdentity"` key in `Finding.to_dict()` adjacent to `"fingerprint"`.
- **SARIF unchanged.** `partialFingerprints.gruffFingerprint` continues to mirror the line-precise fingerprint; the additive stable identity is not folded in. A future ADR can add a `partialFingerprints.gruffStableIdentity` entry if a SARIF consumer asks for it.
- **Baseline matching unchanged.** `BaselineFilter` keys on `(fingerprint, rule_id, file_path)`; the additive field is informational for external diff tooling, not a baseline mechanism.

**Schema version:** no bump. `gruff-py.analysis.v1` consumers ignore unknown keys per the existing schema contract. If multiple additive changes accumulate in a future cycle, a `v1.1` bump is a release-prep decision, not this milestone's.

## Context

Two failure modes converge:

1. **Line-shift churn in external diff tooling.** When unrelated edits move a finding by N lines, `fingerprint` changes (line is in its input set, intentionally — so a moved violation can be re-baselined deliberately). Consumers wanting "the same logical finding, even if it moved" today must reimplement an identity over `(ruleId, file, symbol)` themselves — see `gruff-php/.goat-flow/scratchpad/gruff-php-improvement-feedback.md` section 12 for the "167 fixed, 141 new" anecdote.
2. **Symbol-less findings.** For rules that never populate `symbol` (most `security.*`, `sensitive-data.*`, several text-scan rules), there is no obvious cross-edit identity at all. Falling back to `message` is the least-bad cross-port choice; the message-as-fallback identity is message-dependent by construction, and that is acceptable for rules whose entire signal is the rendered message.

The reviewer's literal proposal (replace the `fingerprint` formula with a line-insensitive one) was rejected because it silently invalidates every gruff-baseline.json in the wild, and removes the ability for `BaselineFilter` to disambiguate multiple findings of the same rule at the same symbol on different lines. Additive coexistence is the non-breaking choice.

The field name `stableIdentity` was selected over `partialFingerprint` (collides with SARIF's already-distinct `partialFingerprints` map), `lineInsensitiveFingerprint` (verbose; reads as a negation of the primary key), `symbolFingerprint` (misleading for the symbol-less fallback path), and `identity` (too generic; suggests primary identity, but `fingerprint` already holds that role for baselines).

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Add `stableIdentity` adjacent to `fingerprint`, no schema bump, baselines untouched (accepted) | Two identity columns to keep in sync; external consumers must learn which to pick. | **Accepted.** Smallest non-breaking surface; documentation makes the choice explicit ("baseline = fingerprint, diff = stableIdentity"); the same field shape lands on gruff-php so cross-port tooling sees one model. |
| Replace `fingerprint`'s formula with a line-insensitive one | Invalidates every existing baseline file silently; breaks `BaselineFilter`'s ability to disambiguate two violations of the same rule at the same symbol on different lines. | Rejected — the reviewer's literal proposal; one-way silent break. |
| Hash `message` verbatim into the symbol-present identity too | Messages contain variable data (parameter names, counts) that drifts across edits; pulling it into the primary identity path creates spurious churn. | Rejected — message is in the input set **only** as a symbol-less fallback where there is no better option. |
| Add a `--diff-strategy=fingerprint|symbol|location` CLI flag | Couples a presentation concern (how a consumer keys its diff) to gruff-py's surface; gruff-py does not need to enforce strategy. | Rejected — the two JSON fields are enough for consumers to pick on their own. |
| Bump `gruff-py.analysis.v1` to `v1.1` solely for this additive field | A consumer ignoring unknown keys is unaffected; a consumer that hard-asserts schema version would force a coordinated release across every sibling port for a non-breaking addition. | Rejected — schema bumps cost more than they earn for additive fields. Revisit at release-prep if multiple additive changes accumulate. |
| Add the field to SARIF `partialFingerprints.gruffStableIdentity` immediately | Locks the SARIF surface to the new field before any SARIF consumer has asked for it; a later rename or removal becomes a SARIF schema break. | Rejected — SARIF stays unchanged; revisit when a code-scanning consumer requests it. |
| Diverge from gruff-php on field name or input set | Cross-port tooling has to special-case per implementation; defeats the whole point of byte-equivalent identities. | Rejected — coordinate verbatim. The pending gruff-php M05 already documents the same field name, same input set, same 16-char prefix; this ADR locks the gruff-py side and gruff-php adopts the same shape. |

## Consequences

**Source:**

- `src/gruffpy/finding/fingerprint.py` grows a sibling helper `stable_identity_for(rule_id, file_path, symbol, message)` that reuses the PHP-compatible JSON canonical encoding and SHA-256 prefix length.
- `src/gruffpy/finding/finding.py::Finding` grows a `stable_identity()` method; `to_dict()` returns `"stableIdentity"` adjacent to `"fingerprint"`. `fingerprint()` is byte-for-byte unchanged.
- `JsonReporter` automatically picks up the new key via `to_dict()` — no reporter-side change.
- `SarifReporter` is **not** updated; `partialFingerprints.gruffFingerprint` continues to mirror the line-precise fingerprint.
- `BaselineFilter` is **not** updated; the additive field is informational for external diff tooling.

**Tests:**

- `tests/unit/finding/test_stable_identity.py` covers: 16-char hex shape, determinism, symbol-present vs symbol-absent input sets, line-shift invariance (line, end_line, column differ → identity unchanged), rule-id-differs distinguishes, file-differs distinguishes, symbol-differs distinguishes, message-fallback flows through when symbol is None.
- `tests/integration/test_json_byte_equivalence.py` continues to pass: the additive key is JSON-encoded the same way on both sides (PHP-compatible) so round-trip equivalence holds. An assertion is added to surface the key explicitly in the rendered Python JSON.
- Existing `tests/unit/finding/test_fingerprint.py` PHP_GROUND_TRUTH remains unchanged — `fingerprint()` is byte-for-byte the same.

**Docs:**

- `.goat-flow/architecture.md` Fingerprint paragraph extends with one sentence describing the additive identity and its baseline-vs-diff distinction.
- `docs/rules.md` is autogenerated from the rule catalogue and is not the JSON-shape home; no edit needed there.

**Cross-port:**

- `gruff-php/.goat-flow/tasks/0.1.4/M05-stable-identity-field-for-diffs.md` documents the same field name, same input set, same 16-char SHA-256 prefix — both sides adopt verbatim. The PHP side is still pending; the Python side ships first without blocking, and the byte-equivalence test (`test_json_byte_equivalence.py`) will pick up identical digests once both sides are populated with the same fixture.

## Reversibility

**Two-way door on the field name and input set.** The field is additive; renaming it or changing its inputs is a coordinated cross-port edit (gruff-py + gruff-php + tests + ADR) but does not invalidate any existing baseline file. Pre-condition for any rename is that no SARIF consumer has already shipped a `partialFingerprints.gruffStableIdentity` mapping; if one does, that becomes a SARIF schema break.

**One-way door on the cross-port byte equivalence.** Once both ports emit the same digest for the same logical finding, downstream tooling will hard-bake the digest values. Diverging the input set or hashing algorithm later requires a coordinated migration across every consumer.

**Revisit triggers:**

- A SARIF consumer requests the line-insensitive identity in `partialFingerprints`. Follow-up ADR adds the SARIF mapping and locks the name there.
- A new gruff-family port (gruff-rs, gruff-ts, gruff-go) requests the same field. Coordinate the same input set and name in that port; the ADR stands.
- `BaselineFilter` is upgraded to optionally consume `stableIdentity`. Major behaviour change for every existing baseline file; separate ADR, not this one.
- `message` template drift across ports causes spurious symbol-less identity churn. Mitigation is per-rule template normalisation, not changing the identity input set.
