# ADR-017: Security taint-lite intra-procedural posture

**Status:** Accepted
**Date:** 2026-05-23
**Ticket/Context:** M35 ships `security.ssrf` and `security.path-traversal`,
the first gruff-py rules that require source-to-sink reasoning rather than
single-AST-node pattern matching. Without an explicit posture the helper
that powers those rules will accumulate interprocedural ambitions and
become an engine the project does not have the resources to maintain.

## Decision

gruff-py's security taint analysis is **intra-procedural only**. The
analysis lives in a single module — `src/gruffpy/rule/security/_security_taint_helper.py`
— and obeys these rules:

1. **Scope is one `FunctionDef` / `AsyncFunctionDef`.** A tainted-name set
   is built per-function. Entering a nested function resets the set.
   Module-scope code is analysed as if it were a single anonymous
   function.
2. **Sources are an explicit, finite set.** Today this is
   `request.json/form/args/GET/POST/data/query_params/values` (reused from
   `security.extract-compact-user-input`) plus FastAPI parameter
   annotations (`Query`, `Body`, `Path`, `Form`, `Header`, `Cookie`).
   New sources require an explicit code change, not configuration.
3. **Sanitisers are an explicit allowlist per rule.** Today:
   `urllib.parse.urlparse(...).netloc` chains and `validators.url(...)` for
   SSRF; `werkzeug.utils.secure_filename` and `os.path.realpath` for
   path traversal. Unknown calls are treated as **untainted** (the
   conservative posture — see the trade-off table below).
4. **Taint propagates through:** `Name` references, `Subscript`,
   `Attribute`, `BinOp(Add | Mod)`, `JoinedStr` (f-string), and
   `<tainted>.format(...)` calls.
5. **Reassignment kills taint.** `x = request.json; x = "literal"`
   leaves `x` untainted at the sink.
6. **Branch joins are conservative.** If `x` is tainted in one branch and
   untainted in another, the join is **untainted** — favouring low
   false-positive rate over completeness.
7. **No interprocedural analysis, no import-graph resolution, no symbolic
   execution.** A call result is untainted; an attribute read on a
   non-tainted name is untainted; a comprehension is treated as a single
   expression.
8. **No fingerprint or schema change.** Optional `metadata.source` and
   `metadata.sink` labels per ADR-011 are carried on findings but are
   not fingerprint inputs.

## Context

The gruff-py vs Bandit/Semgrep coverage matrix (worked through in this
session) identified two Python-specific security gaps that genuinely
require source-to-sink reasoning: SSRF (`requests.get(user_input)`) and
path traversal (`open(user_input)`). Every other gap in M33 and M34 was
representable as a single-AST-node match.

CodeQL and Semgrep ship full taint engines. Bandit does not — its rules
are syntactic. gruff-py's posture is closer to Bandit's, but a tiny
bounded taint helper is a meaningful step up in precision without
becoming an engine.

The M17 milestone already introduced a same-scope literal-origin helper
(`verify = False; requests.get(url, verify=verify)`) for the
`security.disabled-ssl-verification` rule. This ADR generalises that
posture to identifier provenance, not just literal-false provenance.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Full interprocedural taint with import-graph resolution | Maintenance cost dominates the rest of gruff-py; FP rate on plausible Python idioms exceeds 25% on the framework fixtures we already have. | Rejected — wrong tool for a complementary linter. |
| Intra-procedural with **strict** posture (unknown call = tainted) | High recall but FP rate explodes (`str(x)`, `len(x)`, `x.lower()` all preserve taint and feed sinks; framework helpers we have not yet allowlisted cause findings users will tune off). | Rejected — erodes trust in security findings; per `.goat-flow/footguns/compatibility.md`, FP cost is higher than FN cost. |
| Intra-procedural with **conservative** posture (unknown call = untainted) | Lower recall: `str(tainted_url)` is treated as safe even though it isn't sanitised. Genuine vulnerabilities can slip through when a project wraps sources in unrecognised calls. | **Accepted** — this is the explicit trade-off. We complement Bandit / Semgrep, not replace them; FP rate matters more than recall for default-on rules. |
| Add taint to every existing rule that "might benefit" | The visitor protocol expands beyond what we can document; per-rule cost grows. | Rejected — taint stays restricted to rules where it is essential. SSRF and path-traversal are the two today. |
| Skip taint entirely; only ship single-node sinks | Cannot detect `requests.get(user_url)` or `open(user_path)` shapes — the most common SSRF / path-traversal patterns. | Rejected — leaves two of the highest-value Python security gaps uncovered. |

## Reversibility

**One-way for the conservative posture choice.** Switching from
"unknown call = untainted" to "unknown call = tainted" would change the
FP profile across every consumer rule; users would tune findings off
and trust would erode before a new ADR could restore the previous
behaviour. The decision is recorded so a future maintainer who is
tempted to flip the default knows what is being given up.

**Two-way for the source / sanitiser / sink lists.** These are
implementation lists in `_security_taint_helper.py` and the consumer
rule files; adding a source or sanitiser is a normal PR. Adding a sink
class typically also needs a new rule, but the helper does not need
amendment to support it.

**Revisit triggers:**

- FP rate on Django/Flask/FastAPI fixture apps exceeds 25% (kill
  criterion in M35).
- A meaningful fraction (>10%) of consumer-rule findings cite the same
  sanitiser missing from the allowlist — at that point, formalise an
  allowlist-extension PR template.
- Sibling gruff implementations adopt a different taint posture that
  causes cross-impl JSON byte-equivalence drift on shared fixtures.
