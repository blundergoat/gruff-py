# ADR-017: Security taint-lite intra-procedural posture

**Status:** Accepted
**Date:** 2026-05-23
**Updated:** 2026-07-12 — approved a strict, sink-specific Markdown-link
sanitizer posture with bounded same-unit import binding recognition.
**Clarified:** 2026-07-12 — bounded request accessor calls preserve the finite
source vocabulary without changing the conservative unknown-call default.
**Ticket/Context:** M35 ships `security.ssrf` and `security.path-traversal`,
the first gruff-py rules that require source-to-sink reasoning rather than
single-AST-node pattern matching. Without an explicit posture the helper
that powers those rules will accumulate interprocedural ambitions and
become an engine the project does not have the resources to maintain.

## Decision

gruff-py's security taint analysis is **intra-procedural only**. The
analysis lives in a single module - `src/gruffpy/rule/security/_security_taint_helper.py`
- and obeys these rules:

1. **Scope is one `FunctionDef` / `AsyncFunctionDef`.** A tainted-name set
   is built per-function. Entering a nested function resets the set.
   Module-scope code is analysed as if it were a single anonymous
   function.
2. **Sources are an explicit, finite set.** Today this is
   `request.json/form/args/GET/POST/data/query_params/values`, direct
   `request.get_json()` (reused from `security.extract-compact-user-input`),
   plus FastAPI parameter annotations (`Query`, `Body`, `Path`, `Form`,
   `Header`, `Cookie`). New sources require an explicit code change, not
   configuration.
3. **Sanitisers are an explicit allowlist per rule.** Today:
   `urllib.parse.urlparse(...).netloc` chains and `validators.url(...)` for
   SSRF; `werkzeug.utils.secure_filename` and `os.path.realpath` for
   path traversal. Unknown calls are treated as **untainted** (the
   conservative posture - see the trade-off table below).
4. **Taint propagates through:** `Name` references, `Subscript`,
   `Attribute`, `BinOp(Add | Mod)`, `JoinedStr` (f-string),
   `<tainted>.format(...)`, and `get`/`getlist` only when their receiver is
   already tainted. Generic mappings, caches, unrelated `.data` attributes,
   and other methods such as `pop` remain untainted.
5. **Reassignment kills taint.** `x = request.json; x = "literal"`
   leaves `x` untainted at the sink.
6. **Branch joins are conservative.** If `x` is tainted in one branch and
   untainted in another, the join is **untainted** - favouring low
   false-positive rate over completeness.
7. **No interprocedural analysis, no import-graph resolution, no symbolic
   execution.** Apart from the finite direct/request-accessor seam above, a
   call result is untainted; an attribute read on a non-tainted name is
   untainted; a comprehension is treated as a single expression.
8. **No fingerprint or schema change.** Optional `metadata.source` and
   `metadata.sink` labels per ADR-011 are carried on findings but are
   not fingerprint inputs.
9. **Markdown links use a separate strict proof.** The advisory
   `security.unsanitized-markdown-interpolation` rule does not reuse or change
   the shared taint helper's unknown-call posture. A label or URL is safe only
   when the rule proves a literal, a matching configured sanitizer call, or
   bounded same-function provenance from one of those values. Unknown calls,
   uncertain branch joins, overwrites, and wrong-slot sanitizers remain unsafe.
10. **Markdown sanitizer imports are resolved only from syntax in the scanned
    unit.** Exact `import` and `from ... import ...` bindings, including aliases,
    may map a lexical call target to a configured canonical target. For example,
    `from urllib.parse import quote as encode_url` lets `encode_url(value)` match
    the configured `urllib.parse.quote` target until `encode_url` is rebound.
    Parameters, assignments, definitions, and later imports that replace a root
    kill that trust at the lexical position. Nested functions start fresh. The
    analysis never imports code, follows an import graph, or resolves a symbol
    through another module.
11. **Markdown sanitizer configuration is slot-aware and exact.** Public options
    are `labelSanitizers` and `urlSanitizers`; entries are non-empty Python call
    targets such as `markdown_label` or `helpers.markdown_url`, never wildcard or
    word-pattern matches. Labels trust no call by default. URLs trust only
    `urllib.parse.quote` and `urllib.parse.quote_plus` by default, and those
    defaults stop being safe when a splat or a non-literal/delimiter-preserving
    `safe` argument could retain `]`, `(`, or `)`. An explicit empty list trusts
    no call for that slot.

## Context

The gruff-py vs Bandit/Semgrep coverage matrix (worked through in this
session) identified two Python-specific security gaps that genuinely
require source-to-sink reasoning: SSRF (`requests.get(user_input)`) and
path traversal (`open(user_input)`). Every other gap in M33 and M34 was
representable as a single-AST-node match.

CodeQL and Semgrep ship full taint engines. Bandit does not - its rules
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
| Full interprocedural taint with import-graph resolution | Maintenance cost dominates the rest of gruff-py; FP rate on plausible Python idioms exceeds 25% on the framework fixtures we already have. | Rejected - wrong tool for a complementary linter. |
| Intra-procedural with **strict** posture (unknown call = tainted) | High recall but FP rate explodes (`str(x)`, `len(x)`, `x.lower()` all preserve taint and feed sinks; framework helpers we have not yet allowlisted cause findings users will tune off). | Rejected - erodes trust in security findings; per `.goat-flow/footguns/compatibility.md`, FP cost is higher than FN cost. |
| Intra-procedural with **conservative** posture (unknown call = untainted) | Lower recall: `str(tainted_url)` is treated as safe even though it isn't sanitised. Genuine vulnerabilities can slip through when a project wraps sources in unrecognised calls. | **Accepted** - this is the explicit trade-off. We complement Bandit / Semgrep, not replace them; FP rate matters more than recall for default-on rules. |
| Reuse the conservative unknown-call posture for Markdown link slots | `str(raw)` and `identity(raw)` silence the one rule whose purpose is to prove delimiter removal. | Rejected for this sink only. The Markdown rule is advisory, has explicit configurable sanitizer targets, and keeps its proof separate from the shared helper. |
| Match Markdown sanitizers by pure lexical spelling only | The dominant `from urllib.parse import quote; quote(url)` spelling produces a false positive unless every project repeats a bare-name override. | Rejected. Same-unit import bindings are finite syntax and rebinding-safe; they do not require import-graph resolution. |
| Resolve Markdown sanitizer bindings across modules | Trust can depend on runtime exports, monkeypatching, and import order that the local AST cannot prove. | Rejected - outside the intra-procedural budget and a direct route to false negatives. |
| Add taint to every existing rule that "might benefit" | The visitor protocol expands beyond what we can document; per-rule cost grows. | Rejected - taint stays restricted to rules where it is essential. SSRF and path-traversal are the two today. |
| Skip taint entirely; only ship single-node sinks | Cannot detect `requests.get(user_url)` or `open(user_path)` shapes - the most common SSRF / path-traversal patterns. | Rejected - leaves two of the highest-value Python security gaps uncovered. |

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

**Two-way for the Markdown import-binding grammar and slot defaults.** A future
change may remove a default or narrow binding recognition when paired attack
and safety fixtures show a false-negative path. Broadening either surface still
requires exact targets, rebinding controls, and operator review because it can
silence a security finding. Numeric construction remains untrusted beyond
literal values: broad arithmetic can render complex values with parentheses,
and trusting `int(...)` or annotations would require proving that built-ins and
runtime types were not rebound.

**Revisit triggers:**

- FP rate on Django/Flask/FastAPI fixture apps exceeds 25% (kill
  criterion in M35).
- A meaningful fraction (>10%) of consumer-rule findings cite the same
  sanitiser missing from the allowlist - at that point, formalise an
  allowlist-extension PR template.
- Sibling gruff implementations adopt a different taint posture that
  causes cross-impl JSON byte-equivalence drift on shared fixtures.
