# ADR-028: A module-qualified request receiver needs a same-file import binding

**Status:** Accepted
**Date:** 2026-08-12
**Ticket/Context:** 0.5.0 go-live remediation; narrows the receiver half of
ADR-017's taint-lite posture without widening its intra-procedural scope.

## Decision

Security rules treat an expression as the framework request object when its
receiver is one of exactly three shapes:

- a bare `request` name;
- `self.request`; or
- `<name>.request`, where `<name>` is bound by an `import` or `from ... import`
  statement anywhere in the same file.

Any other `<expr>.request` receiver is application data. `imported_module_names`
in `_security_node_helper.py` supplies the binding set, and both request-detecting
sites consume it: `_is_request_object` in `_security_taint_helper.py`, which
feeds `security.ssrf` and `security.path-traversal`, and `_is_request_attribute`
in `extract_compact_user_input_rule.py`, which backs
`security.extract-compact-user-input`. The two must not diverge again.

Conformance is checkable: `flask.request.args["u"]` under `import flask` is a
source, and `other.request.json` for a parameter `other` is not.

## Context

The receiver predicate originally accepted any `X.request`. On 2026-07-16, commit
`4a072aa` narrowed it to a bare `request` or exactly `self.request`, adding the
regression test `test_unrelated_request_attribute_is_not_a_framework_source`
in the same commit. The narrowing closed a real false positive, where an
application object exposing a `request` attribute seeded taint.

It also removed a detection path nobody recorded. Reproduced 2026-08-12 before
the fix:

| Expression | Tainted before |
| --- | --- |
| `request.args['u']` | yes |
| `self.request.json` | yes |
| `flask.request.args['u']` | no |
| `flask.request.args.get('u')` | no |
| `other.request.json` | no |

`security.ssrf` and `security.path-traversal` both construct a `TaintAnalyser`,
so both lost coverage for the module-qualified Flask idiom. The v0.5.0 CHANGELOG
entry describing framework request accessors predates the narrowing and never
mentioned it. `extract_compact_user_input_rule.py` was not narrowed at all, so
the two rules disagreed about what a request object is.

The commit that made the change is titled for an unrelated Markdown fix, which is
why the narrowing survived review. Recording the policy here is what stops the
next agent re-deriving it from the code alone.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Accept any `X.request` | An application object with a `request` attribute seeds taint, the false positive `4a072aa` closed | Rejected; reopens a known defect |
| Keep bare `request` / `self.request` only | `flask.request.*` never taints, so SSRF and path traversal miss a documented Flask idiom in silence | Rejected; a silent security regression outranks the tidier predicate |
| Hardcode a framework-module allowlist | Covers `flask` and nothing else without new evidence; every further framework is another edit, and naming unobserved frameworks would be invention | Rejected; the list is the maintenance burden |
| Require a same-file import binding | A local variable shadowing an imported module name still taints; `<mod>.request.<attr>` on an imported stdlib module would too, though no such attribute exists | Accepted; needs no framework names, and both residual shapes fail toward more findings on security rules |

## Reversibility

**Two-way door.** The binding set is computed per file from `ast` and feeds two
predicates; reverting means dropping the `imported_modules` argument. No
fingerprint, schema key, baseline, or finding message depends on it, so a revert
changes which findings appear and nothing about their identity.

Revisit if the import-binding set has to grow beyond same-file `import`
statements — alias chasing, `importlib`, re-exports, or type inference. That is
the boundary ADR-017 draws, and crossing it is a new decision rather than an
extension of this one.
