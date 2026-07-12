---
category: rule-verification
last_reviewed: 2026-07-12
---

## Lesson: New test docstrings need complete fixture and failure contracts before dogfood

**Created:** 2026-07-12
**Incident:** During safe `init --force` verification, focused tests, ruff, and
mypy were green, but the required dogfood scan failed on seven documentation
findings in newly rewritten tests. Four journey docstrings described the
behavior but omitted their `tmp_path` and `monkeypatch` parameters; a nested
filesystem-failure helper omitted both parameters and its deliberate
`OSError`; one schema-recovery test omitted `tmp_path`. Adding the missing
`Args` and `Raises` contracts made the same dogfood reproduction return zero
findings without changing test behavior. The same trap recurred while hardening
Markdown sanitizer provenance: 20 parametrized rule tests had concise behavior
docstrings but no `Args` entries, and dogfood—not pytest, ruff, or mypy—was the
first gate to reject them.

The same trap recurred during scalar Boolean annotation verification: seven
new parametrized matrix tests described the scan behavior but omitted their
parameter contracts. Focused pytest, ruff, and mypy were green; the root
dogfood scan reported all seven `docs.missing-param-doc` findings. Adding exact
`Args` entries for declaration templates, metadata kinds, and annotation
spellings cleared that surface without changing an assertion.

Before broad dogfood, check every new or materially rewritten test docstring
against its full signature, including pytest fixtures. A nested helper that
models a user-visible failure also documents the exception it deliberately
raises. Focused pytest and static type checks do not cover these documentation
rules because the project analyser scans `tests/` as product-quality code.

## Lesson: File-size splits must expose cross-file helper ownership

**Created:** 2026-07-12
**What happened:** The Markdown sanitizer provenance helper exceeded the
project's 1,000-line error threshold, so it was split into a statement index and
a flow model. Seven underscore-prefixed model functions were imported and used
by the sibling index, but `dead-code.unused-private-function` intentionally
checks a private function's enclosing module and reported every one as unused.
Renaming only the cross-file API to public names inside the still-private module
made ownership honest; module-internal helpers remained private.
**Evidence:**
`src/gruffpy/rule/security/_markdown_sanitizer_model.py` (search:
`def combine_expression_safety`) and
`src/gruffpy/rule/security/_markdown_sanitizer_provenance.py` (search:
`combine_expression_safety`) — the defining and consuming anchors are now
explicit, and the repeated root dogfood scan returned zero findings.
**Prevention:** Before splitting a large module, classify each moved symbol as
module-internal or cross-file API. Give cross-file helpers public names even
when their module is private, add full return/field documentation during the
move, and run root dogfood immediately after the split rather than relying on
import-aware lint or type checks.
