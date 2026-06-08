# ADR-005: Docstring style detection - parser choice

**Status:** Accepted
**Date:** 2026-05-14
**Ticket/Context:** `.goat-flow/tasks/0.1/M06-documentation-pillar-v0.1.md`; gate for the documentation pillar (10 rules, several of which need to compare docstring fields against Python signatures across Google, NumPy, and Sphinx styles).

## Decision

gruff-py's documentation pillar parses docstrings using **`docstring-parser`** (PyPI, MIT, pure Python, 22 KB wheel, zero runtime dependencies, ships `py.typed`). The library is wrapped behind one in-tree helper, `src/gruffpy/rule/docs/_docstring_parser.py`, that exposes a `ParsedDocstring` dataclass normalising Google / NumPy / Sphinx-`:param:` output into a single shape consumed by `docs.missing-param-doc`, `docs.missing-return-doc`, `docs.missing-raises-doc`, and `docs.stale-param-doc`.

Style auto-detection sequence inside the wrapper: try the library's Google parser, then NumPy, then Sphinx (`epydoc`/`rest`). If all three fail, the wrapper returns `None` and the field-mismatch rules emit zero findings for that docstring (they require parsable input - presence-only checks like `docs.missing-function-docstring` are unaffected).

The library is the only third-party docstring parser pinned by gruff-py. Rules MUST consume `_docstring_parser.py`; rules MUST NOT import `docstring_parser` directly. This isolates the dependency behind one swap point.

## Context

M06's field-aware rules (`missing-param-doc`, `missing-return-doc`, `missing-raises-doc`, `stale-param-doc`) need to extract per-parameter, per-return, and per-raises entries from a docstring written in any of the three styles Python codebases use in practice. The kill criterion in the milestone says: if no parser can handle all three with reasonable accuracy, the rules emit majority-false-positives and the pillar is dead.

Three options are available and the milestone explicitly requires this ADR to evaluate all three:

| Option | License | Maintenance | AST integration | Install size |
|---|---|---|---|---|
| **(a) `docstring-parser` on PyPI** | MIT | Active; latest 0.18.0 (April 2026); Python 3.8–3.14 declared support | Returns a typed `Docstring` AST per style; small public surface (`parse(text, style=Style.AUTO)`). `py.typed` marker ships. | **22 KB wheel** (verified via `pip download --no-deps`; 73 KB uncompressed across 9 files); **zero runtime deps**. PyPI JSON metadata's larger figure was bytes, not KB. |
| **(b) Vendor a fork of pydoclint's parser** | MIT (pydoclint), MIT (`docstring_parser_fork`) | pydoclint itself depends on `docstring_parser_fork` rather than upstream `docstring-parser`. Vendoring means inheriting whatever delta motivated the fork without owning the divergence-tracking work. | pydoclint's parser is tightly coupled to its linting passes; extracting just the parser requires cutting out checker code we don't want. | Smaller than installing pydoclint itself but adds in-tree maintenance load. |
| **(c) Hand-roll a Google / NumPy / Sphinx tokeniser** | Native | Owned in-tree | Cleanest - produces gruff's own dataclasses directly. | Zero new third-party deps. Estimated ~200–400 LOC plus a fixture corpus for each style's edge cases (indented continuations, mixed type-hint syntax, `Args:` vs `Parameters:`, ReST field-list grouping, type-in-name like `param (int):` vs `param: int`). |

The verified 22 KB wheel removes the install-size argument that initially looked like a strike against (a). With that adjusted, (a) wins on every axis the milestone asked about: license is permissive, maintenance is upstream and active, AST integration is exactly what M06 needs, and the install footprint is smaller than the YAML loader gruff-py already pins.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| **(a) `docstring-parser` library, wrapped behind `_docstring_parser.py`** (accepted) | Library upstream changes the AST shape between minor versions; gruff's wrapper has to absorb the change. | Accepted: the wrapper is the single swap point; upstream API has been stable through 0.15 → 0.18; cost of an absorption PR is bounded. Pure Python with zero transitive deps means no supply-chain surface beyond the one package. |
| **(b) Vendor pydoclint's parser fork** | Inherits a fork's drift from upstream `docstring-parser` without inheriting the fork's bug-fixing momentum. Pydoclint chose to fork upstream for reasons that aren't gruff's reasons; we'd be carrying their problem statement. | Rejected: greater long-term maintenance cost than (a) for no install-size win. The fork is itself MIT but the divergence justification is opaque to gruff. |
| **(c) Hand-roll three-style parser in-tree** | Edge cases in NumPy section indentation, Sphinx `:type:` vs `:param:` interleaving, and Google `Returns:` blocks with bullet lists silently produce wrong parses; gruff doesn't have a fixture corpus comparable to `docstring-parser`'s own test suite; gruff agents will be re-implementing edge-case fixes that upstream has already shipped. | Rejected: the 22 KB install cost is dramatically lower than the maintenance cost of owning the parser. The library's tests for edge cases are work gruff would otherwise repeat. |
| Defer field-aware rules to v0.2 | M06 ships fewer rules; the milestone's exit criteria can't be met. | Not chosen: M06 already specifies the 10-rule scope and the kill criterion only fires if *no* parser works, not if we shrink the pillar. |

## Consequences

- `pyproject.toml` `[project] dependencies` gains `docstring-parser>=0.15,<1`. This crosses an Ask First boundary per `CLAUDE.md`; the dep change happens as a separate, explicitly-approved follow-up to landing this ADR. The lower bound 0.15 is the first release with the stable `Style.AUTO` API used by the wrapper; the `<1` upper bound is a SemVer-style guard against a hypothetical 1.0 API rewrite.
- `src/gruffpy/rule/docs/_docstring_parser.py` is the only file that imports `docstring_parser`. A grep test in `tests/integration/` enforces the import isolation; rule modules import from the wrapper only.
- The wrapper's `ParsedDocstring` dataclass is a frozen, slotted value object (consistent with gruff-py's value-object pattern per the design-decisions memory). Fields: `summary`, `description`, `params` (tuple of `DocstringField`), `returns` (`DocstringField | None`), `raises` (tuple), `style` (enum of `google | numpy | sphinx | unknown`).
- If the auto-detection sequence returns `unknown`, field-mismatch rules (`missing-param-doc`, `missing-return-doc`, `missing-raises-doc`, `stale-param-doc`) skip the function and emit no findings. Presence-only rules (`missing-module-docstring`, `missing-class-docstring`, `missing-function-docstring`, `useless-docstring`, `todo-density`, `missing-readme`) are unaffected.

## Reversibility

**Two-way door.** The library is consumed only via `_docstring_parser.py`. Swapping to (b) vendor or (c) hand-roll requires rewriting one file plus its tests; no rule module or test fixture changes. The 22 KB install footprint means dropping the dep entirely costs nothing measurable in the install graph.

Revisit triggers (any of):

- Upstream `docstring-parser` stops releasing for >12 months AND a CVE or correctness bug lands without a maintainer response.
- A docstring style emerges in mainstream use (e.g. a hypothetical "PEP-XXX docstring schema") that the library refuses to support.
- The field-mismatch rules' false-positive rate on a dogfood corpus exceeds 20% and can be traced to a parser limitation that upstream won't fix.

When a revisit is triggered, the swap target is (c) hand-roll, not (b). (b) was the rejected middle path; if (a) fails, gruff owns the parser in-tree.
