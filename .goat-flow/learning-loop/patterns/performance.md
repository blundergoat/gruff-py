---
category: performance
last_reviewed: 2026-05-20
---

## Pattern: Measure performance changes with the shipped harness

**Created:** 2026-05-17
**Context:** Performance changes to rule traversal and source discovery can look locally obvious but still move costs between workloads. The project has a purpose-built harness at `scripts/test-performance.sh` (search: "workload matrix") that measures CLI startup, analysis, reporting, synthetic scaling, RSS, cProfile attribution, and import time.

**Approach:** Before keeping a performance patch, run `scripts/test-performance.sh --repeat 3 --json <path>` before and after the change, compare workload medians, and inspect the generated cProfile attribution. Keep optimizations that improve the target workloads, but remove experiments that only improve a narrow case while regressing source analysis or RSS.

**Evidence:** `src/gruffpy/source/gitignore.py` (`GitignoreMatcher._ensure_loaded`) improved analysis by avoiding eager `.gitignore` scans through ignored project directories. `src/gruffpy/rule/complexity/_walks.py` (`iter_functions`), `src/gruffpy/rule/complexity/cyclomatic_complexity_rule.py` (`cyclomatic_for`), and `src/gruffpy/rule/complexity/_halstead.py` (`halstead_for`) show the kept AST-local caches where repeated rule calls reuse immutable parsed nodes. `src/gruffpy/rule/dead_code/unused_private_function_rule.py` (`_collect_references`) shows the kept rule-local reference aggregation that replaced repeated candidate-scope walks.

**Non-example:** Do not keep a broad shared `ast.walk` materialization cache just because it reduces call counts in cProfile. In this project, that experiment increased memory and made source-analysis medians worse under the harness, so it was removed.

## Pattern: Gate expensive rule walks with necessary source tokens

**Created:** 2026-05-20
**Context:** Rule modules that inspect rare sink shapes can spend most of their
cost walking ASTs for files that cannot possibly match. This showed up in the
performance harness cProfile after `scripts/test-performance.sh --json
perf-out/perf-before.json`: security rule `analyse` methods cumulatively spent
over two profiled seconds walking `src/` even though most files had no matching
security sink tokens.

**Approach:** Before walking an AST, add a conservative source-text gate only
when the token is required by the existing matcher. Examples: `src/gruffpy/rule/security/disabled_ssl_verification_rule.py`
(`_SOURCE_NEEDLES`) requires `verify`, `_create_unverified_context`, or
`disable_warnings`; `src/gruffpy/rule/security/unsafe_yaml_load_rule.py`
requires `yaml`; `src/gruffpy/rule/waste/unused_import_rule.py`
(`_collect_used_names`) keeps annotation parsing tied to the same walk that
collects direct import uses. Do not gate on a token that is merely common in
positive examples if the AST matcher can fire without it.

**Evidence:** After the source gates and unused-import walk consolidation,
`scripts/test-performance.sh --json perf-out/perf-after.json --baseline
perf-out/perf-before.json` reported no regressions. Medians improved on
`analyse-src-text` from 3.5779s to 3.1986s, `analyse-src-json` from 3.4860s to
3.0260s, and `synthetic-1000` from 5.2085s to 4.8498s in the observed run.
