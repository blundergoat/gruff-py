---
category: performance
last_reviewed: 2026-05-17
---

## Pattern: Measure performance changes with the shipped harness

**Created:** 2026-05-17
**Context:** Performance changes to rule traversal and source discovery can look locally obvious but still move costs between workloads. The project has a purpose-built harness at `scripts/test-performance.sh` (search: "workload matrix") that measures CLI startup, analysis, reporting, synthetic scaling, RSS, cProfile attribution, and import time.

**Approach:** Before keeping a performance patch, run `scripts/test-performance.sh --repeat 3 --json <path>` before and after the change, compare workload medians, and inspect the generated cProfile attribution. Keep optimizations that improve the target workloads, but remove experiments that only improve a narrow case while regressing source analysis or RSS.

**Evidence:** `src/gruffpy/source/gitignore.py` (`GitignoreMatcher._ensure_loaded`) improved analysis by avoiding eager `.gitignore` scans through ignored project directories. `src/gruffpy/rule/complexity/_walks.py` (`iter_functions`), `src/gruffpy/rule/complexity/cyclomatic_complexity_rule.py` (`cyclomatic_for`), and `src/gruffpy/rule/complexity/_halstead.py` (`halstead_for`) show the kept AST-local caches where repeated rule calls reuse immutable parsed nodes. `src/gruffpy/rule/dead_code/unused_private_function_rule.py` (`_collect_references`) shows the kept rule-local reference aggregation that replaced repeated candidate-scope walks.

**Non-example:** Do not keep a broad shared `ast.walk` materialization cache just because it reduces call counts in cProfile. In this project, that experiment increased memory and made source-analysis medians worse under the harness, so it was removed.
