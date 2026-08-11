---
category: performance
last_reviewed: 2026-08-11
---

## Pattern: Measure performance changes with the shipped harness

**Created:** 2026-05-17
**Context:** Performance changes to rule traversal and source discovery can look locally obvious but still move costs between workloads. The project has a purpose-built harness at `scripts/test-performance.sh` (search: "workload matrix") that measures CLI startup, analysis, reporting, synthetic scaling, RSS, cProfile attribution, and import time.

**Approach:** Before keeping a performance patch, run `scripts/test-performance.sh --repeat 3 --json <path>` before and after the change, compare workload medians, and inspect the generated cProfile attribution. Keep optimizations that improve the target workloads, but remove experiments that only improve a narrow case while regressing source analysis or RSS.

**Evidence:** `src/gruffpy/source/gitignore.py` (`GitignoreMatcher._ensure_loaded`) improved analysis by avoiding eager `.gitignore` scans through ignored project directories. `src/gruffpy/rule/complexity/_walks.py` (`iter_functions`), `src/gruffpy/rule/complexity/cyclomatic_complexity_rule.py` (`cyclomatic_for`), and `src/gruffpy/rule/complexity/_halstead.py` (`halstead_for`) show the kept AST-local caches where repeated rule calls reuse immutable parsed nodes. `src/gruffpy/rule/dead_code/unused_private_function_rule.py` (`_collect_references`) shows the kept rule-local reference aggregation that replaced repeated candidate-scope walks.

**Non-example:** Do not keep a broad shared `ast.walk` materialization cache just because it reduces call counts in cProfile. In this project, that experiment increased memory and made source-analysis medians worse under the harness, so it was removed.

## Pattern: Gate expensive rule walks with necessary source tokens

**Created:** 2026-05-20
**Context:** Syntax-aware parsers and rules that inspect rare shapes can spend
most of their time traversing files that cannot match. A 2026-08-11
cryptography scan exposed the parser form of this problem: the suppression
parser tokenized a 5.9 MB JSON vector even though the source contained no
`gruff` marker.

**Approach:** Before walking an AST or tokenizing a complete source file, add a
conservative source-text gate only when the token is required by the existing
matcher. Examples: `src/gruffpy/rule/security/disabled_ssl_verification_rule.py`
(`_SOURCE_NEEDLES`) requires `verify`, `_create_unverified_context`, or
`disable_warnings`; `src/gruffpy/rule/security/unsafe_yaml_load_rule.py`
requires `yaml`; `src/gruffpy/rule/waste/unused_import_rule.py`
(`_collect_used_names`) keeps annotation parsing tied to the same walk that
collects direct import uses. `src/gruffpy/suppression/parser.py`
(`parse_suppressions`) requires a case-insensitive `gruff` marker before Python
tokenization. Do not gate on a token that is merely common in positive examples
if the structural matcher can fire without it.

**Evidence:** The marker gate reduced the 281-file cryptography scan from 621.07
seconds to 16.46 seconds while retaining all 3,889 findings; normalized
before/after findings were identical. Earlier source gates and unused-import
walk consolidation also passed `scripts/test-performance.sh` without
regressions: observed medians improved for `analyse-src-text` from 3.5779s to
3.1986s, `analyse-src-json` from 3.4860s to 3.0260s, and `synthetic-1000` from
5.2085s to 4.8498s.
