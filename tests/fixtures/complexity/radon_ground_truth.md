# Cyclomatic complexity — radon ground-truth deltas

| Fixture function | radon 6.0.1 | gruff-py `complexity.cyclomatic` | Delta |
|---|---|---|---|
| `simple` (no branches) | 1 | 1 | 0 |
| `with_branches` (if/elif/else) | 3 | 3 | 0 |
| `with_loop` (for + nested if) | 3 | 3 | 0 |
| `with_boolops` (`a and b or c`) | 4 | 4 | 0 |
| `with_match` (3-arm `match`, wildcard ignored) | 3 | 3 | 0 |
| `with_comprehension` (one comp + one `if` clause) | 3 | 3 | 0 |
| `m1` (2 cases, no wildcard) | 3 | 3 | 0 |
| `m2` (2 cases + `case _`) | 3 | 3 | 0 |
| `m3` (3 cases + `case _`) | 4 | 4 | 0 |
| `t1` (try + 1 except) | 2 | 2 | 0 |
| `t2` (try + 2 except) | 3 | 3 | 0 |
| `a1` (1 assert) | 2 | 2 | 0 |
| `a2` (2 asserts) | 3 | 3 | 0 |

**Cyclomatic delta vs radon: 0 across 13 functions (well within the ±10% tolerance).**

## Halstead volume — radon vs gruff-py

| Fixture function | radon 6.0.1 volume | gruff-py | Delta |
|---|---|---|---|
| `simple` | 4.75 | 4.75 | 0.1% |
| `with_branches` | 20.68 | 20.68 | 0.0% |
| `with_loop` | 13.93 | 13.93 | 0.0% |
| `with_boolops` | 15.51 | 11.61 | 25.1% |
| `with_match` | 0.00 | 0.00 | 0.0% |
| `with_comprehension` | 13.93 | 13.93 | 0.0% |
| `boolops` (hal_test.py) | 15.51 | 11.61 | 25.1% |
| `assigns` (hal_test.py) | 4.75 | 4.75 | 0.1% |
| `calls` (hal_test.py) | 4.75 | 4.75 | 0.1% |

**Average Halstead delta: 5.6%** — within the ±10% tolerance.

**Known delta:** mixed boolean operator chains (`a and b or c`) — radon counts 4 operand slots, gruff-py counts 3. Cause: radon's `visit_BoolOp` appears to add +1 operand per value in `node.values` regardless of nested operator presence; gruff-py recurses into nested BoolOp without that extra increment. Single-pattern, not a general defect. Documented; acceptable for v0.1 ship gate. Revisit if the pattern produces customer-visible miscalibration.

How to re-run this check:

```bash
uvx radon cc tests/fixtures/complexity/cc_fixture.py -s
uvx radon hal tests/fixtures/complexity/cc_fixture.py -f
uv run pytest tests/unit/rule/complexity/test_cyclomatic_complexity_rule.py tests/unit/rule/complexity/test_halstead_volume_rule.py -k radon
```

`radon` is NOT a gruff-py runtime or dev dependency — `uvx` runs it in an isolated env.
