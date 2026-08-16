# ADR-027: Route the score inversion to family ratification

**Status:** Accepted
**Date:** 2026-08-11
**Ticket/Context:** 0.5.x family remediation; supplies measured gruff-py input
to the scoring ratification reserved by `FAMILY-CONTRACT.md` section 12.

## Context

Fresh no-config corpus scans on 2026-08-11 still ranked the deliberately
vulnerable PyGoat application above established libraries after confirmed rule
false positives were removed:

| Repository | Findings before | Findings after | Composite before | Composite after |
| --- | ---: | ---: | ---: | ---: |
| PyGoat | 437 | 435 | 56.27 | 58.45 |
| requests | 1,085 | 1,080 | 19.45 | 19.45 |
| Flask | 1,293 | 1,290 | 18.80 | 22.40 |
| pytest | 11,231 | 11,221 | 6.55 | 12.73 |

The precision pass removed two `test-quality.no-assertions` findings from
direct-imported `pytest.raises` calls and eighteen
`sensitive-data.pii-test-fixture` findings caused by incidental corpus-parent
names or sequential digit fixtures. It did not change scoring. Every repository
still grades F, and PyGoat remains more than 2.5 times higher than the best
clean comparison.

The documentation-overlap check found no function definition that received
`docs.missing-function-docstring` together with `docs.missing-param-doc`,
`docs.missing-return-doc`, or `docs.missing-raises-doc`. Collapsing findings
would therefore remove distinct documentation obligations rather than fix the
suspected triple-counting defect.

`FAMILY-CONTRACT.md` section 12 names the Python/PHP score model as the family's
canonical proposal pending ratification. Its severity weights, confidence
weights, pillar formula, and correlated-complexity cluster key are
compatibility-sensitive inputs. A local retune made only to improve this corpus
ordering would weaken that proposal before the family evaluates it.

## Decision

Keep the current gruff-py score calculation unchanged through the 0.5.x
remediation. Route the measured inversion above into the section 12 family
ratification instead of changing penalty weights, the pillar formula, the
cluster key, or security severity.

Until ratification resolves the calibration problem, describe cross-repository
composite scores as volume-sensitive and do not use them to claim that one
repository is safer or higher quality than another. Findings and pillar evidence
remain useful for reviewing one codebase; the unsupported claim is comparative
ranking across projects with different size and composition.

Any future calibration change must be coordinated across the family, land with
the planned JSON compatibility break, rerun the shared corpus, and preserve
gruff-py's reviewer-verification and security posture.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Preserve the model and route measured inversion to family ratification | Cross-project grades remain misleading during 0.5.x | Accepted. It preserves the contracted canonical proposal and gives ratification current evidence instead of tuning one port in isolation. |
| Retune weights or the pillar formula in gruff-py | Family scores diverge before the planned compatibility break; corpus-fitting may weaken security or reviewer-verification signals | Rejected. Section 12 reserves this decision for family ratification. |
| Collapse documentation findings broadly | Documented functions missing distinct parameter, return, or raises sections lose separate evidence; the measured undocumented-symbol overlap is zero | Rejected. The suspected double-counting defect is absent. |
| Remove composite grades from 0.5.x | Existing report contracts change outside the requested remediation and before sibling coordination | Rejected. Disclosure is sufficient until the family decides the replacement or calibration. |

## Reversibility

This is a two-way routing decision: no scoring code changes. A ratified family
scoring specification supersedes it. Revisit when section 12 is ratified, when
the shared corpus gains an agreed cross-project calibration method, or when a
scoring change is prepared for the coordinated JSON compatibility break.
