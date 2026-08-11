---
category: workflow
last_reviewed: 2026-08-12
---

## Lesson: Separate static contract defects from behavioral pressure failures

**Created:** 2026-08-06
**Incident:** PR #9 review feedback identified contradictory goat-plan mode
language and incomplete goat-critique outcome language. Deterministic reads
reproduced both defects, but six bounded RED pressure runs still chose the
intended behavior. Calling that a behavioral RED would have fabricated failure
evidence; ignoring the static contradictions would have left ambiguous
contracts installed across three agent mirrors.

Track the evidence separately. A contradictory instruction is a
`CONTRACT-GREP` defect even when agents infer the intended path. Pressure-test
results describe observed behavior only: use `RED no-repro` when the baseline
complies and `stay-GREEN smoke` for a later passing rerun. Do not claim
bulletproofing without three consecutive max-pressure passes after a real RED.

TDD evidence:
`.goat-flow/logs/sessions/2026-08-06-goat-plan-tdd.md` and
`.goat-flow/logs/sessions/2026-08-06-goat-critique-tdd.md`.

## Lesson: Always run `git status` before suggesting a commit message

**Created:** 2026-05-27
**Incident:** After shipping the M03+M04 work in a long session, the user asked
"give me one line commit message for uncommitted code". The agent generated a
message summarising every feature touched in the session (summary --group-by,
list-rules explain mode, output-volume hint, graceful ConfigError surfacing,
learning-loop updates) - drawn from session memory of what had been worked on,
not from `git status`. The user pointed out the mistake, asked for a one-line
message again, and the agent regenerated the same kind of summary message.
The user then asked verbatim "wtf, did u even run git status?". They had
committed the prior work between turns; only two staged files remained (the
learning-loop entries from the previous step). The suggested commit message
described work that was not in the staged diff.

Before suggesting any commit message, run `git status` (and `git diff --cached`
when something is staged, or `git diff` when nothing is staged) to see what is
actually about to be committed. Generating from session memory is a
hallucination risk: the user may have already committed some or all of the
work, may have unstaged or reverted edits, or may be on a different branch
than the agent thinks. The cost of one tool call is trivial; the cost of a
wrong message is the user having to call it out and ask again. This is CLAUDE.md
hallucination red-flag #2 ("do not claim completion without listing the
specific files changed in this turn") applied to commit-message synthesis:
the diff is the source of truth for the commit message, not the conversation
transcript.

## Lesson: Read `RuleDocs` (and the rule catalogue) before scoping any new rule-metadata feature

**Created:** 2026-05-27
**Incident:** M04 (list-rules explain mode) was originally scoped to add two
new fields to `RuleDefinition`, build per-rule prose for ~10 rules, derive an
escape-hatch introspection helper, and define cross-references. After reading
the `RuleDocs` dataclass — then in `catalog.py`, since moved to
`src/gruffpy/rule/catalog_docs.py` (search: `class RuleDocs`) — 4 of those
deliverables were already in the codebase: `rationale`, `fix_guidance`,
`bad_example`, `good_example`, `confidence_rationale`, and `config_keys` were
all carried by `RuleDocs`, auto-generated for ~109 rules and custom-curated
for 6. The escape-hatch helper existed as `_config_keys_for` (search:
`def _config_keys_for`). The genuinely-new work shrank to: two new fields on
`RuleDocs` (not `RuleDefinition` - see `.goat-flow/learning-loop/footguns/rules.md`,
search: `RuleDefinition.description.*short label`), a `RELATED_RULES` map,
the CLI surface, and option-description authoring for 12 rules. The milestone's
"~full day" estimate became "~half day" once the read was done.

Before scoping any feature framed as "extend the rule system with X", do a
focused read of `src/gruffpy/rule/catalog.py` and
`src/gruffpy/rule/catalog_docs.py` (the `RuleDocs` dataclass and
the `_docs_for_definition` / `custom_docs_for` factories) and
`src/gruffpy/rule/definition.py`. Confirm what data is already carried and
where. The split between hot-path data on `RuleDefinition` (travels with
every `Finding`) and durable docs metadata on `RuleDocs` is load-bearing -
adding to the wrong side either bloats every finding payload or hides docs
data from JSON consumers. The milestone scope is a starting point, not a
ceiling-and-floor; reading the codebase first saves both directions
(removes deliverables that already exist, and reveals the right container
for the genuinely-new ones).

**2026-07-13 follow-up:** `RuleDocs.config_keys` contains suffixes relative to
`rules.<rule-id>`, not arbitrary fully qualified configuration paths.
`src/gruffpy/cli_list_rules.py` (search: `_rule_detail_escape_hatches`) prefixes
every entry with `rules.<rule-id>.`. Putting the global
`allowlists.acceptedAbbreviations` key there rendered the invalid path
`rules.naming.abbreviation.allowlists.acceptedAbbreviations`; the focused
payload test passed until the human-readable `list-rules` proof exposed it.
Keep global escape hatches in curated prose unless a separately designed docs
field and renderer path is approved, and always run the final explain command
when changing `config_keys`.



## Lesson: Never offer to commit - "offering" still violates the Never tier

**Created:** 2026-05-23
**Incident:** During the M33+M34+M35 security-rules session (12 + new rule
files added across three milestones), the agent ended **every** batch
summary (M33 close, M34 batch 1, M34 batch 2, M34 batch 3a, M34 batch 3b,
M35 close - six times across the session) with a variation of "want me
to commit this?" or "commit now and continue, or pile on more?". The
user did all the commits themselves and finally said:
"no you never commit, that should be in your instructions". It already
was - `CLAUDE.md` lists "NEVER commit, push, publish, or delete user
work" in the Never autonomy tier at the top of the file. The agent
read that line at the start of the session and proceeded to violate it
six times.

The rationalisation pattern was: "offering to commit isn't the same as
committing; I am giving the user an option". That framing is wrong. A
Never-tier instruction covers *proposing* the action too, because every
unprompted offer is friction the user has to deflect. The user does
not need a commit decision-prompt at the end of every batch; they will
decide when to commit and ask if they want help with a message.

When CLAUDE.md says NEVER for a class of actions, that class includes
proposing those actions, asking permission to do them, and structuring
end-of-batch summaries around a "should we do X?" gate where X is in
the prohibited class. The agent should end summaries by describing
what changed and the next *technical* step, never the next *publishing*
step. The same rule covers `git push`, `gh pr create`, `gh pr merge`,
and anything else in the publish-user-work family.

## Lesson: Treat CLAUDE.md Never-tier items as absolute, not preferences to weigh

**Created:** 2026-05-23
**Incident:** Same session as above. The agent had read `CLAUDE.md`
including its Never tier, then over the course of ~12 batches treated
the commit prohibition as a soft preference to balance against
end-of-batch helpfulness. That is the wrong calibration for a Never
item.

CLAUDE.md's autonomy tiers split into Always (mandatory), Ask First
(boundary-flagged), and Never (forbidden). The Never tier is not a list
of strongly-discouraged actions - it is a list of disallowed actions.
Read tier 3 the way a function reads `raise NotImplementedError`: this
path does not exist for the agent.

When summarising at the end of a chunk of work, check the proposed
next-step against the Never tier. If the next step (or any next step
on the menu offered to the user) involves a Never-class action,
delete that option. Suggest something else, or stop suggesting and
let the user drive. Do not present a forbidden action as one of the
multiple-choice options.

## Lesson: Do not bundle destructive cleanup with productive work in one command

**Created:** 2026-06-04
**Incident:** While reproducing the static-analysis-redundant-test false positives
(see `.goat-flow/learning-loop/lessons/verification.md`, search: `crafted fixture`), the agent
put a heredoc append (`cat >> fixture.py <<'PY' ... PY`) and `rm -rf <dir>` in a
single Bash command. The `deny-dangerous.sh` PreToolUse guard
(`.goat-flow/hooks/deny-dangerous.sh`) rejected the whole command for `rm -r without
safe scoping`, so the append never ran. The next `gruff-py analyse` showed the
newly-added case "not firing", which contradicted the agent's own AST
introspection and cost a debugging detour until `wc -l` showed the fixture was
unchanged from before the blocked command.

When a guard hook can reject a command, never combine a destructive op (`rm -r`,
etc.) with productive work in the same compound command: a rejection drops the
entire command, so the productive part silently does not run and the next step's
result looks inexplicably wrong. Run cleanup as its own final command, and prefer
forms the guard accepts - `rm <file>` then `rmdir <dir>` rather than
`rm -rf <dir>`. More generally, when a result contradicts a check you already
proved, first confirm the prior mutation actually applied (`wc -l`,
`git status`, `md5sum`) before re-theorising.

## Lesson: Keep inline verification scripts below shell-guard complexity limits

**Created:** 2026-07-11
**Incident:** While validating the repaired 0.5.0 milestone tree, the agent sent
one long read-only Python heredoc containing structure, link, risk-order, and
index checks. `.goat-flow/hooks/deny-dangerous.sh` rejected it before execution
as having more than 50 chained segments. A later path-check heredoc was also
rejected because its regular expression contained literal backticks, which the
guard conservatively classified as hidden command substitution. Neither failure
was a plan-validation result; both commands had to be reshaped and rerun.

The trap recurred on 2026-08-05 when one combined read-only heredoc tried to
replay five independent PR-review reproductions. The same 50-segment guard
blocked it before execution; five small `python -c` probes then produced the
required defect-specific evidence independently.

M34 hit the related pipe-to-shell guard while replaying a local hook payload
with `printf ... | bash .goat-flow/hooks/gruff-code-quality.sh`. A here-string
into that known local script delivered the same JSON without weakening the
guard and produced `APPLY_PATCH_HOOK_EXIT=0`.

When an inline validator contains many statements, split it into independently
named checks whose output states exactly what passed (`STRUCTURE`, `RISK ORDER`,
`LINKS`, `INDEX`). When a read-only script must inspect Markdown backtick spans,
construct the delimiter inside the script (for example `chr(96)`) instead of
placing literal backticks in the shell command text. Treat any PreToolUse block
as “not run,” never as evidence about the artifact. Feed a known local script
through input redirection or a here-string instead of piping generated text to
a shell interpreter.

## Lesson: New request fields need a fail-closed compatibility default

**Created:** 2026-07-12
**Incident:** While adding the dashboard public-bind acknowledgment, the agent
made `has_acknowledged_public_bind` a required `_DashboardCliRequest` field.
Focused CLI tests passed because Click supplied the new value, but the existing
dashboard-server suite had six direct request constructors and failed before
testing form-state behavior.
**Evidence:** `src/gruffpy/cli_dashboard.py` (search:
`has_acknowledged_public_bind`) - the Boolean request field now defaults to
false; `tests/integration/test_dashboard_server.py` (search:
`def _dashboard_request`) - direct internal construction intentionally omits
the CLI-only acknowledgment and therefore remains fail-closed.

When extending an internal request dataclass, grep every constructor before the
first green claim. If omission has a safe meaning, encode that meaning as a
fail-closed default; otherwise update every caller explicitly and run both the
entry-point tests and the direct-consumer suite.

## Lesson: Split regression tests by review surface before dogfood

**Created:** 2026-05-31
**Updated:** 2026-07-13
**Incident:** While adding correlated scoring coverage, one test asserted file
score, composite score, and pillar penalties together. The full pytest suite
passed, but `uv run gruff-py analyse src tests --fail-on advisory --no-baseline`
flagged `test-quality.eager-test` because the test had too many assertions.

The pattern repeated during per-rule option validation: functional, static,
and manual gates were green, but dogfood found warning wording, accepted-name
alternatives, and applied-setting semantics packed into two eager tests. It
also found raw numeric values repeated in assertions. Splitting those three
review surfaces and naming the configured value made the original dogfood
reproduction return zero findings without deleting any assertion.

M09 repeated the same trap across reporters: one test combined native JSON and
hotspot shape assertions, while another combined text, Markdown, and HTML
terminology. Root dogfood found two eager tests even though all focused gates
passed. Splitting by automation, terminal, pull-request, and browser review
surface preserved every assertion and made the exact dogfood reproduction
return zero findings.

M29 repeated it in a smaller form: one curated-rule-doc test combined global
allowlist routing, replacement semantics, four vocabulary examples, and the
false-positive payload contract. Focused tests and the full suite passed, but
root dogfood counted 11 assertions. Splitting allowlist guidance from
false-positive guidance preserved the contract and kept each review surface
cohesive.

M34 repeated the raw-literal branch at one assertion: the Codex hook contract
test compared its timeout directly with `90`. Focused pytest and ruff passed,
but root dogfood reported `test-quality.magic-number-assertion`. Naming the
timeout contract cleared the exact finding without suppressing the rule.

When a regression spans multiple outputs, keep one test per reviewer surface
even if the setup is shared. This preserves the signal of
`test-quality.eager-test` and keeps dogfood aligned with the
reviewer-verification mission. Name configured boundary values before asserting
them so the test explains the user's choice instead of embedding a magic number.

## Lesson: Prove generated comments semantically before a broad write

**Created:** 2026-08-12
**Decision changed:** A comment-coverage codemod must pass a representative diff review before it may write beyond one file.
**Trigger phase:** ACT
**Incident count:** 1
**Latest occurrence:** 2026-08-12

**Incident:** A source-wide documentation pass tried two deterministic codemods after a hand-written file established the desired shape. The first inserted repeated
“this case applies” comments; the second included identifiers but produced phrases such as “needs parse ranges.” Ruff also rejected the generated docstring lines at the
repository's 100-character limit. Both batches were reversed before behavior verification because they narrated structure instead of explaining a caller consequence.

For comment-density work, let an audit identify omissions but keep prose generation semantic. Before a bulk writer can expand past one file, inspect a sample containing a
branch, loop, exception, existing structured docstring, and missing private-method docstring. Reject the writer if phrases repeat, expose syntax as prose, or fail the normal
lint width. Structural completeness is not evidence of readable comments.
