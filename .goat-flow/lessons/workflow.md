---
category: workflow
last_reviewed: 2026-05-27
---

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
`src/gruffpy/rule/catalog.py` (search: `class RuleDocs`), 4 of those
deliverables were already in the codebase: `rationale`, `fix_guidance`,
`bad_example`, `good_example`, `confidence_rationale`, and `config_keys` were
all carried by `RuleDocs`, auto-generated for ~109 rules and custom-curated
for 6. The escape-hatch helper existed as `_config_keys_for` (search:
`def _config_keys_for`). The genuinely-new work shrank to: two new fields on
`RuleDocs` (not `RuleDefinition` - see `.goat-flow/footguns/rules.md`,
search: `RuleDefinition.description.*short label`), a `RELATED_RULES` map,
the CLI surface, and option-description authoring for 12 rules. The milestone's
"~full day" estimate became "~half day" once the read was done.

Before scoping any feature framed as "extend the rule system with X", do a
focused read of `src/gruffpy/rule/catalog.py` (the `RuleDocs` dataclass and
the `_docs_for_definition` / `_custom_docs_for` factories) and
`src/gruffpy/rule/definition.py`. Confirm what data is already carried and
where. The split between hot-path data on `RuleDefinition` (travels with
every `Finding`) and durable docs metadata on `RuleDocs` is load-bearing -
adding to the wrong side either bloats every finding payload or hides docs
data from JSON consumers. The milestone scope is a starting point, not a
ceiling-and-floor; reading the codebase first saves both directions
(removes deliverables that already exist, and reveals the right container
for the genuinely-new ones).



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
