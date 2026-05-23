---
category: workflow
last_reviewed: 2026-05-23
---

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
