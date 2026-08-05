---
goat-flow-reference-version: "1.13.1"
---
# Milestone Template - Detailed Field Reference

Extracted from the goat-plan SKILL.md to keep the skill file within word budget. The SKILL.md retains a concise summary; this file has the full field descriptions and worked examples.

## Contents

- Milestone field descriptions
- Assumption tracking
- Path-only intake example
- Mode 4 file-write example
- Risk-tagged milestone example
- Phase 3 human verification gate example
- Kill-criteria-triggered stop example

## Milestone Field Descriptions

For each milestone, produce:

- **Objective** - 1-2 sentences: what this milestone proves or delivers
- **Tasks** - Checkboxes. Ordered by dependency, riskiest first. Each task is a concrete action, not a vague goal. Tag each task with a risk level: `[RISKY]` unknowns/integrations/unproven assumptions, `[CORE]` essential logic, `[SAFE]` straightforward work. Order: all [RISKY] first, then [CORE], then [SAFE].
- **Assumptions to validate** - What must be proven true during this milestone (not tasks - beliefs about the system)
- **Exit criteria** - Testable, binary pass/fail. Not "performance is acceptable" - instead "p95 latency under 500ms"
- **Testing gate** - What must be verified before starting the next milestone:
  - Static / Contract Check: language-appropriate static analysis (linters, type checkers) that must pass before behavioural tests run
  - Automated: which test commands must pass
  - Manual: what a human must check (checkbox list, one action + one expected result per item)
  - Acceptance: who signs off (developer self-check, QA review, or stakeholder demo)
- **Mid-implementation proof** - for milestones expected to touch 3+ files or run longer than 30-60 minutes, name one focused command, reproduction, or smoke check to run before switching modules or after a bounded edit batch
- **Kill criteria** - What would make us stop at this milestone rather than continue
- **Depends on** - Which milestone must complete first
- **Read first** - Files the implementing agent should read before starting this milestone

## Assumption Tracking

Assumptions are not tasks - they're beliefs about the system that affect the plan:

The bracketed entries below are template placeholders, not execution evidence. Replace them with claims and proof from the active task.

```markdown
## Assumptions to validate

- [ ] [Claim that changes the plan if false] (unverified)
- [x] [Validated claim] ([literal command output or observation from this session])
- [ ] [Invalidated claim] (INVALIDATED: [evidence]; plan updated at [path and anchor])
```

When an assumption is validated, tick it and note the evidence. When an assumption is invalidated, update the milestone plan immediately - don't continue building on a false premise.

## Worked Example - Path-Only Intake

User message: `.goat-flow/plans/<existing-plan>/`

Evidence read: the active pointer and existing milestone status/task fields at the supplied path.

Expected output:

```markdown
Mode: Path-Only Intake. [Plan path] is [active/inactive]. [Literal status summary]. Current unchecked task: [literal task or none]. Next action needed: summary, status check, plan update, or start a specific milestone?
```

Expected outcome: no writes to `.goat-flow/plans/.active`, milestone status fields, task checkboxes, or code.

## Worked Example - Mode 4 File-Write

User message: `Create milestones for [approved outcome].`

Expected writes:
- `.goat-flow/plans/.active` is a one-line pointer: `<plan-slug>`
- `.goat-flow/plans/<plan-slug>/ISSUE.md`
- `.goat-flow/plans/<plan-slug>/M01-<milestone-slug>.md`

Expected milestone shape; every bracketed value must be replaced with active-task evidence:

```markdown
# Milestone 01: [Riskiest bounded outcome]

Status: not-started

## Objective

[One testable outcome.]

## Tasks

- [ ] [RISKY] [Prove the highest-risk assumption]
- [ ] [CORE] [Implement the approved behaviour]
- [ ] [SAFE] [Reconcile documentation or mirrors]

## Assumptions to validate

- [ ] [Load-bearing claim] (unverified)

## Exit criteria

- [ ] [Binary acceptance condition]

## Testing Gate

### Static / Contract Check

- [ ] `[exact project command]` exits 0

### Automated

- [ ] `[focused test command]` reports zero failures

### Manual

- [ ] [One action]; expected: [one observable result]

### Acceptance

- [ ] [Named human or role] approves the evidence

## Mid-implementation proof

- [ ] `[focused command or reproduction]` produces [expected result]

## Kill criteria

- Stop if [specific observation invalidates the plan].

## Depends on

- None

## Read first

- `[actual relevant path]`

## Deferred

- None
```

Expected checkpoint: `Milestone files + ISSUE.md written to .goat-flow/plans/<plan-slug>/. Ready to start implementation.`

## Worked Example - Risk-Tagged Milestone

```markdown
## Tasks

- [ ] [RISKY] [Run the evidence-producing spike]
- [ ] [RISKY] [Validate the remaining external dependency]
- [ ] [CORE] [Implement essential logic]
- [ ] [SAFE] [Update generated or explanatory material]
```

## Worked Example - Phase 3 Human Verification Gate

Use this template only after running the checks. Replace every bracketed value with literal evidence from the current session; never mark a placeholder complete.

```markdown
M01 complete - Human Verification Gate (BLOCKING)

Files changed this session:
- `[actual path]` - [observed delta]

Exit criteria (evidence from this session):
- [x] [Criterion] - `[literal command]`: [literal pass line]
- [ ] [Manual criterion] - pending human verification

Assumptions:
- [x] [Validated claim] ([literal evidence])
- [ ] [Invalidated claim] - INVALIDATED: [literal evidence]. [Next milestone] updated at [path and anchor].

M01 complete. Approve to proceed with M02, or adjust?
```

The agent stops here and waits. It does not set M02 to `in-progress`, tick M02 tasks, or touch code until the human approves. Any invalidated assumption has already amended M02's scope per the Milestone Retrospective protocol in `skill-conventions.md`.

## Worked Example - Kill-Criteria-Triggered Stop

Use this template only after a named kill criterion reproduces. Replace each bracketed value with current-session evidence.

```markdown
KILL CRITERIA TRIGGERED - M01 (BLOCKING GATE)

Trigger: `[literal reproduction command]` - [literal failing result]. Proof-class: [RUNTIME or CONTRACT-GREP], this session.

Impact: [Named assumption] is false, so [dependent milestone and requirement] are blocked.

Options: (a) [approved alternative], (b) [re-scope path], (c) abandon the plan.

Stopping. No further milestones started. Which direction?
```

A triggered kill criterion is a BLOCKING GATE (see SKILL.md Constraints, "check kill criteria between milestones"): the agent stops the line, preserves the failing evidence, and does not start M02 or silently downgrade scope.

## Critique Follow-up

`/goat-plan` does not run `/goat-critique` automatically. If the user explicitly asks to critique a plan, run `/goat-critique` against the written milestone files as separate report-only work. Do not save critique alternatives inside milestone files unless the user asks to apply a specific change.
