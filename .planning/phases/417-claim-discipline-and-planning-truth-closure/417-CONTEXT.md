# Phase 417 Context: Claim Discipline and Planning Truth Closure

## Why This Phase Exists

The repo is now close to one honest bounded ARC release, but the release
boundary is still blurred by stale stronger-language remnants and planning
drift. README, qualification docs, review docs, and planning state do not yet
all speak with one bounded-ship voice.

Phase `417` exists to make the bounded ARC release claim explicit and
internally consistent before any deeper runtime closure is blessed.

## Required Outcomes

1. Align README, qualification docs, release docs, and review docs to one
   bounded ARC claim and explicit non-claims.
2. Reconcile `.planning/PROJECT.md`, `.planning/MILESTONES.md`,
   `.planning/ROADMAP.md`, `.planning/REQUIREMENTS.md`, and
   `.planning/STATE.md` so they agree on latest completed milestone, active
   milestone, and next action.
3. Remove stale `v3.17` text that still implies the market-proof lane is the
   active or unstarted ship lane.

## Existing Assets

- `docs/review/13-ship-blocker-ladder.md`
- `docs/review/01-formal-verification-remediation.md`
- `docs/review/12-standards-positioning-remediation.md`
- `README.md`
- `docs/release/QUALIFICATION.md`
- `.planning/*`

## Gaps To Close

- formal-proof and stronger-boundary language still drifts above the honest
  bounded ship claim
- planning files disagree on active/completed milestone truth
- no authoritative bounded ARC release wording exists yet

## Requirements Mapped

- `TRUTH5-01`
- `TRUTH5-02`

## Exit Criteria

This phase is complete only when a reviewer can read the ship-facing docs and
the live planning stack and arrive at the same bounded ARC claim boundary.
