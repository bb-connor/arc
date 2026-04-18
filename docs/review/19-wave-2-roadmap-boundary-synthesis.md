## Wave 2 Roadmap Boundary Synthesis

Date: 2026-04-16

This memo captures the second six-agent review and debate round performed after
`docs/review/18-post-32-boundary-synthesis.md`.

It is a synthesis record, not a ship-boundary authority document.

## Inputs

- `docs/POST_ROADMAP_ADDENDUM.md`
- `docs/review/18-post-32-boundary-synthesis.md`
- `docs/review/15-vision-gap-map.md`
- `docs/review/17-post-closure-execution-board.md`
- `docs/review/01-formal-verification-remediation.md`
- `docs/review/11-reputation-federation-remediation.md`
- `docs/review/12-standards-positioning-remediation.md`
- `docs/protocols/STRATEGIC-VISION.md`
- `docs/protocols/FUTURE-MOATS-AND-RESEARCH.md`
- `docs/release/QUALIFICATION.md`
- `docs/release/RELEASE_AUDIT.md`
- `.planning/PROJECT.md`
- `.planning/STATE.md`

## Wave 2 Question

Given the Wave 1 conclusion that the roadmap should not grow into a fake
product ladder after technical closure, what is the cleanest final structure
for:

1. the last numbered repo-solvable phase
2. the external-evidence programs that follow
3. the standing proof and claim-discipline controls that continue after the
   numbered roadmap stops

## Wave 2 Consensus

Wave 2 preserved the main Wave 1 conclusion:

1. there should be no ordinary `Phase 33`
2. the strongest ARC thesis cannot be closed by repo work alone
3. ZK receipt proofs and TEE-backed execution stay explicit research tracks
4. proof-discipline continues after the numbered roadmap as a standing gate,
   not as another product phase

Wave 2 then refined the structure:

- the post-roadmap remainder should not be one blended bucket
- standards and trust-portability qualification are a distinct evidence class
  from market validation and external proof
- those two evidence classes should be represented as separate external
  programs

## Debate Outcome

### 31 vs 32

Wave 2 voted `4-2` to end the numbered roadmap at `Phase 31`.

Majority position:

- Phase 31 is the last repo-solvable closure phase
- the current Phase 32 material is already external evidence work, not product
  implementation work
- keeping that material inside the numbered ladder weakens the boundary between
  implementation truth and market-proof truth

Minority position:

- keep Phase 32 as one final numbered handoff marker
- use it only as the boundary phase where repo truth stops and external
  evidence begins

### One Program vs Two Programs

Wave 2 was unanimous that the post-roadmap remainder should split into two
external programs:

1. `Standards And Trust-Portability Qualification`
2. `Market Validation And External Proof`

The debate was also unanimous that research should remain separate from both:

- ZK receipt proofs
- TEE-backed execution and receipt binding

## Resulting Structure

The cleanest combined structure after Wave 2 is:

1. `docs/POST_ROADMAP_ADDENDUM.md` ends with the last repo-solvable closure
   phase.
2. A separate companion document tracks the external programs needed to prove
   the strongest strategic thesis.
3. Research remains in explicit research tracks, not roadmap phases.
4. Release qualification and claim-discipline remain standing controls, not
   horizon-phase backlog.

## Concrete Guidance For The Addendum

Wave 2 supported the following changes:

- stop the numbered ladder at the last repo-solvable closure point
- remove or demote roadmap-shaped treatment of external operator dependence,
  partner dependence, and market proof
- add a hard stop-line that says the addendum only governs repo-solvable work
- point outward to companion external-program docs rather than trying to make
  the addendum do double duty as a market-proof plan
- keep research and standing proof-governance visibly separate

## Governance Warning

The strongest warning from Wave 2 was structural:

If external proof stays inside the addendum in roadmap-shaped form, the project
creates a shadow roadmap that can silently widen claims beyond the release and
qualification boundary.

The fix is to separate:

- repo-solvable closure
- external evidence programs
- research tracks
- standing release and claim-discipline controls

## Bottom Line

Wave 2 keeps the Wave 1 honesty rule and makes it sharper.

The numbered roadmap should end where repo-solvable closure ends.
The remaining vision work should be tracked as external programs and research,
not as more internal product phases.
