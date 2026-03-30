# Phase 44 Context

## Goal

Convert the release-candidate posture into a real launch decision backed by
final qualification and partner evidence.

## Current Code Reality

- ARC already ships a broad qualification lane, release docs, and milestone
  audits, but the current launch posture is still conditional.
- The repo has standards-facing docs, operator guides, and production
  qualification artifacts, yet they have not been closed into one explicit
  launch/no-go package.
- `v2.8` phase 43 should leave a clear formal/spec closure state that this
  phase can consume.
- The final ship bar needs more than tests passing: it needs a decision record,
  partner-facing proof artifacts, and alignment across release, standards, and
  launch narrative.

## Decisions For This Phase

- The GA gate is evidence-based and explicit: either launch or no-go, not a
  vaguely optimistic candidate.
- Final qualification must rerun through the canonical scripts rather than rely
  on stale milestone memory.
- Partner-proof artifacts should be derived from the same evidence set used for
  the launch decision.
- The launch narrative must reflect the actual ARC surface, not historical
  Pact-era branding or earlier roadmap assumptions.

## Risks

- Launch materials can drift away from the verified product surface.
- Qualification can go stale if this phase relies on earlier runs instead of a
  fresh release pass.
- Partner-facing artifacts can overclaim portability, trust, or assurance if
  they are not tied to the real evidence set.

## Phase 44 Execution Shape

- 44-01: define the GA checklist and decision contract
- 44-02: produce final qualification, partner-proof, and standards-facing artifacts
- 44-03: audit launch readiness and close the milestone with evidence
