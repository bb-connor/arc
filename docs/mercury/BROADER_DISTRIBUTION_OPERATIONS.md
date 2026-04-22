# MERCURY Broader Distribution Operations

**Date:** 2026-04-04  
**Milestone:** `v2.56`

---

## Purpose

The broader-distribution lane packages one bounded Mercury selective account-
qualification motion while preserving the same reference-distribution truth
chain. This runbook defines the minimum artifact set, claim-governance rules,
selective-account approval boundary, and fail-closed distribution-handoff
posture for that lane.

---

## Required Bundle Components

Every `broader-distribution export` bundle must include:

- one broader-distribution profile
- one broader-distribution package
- one target-account freeze artifact
- one broader-distribution manifest
- one claim-governance rules file
- one selective-account approval artifact
- one distribution-handoff brief
- one reference-distribution package
- one account-motion freeze artifact
- one reference-distribution manifest
- one reference claim-discipline rules file
- one buyer-reference approval artifact
- one sales-handoff brief
- one controlled-adoption package
- one renewal-evidence manifest
- one renewal acknowledgement
- one reference-readiness brief
- one release-readiness package
- one trust-network package
- one assurance-suite package
- one proof package
- one inquiry package
- one inquiry verification report
- one reviewer package
- one qualification report

The bundle is incomplete if any of those files are missing, inconsistent, or
cannot be matched back to the same workflow.

---

## Operating Boundary

- qualification owner: `mercury-account-qualification`
- approval owner: `mercury-broader-distribution-approval`
- distribution owner: `mercury-broader-distribution`

The qualification owner controls the bounded motion and supported claim.
Approval owns the hard go/no-go gate for governed broader distribution.
Distribution receives the bundle only after approval is present and the scope
remains bounded to one selective account-qualification motion.

---

## Fail-Closed Rules

The broader-distribution path must fail closed when:

- the profile and package disagree on distribution motion or surface
- the approved claim expands beyond the bounded evidence-backed sentence
- selective-account approval is missing before handoff
- the manifest omits reference-distribution, controlled-adoption, proof,
  inquiry, or reviewer files
- the motion widens beyond one selective account or one governed distribution
  bundle

Recovery posture:

1. stop the handoff immediately
2. regenerate the broader-distribution export from the canonical
   reference-distribution lane
3. require a fresh selective-account approval before reuse

---

## Deferred Operations

This runbook does not authorize:

- multiple broader-distribution motions or surfaces
- a generic sales platform, CRM workflow, or channel console
- partner marketplaces or multi-segment account programs
- a merged Mercury and Chio-Wall shell
- Chio-side commercial control surfaces
- broad rollout or universal performance claims

Those remain separate decisions, not hidden responsibilities inside `v2.56`.
