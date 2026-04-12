# MERCURY Reference Distribution Operations

**Date:** 2026-04-03  
**Milestone:** `v2.55`

---

## Purpose

The reference-distribution lane packages one bounded Mercury landed-account
expansion motion while preserving the same controlled-adoption truth chain.
This runbook defines the minimum artifact set, claim-discipline rules, buyer-
approval boundary, and fail-closed sales-handoff posture for that lane.

---

## Required Bundle Components

Every `reference-distribution export` bundle must include:

- one reference-distribution profile
- one reference-distribution package
- one account-motion freeze artifact
- one reference-distribution manifest
- one claim-discipline rules file
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

- reference owner: `mercury-reference-program`
- buyer approval owner: `mercury-buyer-reference-approval`
- sales owner: `mercury-landed-account-sales`

The reference owner controls the approved claim. Buyer approval owns the hard
go/no-go gate for external reference use. Sales only receives the bundle after
approval is present and the scope remains bounded to one landed-account motion.

---

## Fail-Closed Rules

The reference-distribution path must fail closed when:

- the profile and package disagree on expansion motion or distribution surface
- the approved claim expands beyond the bounded evidence-backed sentence
- buyer-reference approval is missing before handoff
- the manifest omits controlled-adoption, renewal, proof, inquiry, or reviewer
  files
- the landed-account motion widens beyond one approved reference bundle

Recovery posture:

1. stop the handoff immediately
2. regenerate the reference-distribution export from the canonical
   controlled-adoption lane
3. require a fresh buyer-reference approval before reuse

---

## Deferred Operations

This runbook does not authorize:

- multiple landed-account motions
- a generic sales platform or CRM workflow
- a merged Mercury and ARC-Wall shell
- ARC-side commercial control surfaces
- broad rollout or universal performance claims

Those remain separate decisions, not hidden responsibilities inside `v2.55`.
