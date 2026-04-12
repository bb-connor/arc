# MERCURY Delivery Continuity Operations

**Date:** 2026-04-04  
**Milestone:** `v2.58`

---

## Purpose

The delivery-continuity lane packages one bounded Mercury continuity motion
while preserving the same selective-account-activation truth chain. This
runbook defines the minimum artifact set, outcome-evidence rules, renewal-gate
boundary, escalation posture, and fail-closed customer-evidence handoff for
that lane.

---

## Required Bundle Components

Every `delivery-continuity export` bundle must include:

- one delivery-continuity profile
- one delivery-continuity package
- one account-boundary freeze artifact
- one delivery-continuity manifest
- one outcome-evidence summary
- one renewal-gate artifact
- one delivery-escalation brief
- one customer-evidence handoff artifact
- one selective-account-activation package
- one activation-scope freeze artifact
- one selective-account-activation manifest
- one claim-containment rules file
- one activation-approval-refresh artifact
- one customer-handoff brief
- one broader-distribution package
- one broader-distribution manifest
- one target-account freeze artifact
- one claim-governance rules file
- one selective-account approval artifact
- one reference-distribution package
- one controlled-adoption package
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

- continuity owner: `mercury-delivery-continuity`
- renewal owner: `mercury-renewal-gate`
- evidence owner: `mercury-customer-evidence`

The continuity owner controls the bounded service motion and supported claim.
Renewal owns the hard go/no-go gate for evidence-backed reuse.
Customer evidence receives the bundle only after the renewal gate is current
and the scope remains bounded to one already activated account.

---

## Fail-Closed Rules

The delivery-continuity path must fail closed when:

- the profile and package disagree on continuity motion or surface
- supported claims expand beyond the bounded evidence-backed sentence
- the renewal gate is missing or stale before customer-evidence reuse
- the manifest omits selective-account-activation, proof, inquiry, or reviewer
  files
- the motion widens beyond one already activated account or one outcome-
  evidence bundle

Recovery posture:

1. stop reuse of the continuity bundle immediately
2. regenerate the delivery-continuity export from the canonical selective-
   account-activation lane
3. require a fresh renewal-gate review before reuse

---

## Deferred Operations

This runbook does not authorize:

- multiple continuity motions or surfaces
- a generic onboarding suite, CRM workflow, or support desk
- channel marketplaces or multi-account continuity programs
- a merged Mercury and ARC-Wall shell
- ARC-side commercial control surfaces
- broad customer-health or universal renewal-performance claims

Those remain separate decisions, not hidden responsibilities inside `v2.58`.
