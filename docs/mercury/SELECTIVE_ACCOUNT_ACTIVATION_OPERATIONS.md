# MERCURY Selective Account Activation Operations

**Date:** 2026-04-04  
**Milestone:** `v2.57`

---

## Purpose

The selective-account-activation lane packages one bounded Mercury activation
motion while preserving the same broader-distribution truth chain. This
runbook defines the minimum artifact set, claim-containment rules, approval-
refresh boundary, and fail-closed customer-handoff posture for that lane.

---

## Required Bundle Components

Every `selective-account-activation export` bundle must include:

- one selective-account-activation profile
- one selective-account-activation package
- one activation-scope freeze artifact
- one selective-account-activation manifest
- one claim-containment rules file
- one activation-approval-refresh artifact
- one customer-handoff brief
- one broader-distribution package
- one target-account freeze artifact
- one broader-distribution manifest
- one claim-governance rules file
- one selective-account approval artifact
- one distribution-handoff brief
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

- activation owner: `mercury-selective-account-activation`
- approval owner: `mercury-activation-approval`
- delivery owner: `mercury-controlled-delivery`

The activation owner controls the bounded motion and supported claim.
Approval owns the hard go/no-go refresh gate for controlled delivery.
Delivery receives the bundle only after refresh is present and the scope
remains bounded to one selective-account activation motion.

---

## Fail-Closed Rules

The selective-account-activation path must fail closed when:

- the profile and package disagree on activation motion or delivery surface
- the approved claim expands beyond the bounded evidence-backed sentence
- approval refresh is missing before controlled delivery
- the manifest omits broader-distribution, proof, inquiry, or reviewer files
- the motion widens beyond one account or one controlled delivery bundle

Recovery posture:

1. stop the handoff immediately
2. regenerate the selective-account-activation export from the canonical
   broader-distribution lane
3. require a fresh approval refresh before reuse

---

## Deferred Operations

This runbook does not authorize:

- multiple activation motions or delivery surfaces
- a generic onboarding suite, CRM workflow, or channel marketplace
- partner marketplaces or multi-segment activation programs
- a merged Mercury and Chio-Wall shell
- Chio-side commercial control surfaces
- broad rollout or universal performance claims

Those remain separate decisions, not hidden responsibilities inside `v2.57`.
