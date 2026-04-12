# MERCURY Supervised-Live Operations Runbook

**Date:** 2026-04-02  
**Audience:** engineering, operations, security, compliance, and design-partner reviewers

---

## 1. Purpose

This is the canonical runbook for MERCURY's first supervised-live bridge. It
defines the minimum key-management, monitoring, degraded-mode, and recovery
posture for the same controlled release, rollback, and inquiry workflow while
customer execution systems remain primary.

It does not define a generic production connector program or mediated in-line
control plane.

---

## 2. Key and Trust Material Posture

- keep receipt-signing and publication keys under named operator and
  infrastructure or security ownership
- separate day-to-day workflow ownership from signing-key custody; MERCURY does
  not gain broader execution authority from holding evidence keys
- record the active key reference, rotation date, and expected publication
  continuity for every supervised-live review window
- if key custody, rotation, revocation, or backup posture becomes uncertain,
  pause new supervised-live proof claims until the trust posture is reviewed

Minimum expectations before a covered window starts:

1. the active signing path is known and reachable
2. backup or recovery instructions are available to the named support owner
3. publication references can still be updated for the review window
4. key incidents have an escalation path that reaches both MERCURY operators
   and workflow owners

---

## 3. Monitoring Minimums

The bridge is only truthful when the following evidence-service signals remain
healthy:

- intake continuity for the same supervised-live workflow
- artifact retention success for referenced evidence
- receipt-signing success
- checkpoint or publication freshness
- canary verification of exported proof packages
- alert delivery to named MERCURY and infrastructure owners

Recommended operator-visible checks:

| Signal | Healthy state | Fail-closed trigger |
|--------|---------------|---------------------|
| Intake | expected events arrive for the covered workflow | feed interruption, unexplained lag, or dropped source identifiers |
| Retention | referenced artifacts persist and hashes resolve | storage error, missing artifact, or retention-policy drift |
| Signing | receipts and checkpoints continue to sign | signing backend unreachable, revoked, or ambiguous |
| Publication | continuity and freshness stay within the agreed window | checkpoint or publication lag exceeds the review tolerance |
| Monitoring | alerts and canary verification still run | monitoring blind spot or unresolved alert transport failure |

---

## 4. Approval and Interrupt Gates

Supervised-live evidence is export-ready only when all of the following remain
explicit:

- release gate approved for the covered workflow window
- rollback gate approved so the same workflow still has an explicit bounded
  interrupt path
- coverage state marked `covered`
- intake, retention, signing, publication, and monitoring all healthy

If any of those conditions stop being true, MERCURY must fail closed. That
means the workflow may continue through the customer's primary systems, but
MERCURY must not emit new supervised-live proof claims for the affected
interval.

Every interruption requires:

- an incident identifier
- a short operator-visible summary
- a narrower coverage claim, never a broader one

---

## 5. Degraded-Mode Response

| Condition | Required action |
|-----------|-----------------|
| Intake gap or mirrored-feed loss | mark coverage interrupted, open an incident, and stop new supervised-live export for the affected interval |
| Retention failure | pause export, preserve the causal record of what is missing, and review retention integrity before resuming |
| Signing or publication issue | treat proof continuity as untrusted until the trust path is restored and reviewed |
| Monitoring blind spot | move to degraded mode immediately; do not claim covered supervision without alerting and canary verification |
| Reviewer or owner unavailable | do not widen authority or close the bridge decision while required owners are absent |

The fail-closed rule applies even when the customer's primary workflow keeps
running successfully.

---

## 6. Recovery and Return to Covered State

Recovery is complete only when:

1. the triggering incident is resolved or bounded
2. the affected evidence interval is labeled honestly as covered, interrupted,
   or partial
3. receipt signing, publication, and monitoring are healthy again
4. the release and rollback gates are still explicitly approved
5. the named reviewer path accepts the post-incident trust posture

Do not relabel degraded intervals as fully covered after the fact. Recovery
restores future covered operation; it does not erase the causal record of the
incident.

---

## 7. Required Artifacts

The supervised-live bridge should retain or reference:

- the capture contract for the covered interval
- the approval-gate identifiers and approver subjects
- interruption records for any degraded or interrupted period
- proof or inquiry exports only for intervals that still satisfy the covered
  posture
- the final proceed, defer, or stop decision record from the bridge-close phase

This runbook works with [SUPERVISED_LIVE_BRIDGE.md](SUPERVISED_LIVE_BRIDGE.md),
[SUPERVISED_LIVE_OPERATING_MODEL.md](SUPERVISED_LIVE_OPERATING_MODEL.md), and
the typed supervised-live capture contract in `arc-mercury-core`.
