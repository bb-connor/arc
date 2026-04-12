# MERCURY Supervised-Live Operating Model

**Date:** 2026-04-02  
**Audience:** engineering, operations, compliance, and design-partner owners

---

## 1. Objective

Define the minimum operating envelope for MERCURY's first supervised-live
bridge. This document is intentionally narrow: it covers the same controlled
release, rollback, and inquiry workflow while existing customer execution
systems remain primary.

It does not define a generic production connector program or mediated in-line
control model.

---

## 2. Operating Assumptions

- MERCURY remains the evidence layer around the workflow, not the primary
  execution system
- the workflow owner keeps operational ownership of the live release or
  rollback path inside existing customer systems
- MERCURY operators own evidence capture, retention, signing, publication, and
  export correctness for the periods they claim
- supervised-live coverage is truthful only when intake, retention, signing,
  and publication remain healthy enough to support the proof contract

---

## 3. Required Human Roles

| Role | Required ownership |
|------|--------------------|
| Workflow owner | Owns the governed release, rollback, and inquiry workflow inside the customer's primary systems and decides whether the workflow should enter supervised-live review at all |
| MERCURY operator | Owns intake health, evidence capture, package generation, publication continuity, and incident logging for the supervised-live bridge |
| Compliance or risk reviewer | Owns acceptance of the proof boundary, disclosure posture, and whether supervised-live evidence is acceptable for review and inquiry use |
| Infrastructure or security support | Owns signing-key controls, storage posture, monitoring, and incident-response support for outages that affect trust or retention |

No single role should silently substitute for another. If one role is missing,
the bridge is degraded and the decision record must say so.

---

## 4. Pre-Bridge Checklist

Before supervised-live starts, confirm all of the following:

1. the pilot corpus is reproducible with the repo-native commands
2. proof and inquiry packages verify cleanly for the current workflow contract
3. rollback handling is exercised for the same workflow
4. source-artifact retention and disclosure obligations are accepted
5. named owners and escalation contacts exist for all required roles
6. the account agrees that MERCURY evidence is review-grade and not a claim of
   execution quality

---

## 5. Normal Operating Cycle

### Start of day or session

- confirm intake health for the supervised-live workflow
- confirm storage, signing, and publication prerequisites are available
- confirm the named workflow owner and reviewer path are reachable

### During the workflow

- capture live or mirrored events only for the frozen workflow family
- preserve source identifiers and retained-artifact continuity
- record operator-visible incidents that affect coverage or proof confidence

### End of day or review window

- confirm checkpoint or publication continuity for the covered interval
- record any evidence gaps or partial-coverage periods
- prepare proof or inquiry exports only from the covered interval and approved
  disclosure posture

---

## 6. Degraded-Mode and Outage Rules

| Condition | Required posture |
|-----------|------------------|
| Intake gap or mirrored-feed interruption | Mark supervised-live evidence coverage interrupted, open an incident, and do not imply completeness for the affected interval |
| Artifact retention or storage failure | Pause new supervised-live package claims until retention integrity is restored and reviewed |
| Signing or publication issue | Hold external proof continuity claims and bridge-closure decisions until trust and publication posture are reviewed |
| Reviewer or owner unavailable | Do not widen scope or close the bridge decision without the missing owner; continue only within already-approved workflow boundaries |

The customer's primary systems may continue running the workflow. MERCURY does
not gain broader authority just because its own evidence services are impaired.

See
[SUPERVISED_LIVE_OPERATIONS_RUNBOOK.md](SUPERVISED_LIVE_OPERATIONS_RUNBOOK.md)
for the canonical key-management, monitoring, fail-closed, and recovery
procedure.

---

## 7. Escalation Principles

- escalate toward narrower claims, not broader claims
- preserve the causal record of any incident that affects coverage
- prefer temporary defer over speculative proceed
- treat unresolved owner or trust-boundary ambiguity as a bridge blocker

---

## 8. Relationship to Later Phases

This document freezes the operating model. Later phases can implement,
exercise, and qualify it, but they should not redefine it into a broader
product without an explicit new milestone.
