# MERCURY Supervised-Live Bridge

**Date:** 2026-04-02  
**Audience:** product, engineering, compliance, and design-partner stakeholders

---

## 1. Purpose

`v2.43` ends at pilot readiness. The next decision is not "what connector do we
add?" It is whether the same controlled release, rollback, and inquiry
workflow should move from replay or shadow into supervised-live operation.

---

## 2. Scope Lock

The first workflow sentence remains:

> Controlled release, rollback, and inquiry evidence for AI-assisted execution
> workflow changes.

The first supported post-pilot bridge is:

> supervised-live productionization of the same governed workflow while the
> customer's existing execution systems remain primary

That means MERCURY stays the evidence and proof layer around the workflow. It
does not quietly become the buyer's primary OMS, EMS, FIX engine, or generic
governance platform just because the workflow is now operating in production.

---

## 3. Entry Criteria

Only open the supervised-live bridge if all of the following are true:

- the design partner accepts the proof boundary as review-grade evidence rather
  than execution-performance proof
- the pilot corpus can be reproduced with the shipped repo command
- the primary proof package and inquiry package verify cleanly
- the rollback variant is exercised and understood
- source-artifact retention, disclosure, and reviewer obligations are agreed

---

## 4. Controlled Operating Envelope

The supervised-live bridge is only valid inside the following operating model:

- existing customer execution systems remain primary for workflow execution,
  routing, and broker or venue interaction
- MERCURY captures and proves the same workflow events, approvals, retained
  artifacts, and reconciliation identifiers around those primary systems
- workflow ownership, operator ownership, reviewer ownership, and
  infrastructure or security ownership are named before the bridge opens
- periods where MERCURY capture, retention, signing, or publication are known
  to be impaired cannot be described as complete proof coverage

See [SUPERVISED_LIVE_OPERATING_MODEL.md](SUPERVISED_LIVE_OPERATING_MODEL.md)
for the canonical role model, escalation assumptions, and degraded-mode
posture. See
[SUPERVISED_LIVE_OPERATIONS_RUNBOOK.md](SUPERVISED_LIVE_OPERATIONS_RUNBOOK.md)
for the key-management, monitoring, fail-closed, and recovery rules that make
the bridge executable.

---

## 5. Approval and Interrupt Rules

The supervised-live bridge is only truthful when MERCURY can show explicit
control state around the same workflow:

- the release gate is approved for the covered interval
- the rollback gate is approved so the workflow still has a bounded interrupt
  path
- coverage is marked `covered` only while intake, retention, signing,
  publication, and monitoring remain healthy
- interruptions or degraded intervals carry an incident record and pause new
  supervised-live proof claims

MERCURY may record degraded or interrupted state, but it must fail closed on
new supervised-live export until the runbook says the workflow is covered
again.

---

## 6. Allowed Additions and Explicit Non-Goals

That bridge may add:

- live or mirrored event intake for the same workflow
- operator runbooks for key management and degraded mode
- explicit approval and interruption rules around release and rollback actions

That bridge must not automatically add:

- broad OMS or EMS connector programs
- generic surveillance or archive integrations
- browser-portal expansion
- multiple workflow families
- mediated in-line control
- proof-of-best-execution or regulatory-completeness claims

Anything in that list needs its own later funded phase after the bridge closes.

---

## 7. Outage and Degraded-Mode Posture

The bridge keeps the same workflow bounded even when things go wrong:

- if live or mirrored intake is interrupted, MERCURY coverage is interrupted
  and the incident must be recorded; the workflow may continue through the
  customer's primary systems, but proof continuity cannot be implied
- if artifact retention, signing, checkpoint publication, or key material is
  impaired, new supervised-live claims pause until the issue is resolved and
  reviewed
- outages do not authorize MERCURY to widen its role into direct execution or
  broader integrations
- degraded mode is a bounded evidence-service posture, not silent failover into
  a deeper control plane

---

## 8. Conversion Gate and Decision Artifact

The bridge does not close with a vague "more integration" discussion. It
closes with one explicit decision artifact:

- [SUPERVISED_LIVE_QUALIFICATION_PACKAGE.md](SUPERVISED_LIVE_QUALIFICATION_PACKAGE.md)
- [SUPERVISED_LIVE_DECISION_RECORD.md](SUPERVISED_LIVE_DECISION_RECORD.md)

That record is the only supported place to conclude the bridge. It must bind:

- the supervised-live qualification evidence
- the operating-model assumptions and named owners
- open risks, gaps, and disclosure obligations
- the single next funded step, if any

Allowed outcomes remain:

1. Proceed to supervised-live for the same workflow.
2. Stay in replay or shadow mode and gather more evidence.
3. Stop and do not widen scope.

---

## 9. Decision Outcomes

Anything outside the three outcomes above is a disguised scope increase.
