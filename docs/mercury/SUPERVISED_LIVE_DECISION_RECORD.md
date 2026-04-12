# MERCURY Supervised-Live Decision Record

**Date:** 2026-04-02  
**Audience:** design-partner sponsors, product, engineering, compliance, and commercial owners

---

## 1. Purpose

This is the canonical artifact for closing MERCURY's post-pilot supervised-live
bridge. The bridge ends only when this record is completed with one outcome:

- `proceed`
- `defer`
- `stop`

No other close-out format should replace it.

---

## 2. When To Use It

Complete this record after the supervised-live qualification work finishes and
before any broader connector, governance, downstream-consumer, OEM, or
multi-workflow program is opened.

If the answer is not `proceed`, the bridge still closes here. The result is an
explicit defer or stop, not a vague expansion backlog.

---

## 3. Required Inputs

The completed record must reference:

- the supervised-live qualification corpus and reviewer package
- the current proof and inquiry verification results
- the operating-model assumptions and named owners
- any open retention, disclosure, trust, or monitoring risks
- the specific commercial or operational reason for proceeding, deferring, or
  stopping

---

## 4. Completed Decision Record

**Account / workflow:** Gold release-control workflow / same-workflow
supervised-live bridge  
**Date:** 2026-04-02  
**Prepared by:** ARC/MERCURY local bridge qualification  
**Decision:** proceed

### Workflow Boundary

- same workflow sentence:
  Controlled release, rollback, and inquiry evidence for AI-assisted
  execution workflow changes.
- existing customer execution systems remain primary: yes
- any requested scope expansion outside that boundary: none

### Qualification Inputs

- supervised-live qualification package:
  `target/mercury-supervised-live-qualification/reviewer-package.json`
- proof verification result:
  `pass` via `target/mercury-supervised-live-qualification/supervised-live/proof-verification.json`
- inquiry verification result:
  `pass` via `target/mercury-supervised-live-qualification/supervised-live/inquiry-verification.json`
- rollback exercise result:
  `pass` via `target/mercury-supervised-live-qualification/pilot/rollback/proof-verification.json`

### Operating Envelope

- workflow owner: design-partner workflow owner for the existing release or
  rollback program
- MERCURY operator: designated MERCURY deployment owner
- compliance or risk reviewer: designated design-partner reviewer
- infrastructure or security support: designated key, storage, and monitoring
  owner
- unresolved owner gaps: account-specific names are assigned at activation, but
  no required role gap remains in the operating model

### Risks and Constraints

- retention or disclosure risks: account-specific retention classes and
  disclosure approvals must remain aligned with the operating model and runbook
- monitoring or publication risks: supervised-live proof claims pause if
  monitoring, signing, or publication health degrades
- trust-boundary risks: MERCURY proves captured evidence and publication
  continuity, not external execution quality or ambient system truth
- reasons a broader expansion is not being approved here: this bridge close-out
  approves only the same workflow; governance workbench, downstream-consumer,
  connector, and OEM tracks require a new milestone decision

### Outcome

- decision rationale: the same workflow now has typed live capture, explicit
  fail-closed control state, a reproducible reviewer package, and a bounded
  rollback proof anchor
- if proceed: open one same-workflow supervised-live design-partner deployment
  review using the qualification package and documented operating envelope
- if defer: not selected
- if stop: not selected

---

## 5. Current Status

Completed locally with the bounded `proceed` outcome above. This record closes
the bridge without approving broader governance, downstream-consumer, or OEM
work.
