# MERCURY Use Cases

**Date:** 2026-04-02  
**Audience:** Product, sales, engineering, and buyer stakeholders

---

## 1. AI Change Review and Release Attestation

### Situation

A team wants to release, rollback, or materially modify a model, prompt,
policy, routing rule, or parameter set used inside a governed trading
workflow.

### MERCURY role

MERCURY records the proposed change, prior and next versions, approval chain,
chronology, policy context, provider provenance, and retained evidence in one
portable proof chain.

### Buyer value

- clear reconstruction of who approved what and under which policy
- stronger release and rollback discipline
- cleaner evidence for supervisory sign-off and post-release review

---

## 2. AI Incident Reconstruction Pack

### Situation

A workflow behaves unexpectedly and the platform team needs to reconstruct what
happened quickly.

### MERCURY role

MERCURY enables lookup by workflow, account, order, strategy, or release ID and
ties the investigation to the signed record, retained evidence bundles, and the
chronology linking release, approval, and downstream events.

### Buyer value

- faster reconstruction
- clearer linkage across systems
- less dependence on fragmented logs and ad hoc ticket archaeology

---

## 3. Supervisory Control Evidence Pack

### Situation

A workflow requires human approval before an AI-assisted recommendation or
parameter change proceeds.

### MERCURY role

MERCURY records the recommendation, the approval or override event, chronology,
policy context, and retained approval artifact in one evidence chain that can
be exported for internal review.

### Buyer value

- clear reconstruction of who approved what and under which policy
- stronger exception review
- reviewer-ready export for archive, surveillance, and compliance teams

---

## 4. Shadow-Mode Workflow Review

### Situation

A trading team is using AI to generate execution recommendations or govern a
release process but does not want a new system in the live order path yet.

### MERCURY role

MERCURY captures replayed or mirrored workflow events, stores the related
artifacts, and creates a signed record for each governed change or supervisory
decision.

### Buyer value

- low-friction deployment
- stronger review material for platform, compliance, and control teams
- evidence before a supervised-live production decision

---

## 5. Client or Internal Inquiry Package

### Situation

A client, allocator, or internal reviewer wants to understand how an
AI-influenced workflow produced a disputed action.

### MERCURY role

MERCURY provides the proof package, reviewed export, evidence references, and
disclosure metadata needed to show what workflow version, policy, approvals,
and artifacts were involved.

When the audience is external, the package should be governed by redaction,
audience control, and communications-review rules set by the customer.

### Buyer value

- more credible workflow explanation
- less dependence on fragmented logs and manual reconstruction
- controlled disclosure instead of ad hoc document assembly

---

## 6. Promotion to Supervised-Live Production

### Situation

A pilot proves useful enough that a customer wants the same governed workflow
to operate in controlled production.

### MERCURY role

The evidence platform remains the foundation while the same workflow moves from
replay or shadow into supervised-live production with the same proof and export
model.

### Buyer value

- no need to re-argue the proof model
- tighter operational adoption in the first account
- cleaner foundation for later downstream integration

---

## 7. Promotion to Downstream Distribution

### Situation

A customer or partner wants MERCURY evidence to appear inside existing archive,
review, surveillance, or case-management systems.

### MERCURY role

The evidence platform remains the foundation while one funded downstream path
is added, such as:

- one governance workflow
- one archive, review, or surveillance connector
- one later assurance workflow
- one future embedded OEM path

### Buyer value

- scalable expansion from a proven evidence substrate
- no need to re-argue the proof model for each next step

---

## Summary

MERCURY is most valuable wherever a trading workflow needs stronger release,
rollback, approval, exception, or investigation evidence. The product does not
depend on full in-line autonomy to be useful.
