# MERCURY Regulatory Positioning

**Date:** 2026-04-02  
**Audience:** Compliance, legal, risk, and product teams

---

## 1. Positioning Principles

MERCURY should be described as:

- decision-provenance infrastructure
- supervisory-evidence infrastructure
- an aid for investigation, review, controlled change, and control testing

MERCURY should not be described as:

- a complete regulatory compliance solution
- proof of best execution
- a replacement for reporting, surveillance, or books-and-records programs
- a client-facing disclosure or attestation system without audience-specific
  review controls
- a substitute for model governance or human oversight

The defensible claim is:

> MERCURY improves the quality, integrity, and portability of evidence around
> governed AI trading workflows.

That language is accurate across the major regulatory regimes relevant to the
product.

---

## 2. Regulatory Context

Supervisory materials are increasingly focused on AI usage, but the relevant
themes remain technology-neutral:

- governance
- monitoring
- accurate records
- control operation
- human oversight
- investigation readiness

MERCURY fits that environment because it strengthens evidence and control
documentation. It does not replace the underlying obligations.

Firms also have to separate several related but distinct classes of material:

- convenience copies used for engineering or analyst access
- supervisory evidence used in review, investigation, and control testing
- regulated records subject to retention, production, and immutability rules
- external communications or disclosures sent to clients, counterparties, or
  regulators

MERCURY can support those distinctions, but it does not decide them on behalf
of the firm.

The initial workflow focus also matters. MERCURY is best aligned to:

- change review and release approval
- rollback and exception handling
- incident reconstruction
- inquiry and reviewed export packaging

Those are narrower and easier to defend than broad claims about autonomous
trading control.

---

## 3. Regime-Specific Emphasis

### Broker-dealer

Primary relevance:

- supervision
- books and records
- communications and disclosures
- market-access control evidence where MERCURY is part of a supervised process

### Investment adviser or asset manager

Primary relevance:

- governance and fiduciary review support
- internal control documentation
- client and allocator inquiry handling
- books-and-records treatment where firms classify the artifacts that way

### Bank-affiliate trading or platform team

Primary relevance:

- model-governance and operational-risk evidence
- change-management controls
- internal review and investigation workflows
- records and audit support under bank-specific policy environments

MERCURY can support all three regimes, but the exact obligations, retention
rules, and communications approvals differ by customer type. Commercial and
regulatory materials should not collapse these regimes into one generic story.

---

## 4. What MERCURY Can Support

### SEC Rule 613 / CAT

MERCURY can support internal reconstruction of how a reportable event arose and
how a workflow decision relates to later order events. It does not replace CAT
submissions or guarantee report completeness.

### SEC Rule 15c3-5 / Market Access

MERCURY can record which supervisory checks or approvals ran and preserve the
policy context surrounding those checks. It does not itself constitute the
market access control.

### MiFID II execution governance

MERCURY can improve the evidence trail behind routing or execution-related
workflow decisions, including policy versioning, retained artifacts, and review
records. It does not prove best execution or replace execution monitoring.

### FINRA supervision

MERCURY can strengthen records used in supervisory review, exception handling,
and control testing. It does not replace written supervisory procedures,
surveillance, or escalation workflows.

### Books-and-records and electronic recordkeeping

MERCURY can help preserve tamper-evident evidence, record lineage, and export
chains for workflows that may later become subject to retention or production
requirements. It can support immutable or audit-trailed storage profiles,
legal-hold workflows, and reproducible export packaging. It does not decide
which artifacts are regulated records, set retention periods, or replace the
firm's books-and-records system of record.

Where firms use inquiry packages or reviewed exports, they should also preserve:

- the exact rendered package delivered or reviewed
- recipient or audience scope
- approval and disclosure state
- production log or furnishing history when relevant

### Communications and external disclosure

MERCURY can produce portable proof packages for clients, internal reviewers,
auditors, or regulators. Those packages still require audience controls,
redaction policy, substantiation review, and in many cases communications
approval before external use. MERCURY should not be marketed as an
automatically compliant client-disclosure channel.

### SR 11-7 and model governance

MERCURY can bind model identifiers, workflow versions, approvals, and decision
artifacts into a durable record. It does not create a model inventory, execute
validation programs, or set governance thresholds.

### EU AI Act

MERCURY can support traceability, monitoring, and documentation where firms are
using AI in trading-related workflows. It should not be marketed as a direct AI
Act compliance answer or as a product whose demand depends on trading being
cleanly classified as high-risk under Annex III.

### Information barriers

MERCURY can record evidence of tool-boundary controls and denials where those
controls exist. ARC-Wall extends this further as a companion product. Neither
product replaces barrier operations, restricted-list management, or broader
MNPI compliance programs.

---

## 5. What MERCURY Does Not Replace

MERCURY does not replace:

- CAT, transaction reporting, or books-and-records infrastructure
- surveillance platforms and investigation case management
- best-execution analysis and TCA
- model risk governance
- operational resiliency programs
- information-barrier policies and procedures
- record-retention classification decisions
- communications review and approval processes
- supervisory ownership of live control paths

These boundaries should appear in external materials, SOWs, and buyer
conversations.

---

## 6. Proof Boundary

### MERCURY can prove

- a specific signing key produced a specific record
- the record contained specific metadata, policy references, and artifact
  references
- the record was included in a published checkpoint
- retained artifacts match the referenced hashes or identifiers
- recorded checks, denials, approvals, or recommendations are represented
  faithfully in the signed output
- a reviewed inquiry package corresponds to a specific disclosed view approved
  for a specific audience

### MERCURY cannot prove by itself

- that a feed or broker was independently authoritative
- that a policy was economically sound
- that the firm's control environment was otherwise sufficient
- that a supervisory conclusion such as best execution was satisfied
- that an exported package is appropriate or compliant for a particular
  audience without separate review controls
- that no off-system activity occurred

---

## 7. Messaging Guide

### Preferred language

- "attested decision provenance"
- "supervisory evidence for governed AI trading workflows"
- "portable, verifiable workflow records"
- "review and investigation support"

### Language to avoid

- "AI Act compliance for trading"
- "best-execution proof"
- "evidence-grade AI governance"
- "client-facing verification"
- "turnkey regulatory shield"
- "replacement for surveillance or reporting"

---

## 8. Record and Obligation Taxonomy

### 1. Convenience copies

Material used for debugging, analytics, or user convenience. These copies may
be disposable and do not automatically inherit record status from the primary
evidence object.

### 2. Supervisory evidence

Receipts, bundle manifests, checkpoints, review exports, and investigation
artifacts used to reconstruct and defend a workflow decision. These are often
high-value internal records even when they are not the firm's formal
books-and-records archive.

### 3. Regulated records

Artifacts a firm determines must be retained under applicable books-and-records
rules, internal policy, or legal instruction. MERCURY can support these
objects, but the firm must still define retention and system-of-record
obligations.

### 4. External disclosures

Packages or summaries delivered outside the firm, including client responses,
counterparty explanations, and regulator-facing exports. These require
audience-specific review controls beyond cryptographic integrity.

For each class, the firm should explicitly define:

- retention period
- WORM or audit-trail requirement
- legal-hold behavior
- export format and production process
- redaction and audience-control rules
- required review and approval step
- preservation of the exact rendered package and delivery or approval log

---

## 9. Compliance FAQ

### Does MERCURY satisfy the EU AI Act by itself?

No. MERCURY can support documentation and traceability, but AI Act obligations
depend on the use case and still require governance, oversight, monitoring, and
organizational controls outside the product.

### Does MERCURY prove best execution?

No. MERCURY preserves decision provenance and supporting evidence. Best
execution remains an economic and supervisory conclusion requiring broader
analysis.

### Does MERCURY replace CAT or transaction reporting?

No. It may improve internal traceability and case reconstruction around those
systems, but it does not replace them.

### Can MERCURY artifacts become regulated records?

Yes. Depending on the workflow, firm policy, and jurisdiction, receipts,
artifacts, review exports, prompts, or approvals may become records that
require defined retention, production, and legal-hold treatment. MERCURY can
support that classification, but it does not make the classification decision
for the firm.

### Does a client-facing proof package need additional controls?

Yes. Any client-facing or external package should be treated as a reviewed
communication or disclosure surface, not just as a cryptographic export.
The exact delivered or reviewed package and its approval history should also be
retained when the firm treats that package as a record or communication.
Audience scoping, redaction, substantiation review, and approval workflows are
still required.

### Are hashes alone enough for regulators or clients?

No. Hashes are useful only if the underlying records, retention controls,
chain-of-custody procedures, and publication discipline are also in place.

### Does putting MERCURY in path create additional obligations?

Potentially, yes. A mediated deployment increases resiliency, change-control,
and vendor-risk expectations. The firm should assume it must define supervisory
ownership, direct-control boundaries, control testing, annual review,
change-management procedures, outage behavior, and books-and-records or
communications treatment for any outputs produced by that live path.
