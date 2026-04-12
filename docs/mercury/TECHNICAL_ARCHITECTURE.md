# MERCURY Technical Architecture

**Date:** 2026-04-03  
**Audience:** Engineers, architects, and security reviewers

---

## 1. Design Goals

MERCURY is designed to produce high-integrity workflow evidence for governed AI
trading workflows and their control events without forcing the first product
release to be a full in-line trading control plane.

Primary goals:

- create a canonical signed evidence record
- retain and reference the source artifacts behind that record
- define a portable proof package and publication profile
- define a reviewed inquiry package derived from that proof package
- publish proof material for later independent verification
- support investigation and review workflows using business identifiers
- provide a clean path to deeper live integrations when justified

Non-goals for the first product release:

- broad OMS/EMS parity
- proprietary FIX engine implementation
- browser-first UX
- proof of economic execution quality

---

## 2. Deployment Modes

MERCURY supports three modes.

| Mode | Purpose | Typical use |
|------|---------|-------------|
| Replay / shadow | Generate evidence from recorded or mirrored workflow events | pilot, review, paper trading |
| Supervised live workflow | Generate evidence for a real workflow while existing execution systems remain primary | post-pilot production over the same workflow contract |
| Mediated in-line control | Put ARC in the authorization path for selected live actions | advanced expansion |

The initial product is built to make the first mode excellent and the second
practical for the same controlled workflow. The third is an expansion path, not
a prerequisite.

---

## 3. Logical Architecture

```text
Workflow events / approvals / source artifacts
                |
                v
      MERCURY ingestion or adapter layer
                |
                v
      ARC-backed receipt and checkpoint engine
                |
        +-------+-------+
        |               |
        v               v
 Evidence bundle store  Proof publication
        |               |
        +-------+-------+
                v
    Query API / verifier CLI / downstream consumers
```

Core components:

- **Ingestion layer:** converts workflow events, approvals, or mirrored order
  actions into canonical MERCURY evidence input
- **Receipt engine:** signs the evidence record and commits it into checkpoints
- **Evidence bundle store:** retains source artifacts referenced by the record
- **Proof publication layer:** emits the canonical publication objects used for
  later verification
- **Retrieval layer:** supports lookup by business identifiers and delivery of
  export packages or API responses derived from the same proof contract
- **Inquiry packaging layer:** derives reviewed exports from the proof package
  without mutating the underlying signed evidence
- **Downstream review distribution:** stages one bounded case-management review
  package on top of the same proof, inquiry, reviewer, and qualification
  artifacts
- **Governance-workbench packaging:** derives one bounded governance decision
  package, control-state file, and audience-specific review packages over the
  same supervised-live qualification and proof artifacts
- **Assurance-suite packaging:** derives reviewer-population disclosure
  profiles, review packages, investigation packages, and one top-level
  assurance-suite contract over the same governance and supervised-live truth
  artifacts

### Supervised-live capture contract

For the first supervised-live bridge, MERCURY should accept one typed capture
contract over the same workflow. That contract can operate in `mirrored` or
`live` mode, but it must still reuse the existing receipt metadata,
bundle-manifest, proof-package, and inquiry-package contracts.

Each supervised-live step should preserve:

- the same workflow and business identifiers already used in pilot receipts
- `source_record_id` continuity back to the originating customer system
- `idempotency_key` continuity so repeated delivery does not silently corrupt
  the evidence chain
- bundle manifests that remain aligned to the same workflow ID as the receipts

The supervised-live capture should also declare typed control state:

- explicit release and rollback gate posture
- evidence health across intake, retention, signing, publication, and
  monitoring
- whether the interval is `covered`, `interrupted`, `degraded`, or under
  `recovery_review`
- interruption records with incident identifiers whenever coverage is not fully
  covered

Healthy captures may export proof and inquiry artifacts. Degraded or
interrupted captures remain representable, but the export path should fail
closed instead of silently producing supervised-live proof claims.

---

## 4. Canonical Evidence Model

### Receipt body

Each MERCURY receipt should be able to capture:

- decision type: `propose`, `approve`, `deny`, `rollback`, `release`,
  `simulate`, `observe`, `route`
- workflow, desk, account, and strategy identifiers
- model identifier and workflow version
- policy identifier or policy hash
- model provider, hosting mode, and dependency provenance
- approval or supervisory metadata
- artifact references
- source-system identifiers used for reconciliation
- chronology and causality metadata

Recommended chronology fields:

- canonical event ID
- idempotency key
- source timestamp
- ingest timestamp
- causal parent event IDs
- stage marker such as `proposal`, `approval`, `rollback`, `release`,
  `override`, `route`, `ack`, or `fill`

### Evidence bundle

Evidence bundles contain or reference the raw artifacts needed to reconstruct a
workflow event, such as:

- prompts or structured workflow inputs
- release diffs or configuration manifests
- approval records
- OMS acknowledgements or mirrored execution events
- market-context artifacts
- policy snapshots
- exception tickets or review comments
- rendered inquiry packages and disclosure approvals when those become records

The integrity contract is:

1. the receipt references the bundle or artifacts
2. the bundle or artifacts have stable identifiers or hashes
3. the verifier can confirm the retained material matches the receipt

Every artifact reference should also carry a policy layer:

- sensitivity class
- disclosure policy
- storage or encryption policy
- retention class
- legal-hold state
- redaction policy
- whether a redacted export remains verifier-equivalent or only
  reviewer-readable

### Reconciliation metadata

Each workflow record should also retain the IDs needed to line up evidence with
other systems, for example:

- internal workflow run ID
- OMS order ID
- broker or venue event ID
- approval ticket ID
- model release or evaluation ID

This is essential for operational usefulness.

Reconciliation should not be identifier-only. The system should preserve a
causal event graph so reviewers can understand how recommendation, approval,
override, and downstream events relate in time.

---

## 5. End-to-End Flow

### Step 1: capture event input

MERCURY receives a workflow event, mirrored action, or replayed input and
normalizes it into the canonical evidence schema.

### Step 2: retain or reference source artifacts

Before signing, MERCURY stores or references the relevant artifacts needed for
later review.

### Step 3: sign receipt

The ARC-backed signing path produces the canonical receipt and assigns stable
identifiers.

### Step 4: checkpoint commitment

Receipts are committed into signed checkpoints on a configured cadence or batch
policy.

### Step 5: publish proof material

Checkpoint metadata is published according to a canonical publication profile.
That profile should include:

- checkpoint payload
- checkpoint sequence continuity semantics
- publication timestamp
- witness or immutable anchor record
- trust-anchor references
- key-rotation or revocation references

### Step 6: retrieval and verification

Reviewers retrieve a `Proof Package v1` through the API or export path and
verify that package with the supported verifier.

### Step 7: inquiry packaging

When a customer needs a reviewed disclosure or inquiry response, MERCURY derives
an `Inquiry Package v1` from the proof package, disclosure policy, and approval
state without altering the underlying signed evidence.

---

## 6. Trust Boundary

### Trusted elements

- receipt-signing key material or signing backend
- receipt construction logic
- publication logic
- retained evidence bundles and their identifiers

### Untrusted or partially trusted elements

- workflow inputs supplied by external systems
- mirrored OMS or broker responses
- market-data artifacts unless independently attested by a third party
- any system outside the receipt and publication boundary

### Implication

MERCURY proves integrity inside its boundary. It does not transform an
untrusted external fact into a trusted one simply by hashing it.

The strongest user-facing statement is therefore:

> MERCURY can prove what it captured, how it published it, and how retained
> artifacts relate to that capture.

For supervised-live mode, that statement is only valid while the control-state
contract says coverage is healthy and approved. See
[SUPERVISED_LIVE_OPERATIONS_RUNBOOK.md](SUPERVISED_LIVE_OPERATIONS_RUNBOOK.md)
for the operator posture that guards that claim.

---

## 7. Verification and Publication

The initial product ships one supported verifier surface: a Rust library and
the dedicated `arc-mercury` CLI app.

### Proof Package v1

The stable artifact for pilot and early production use should be
`Proof Package v1`.

It should include:

- canonical receipt
- evidence bundle manifest
- checkpoint
- inclusion proof
- publication record
- witness or immutable anchor record
- trust-anchor material
- key rotation or revocation material
- schema and profile versions
- optional completeness and freshness declarations

Verification checks:

1. receipt signature validity
2. canonical serialization and content integrity
3. checkpoint inclusion
4. publication-chain integrity
5. evidence-bundle integrity
6. append-only continuity or consistency proof where required by policy

### Publication Profile v1

The publication profile should define:

- the publication object format
- checkpoint sequence continuity rules
- witness record format
- trust-anchor bootstrap rules
- rotation and revocation semantics
- outage and replay behavior
- minimum verifier requirements
- completeness declaration rules
- freshness windows for inquiry or review use
- inclusion and consistency proof requirements for append-only continuity
- long-term archive renewal rules for proof material

This combination makes the evidence portable beyond MERCURY-operated
infrastructure.

### Export and redaction policy

Proof packages may be exported in multiple views:

- full internal review package
- redacted reviewer package
- client or auditor package

Inquiry packages sit above those views and add reviewed disclosure semantics.

The export policy must state:

- which fields are omitted or masked
- whether the exported view remains verifier-equivalent
- which audience may receive the package
- who approved the disclosure
- the exact rendered export digest
- the approval or delivery log bound to that export

---

## 8. Storage and Retention

### Active store

The initial product can use the existing ARC SQLite-backed receipt store for
pilot-scale and early production deployments.

### Artifact storage

Evidence bundles may live in:

- local filesystem
- object storage
- dedicated archival storage

What matters is stable addressing, retention controls, and integrity checks.

What also matters is record policy. For many buyers, some MERCURY artifacts may
become regulated records or supervisory evidence subject to:

- WORM or audit-trail preservation
- legal hold
- prompt production in reasonably usable format
- deletion restrictions
- chain-of-custody requirements

### Retention model

The system should separate:

- active searchable records
- long-term archive
- publication material that must remain independently verifiable

Retention policy is a workflow and regulatory design input, not a universal
default.

The architecture should therefore separate:

- convenience copies
- retained evidence artifacts
- records subject to books-and-records or communications controls
- reviewed inquiry packages and their approval history

---

## 9. Operational Model

The initial product requires:

- explicit key onboarding
- documented checkpoint publication
- health and degraded-mode behavior
- backup and recovery procedures
- monitoring for publication gaps and storage failures
- legal-hold and redaction procedures for export packages
- record, disclosure, and production drills for inquiry packages

For replay or shadow deployments, degraded mode means evidence capture pauses
while the trading workflow can continue through its primary systems.

For a mediated live deployment, degraded mode is a separate design decision and
must be owned explicitly before go-live. That path also requires explicit
supervisory ownership, testing, annual review, outage handling, and control
change management.

---

## 10. ARC Mapping

MERCURY reuses ARC for:

- signing primitives
- receipt structures
- checkpoint commitment
- verification foundations

MERCURY adds:

- trading-specific receipt metadata
- business-identifier queries
- evidence-bundle schema
- reconciliation metadata
- chronology and causality graph fields
- provider and dependency provenance
- proof package and publication profile
- inquiry package semantics
- publication and trust-distribution discipline

This separation keeps the product modular and avoids re-implementing ARC core
behavior unnecessarily.

---

## 11. Expansion Patterns

### Production OMS / EMS or FIX integration

Add one funded production path at a time. Do not assume broad adapter coverage
as a prerequisite for product value.

### Governance and downstream distribution

Governed workflows and archive, review, or surveillance connectors should be
built on top of the same proof package and inquiry package contracts.

The first validated downstream consumer lane remains one case-management review
intake staged through a fail-closed file-drop contract. The current active
expansion path is narrower than a full governance platform: one
`change_review_release_control` governance-workbench workflow that derives a
decision package, control-state file, and workflow-owner/control-team review
packages from the same proof, inquiry, reviewer, and qualification artifacts
rather than introducing a parallel evidence model.

### Assurance, embedded distribution, and trust network

Reviewer-facing assurance surfaces and embedded OEM packaging should come after
the core proof and inquiry contracts are stable.

The assurance-suite lane is now validated, and the trust-network lane is now
also validated. That path exposed one `counterparty_review_exchange`
interoperability manifest and one `arc_checkpoint_witness_chain` trust anchor
derived from the same embedded OEM, assurance, governance, reviewer, and
qualification artifacts rather than a separate trust-service truth path.

### Companion products

ARC-Wall and other extensions can reuse the same signing, publication, and
verification foundations while introducing different evidence types and guard
logic.

The current companion-product lane is one ARC-Wall `control_room_barrier_review`
path over one `tool_access_domain_boundary` surface. It records one bounded
denied cross-domain tool-access event for `research -> execution` using ARC
tool-guard mechanics, ARC receipts, ARC checkpoints, and ARC evidence export
instead of inventing a second substrate or folding ARC-Wall into MERCURY.

### Multi-product hardening

Now that MERCURY and ARC-Wall both have one validated lane, the current active
step is one executed cross-product hardening lane exposed through `arc
product-surface export` and `arc product-surface validate`.

That lane now freezes and executes:

- which services stay ARC-owned and generic
- which shared ARC crate versions stay pinned together across both product lanes
- which surfaces stay product-owned and separate
- which release, trust-material recovery, and operator-routing controls are
  shared across the portfolio

---

## Summary

MERCURY's architecture is deliberately evidence-first: capture the workflow
record correctly, retain what matters, publish proof material credibly, derive
reviewed inquiry packages safely, and expand into deeper integrations only when
the commercial case is specific.
