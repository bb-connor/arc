# MERCURY Trust Network

**Date:** 2026-04-03  
**Audience:** product, engineering, sponsor, and reviewer teams

---

## Purpose

This document freezes the bounded trust-network lane selected for `v2.49`.

The lane is intentionally narrow:

- one trust-network package family over the existing embedded-OEM,
  assurance-suite, governance-workbench, supervised-live, proof, and inquiry
  truth artifacts
- one sponsor boundary only: `counterparty_review_exchange`
- one trust anchor only: `chio_checkpoint_witness_chain`
- one interoperability surface only: `proof_inquiry_bundle_exchange`
- one reviewer population only: `counterparty_review`
- one fail-closed sponsor-owner and Mercury support-owner boundary

It does not approve a generic ecosystem trust broker, multiple sponsor
boundaries, multi-network witness services, Chio-Wall work, or multi-product
platform hardening.

---

## Selected Trust-Network Surface

The selected trust-network path is:

- sponsor boundary: `counterparty_review_exchange`
- trust anchor: `chio_checkpoint_witness_chain`
- interoperability surface: `proof_inquiry_bundle_exchange`
- reviewer population: `counterparty_review`

Those names are deliberate. Mercury is not shipping a broad trust service here.
It is shipping one bounded reviewer-sharing path that keeps the same workflow
sentence, the same evidence model, and the same Chio publication chain intact.

The workflow sentence remains unchanged:

> Controlled release, rollback, and inquiry evidence for AI-assisted execution
> workflow changes.

Trust-network packaging may add witness and trust-anchor continuity around the
same proof path, but it must not create a second truth path.

---

## Operational Owners

- sponsor owner: `counterparty-review-network-sponsor`
- support owner: `mercury-trust-network-ops`

The sponsor owner owns the bounded cross-reviewer exchange lane and witness
continuity obligations. The Mercury support owner owns fail-closed recovery
whenever the required profile, interop manifest, trust-anchor record, witness
record, proof package, inquiry package, reviewer package, or qualification
artifacts are missing or inconsistent.

---

## Scope Boundary

Supported in `v2.49`:

- one trust-network profile contract
- one trust-network package contract
- one interoperability manifest over one proof-and-inquiry bundle exchange
  surface
- one shared counterparty-review package family derived from the validated
  embedded-OEM lane
- one trust-anchor record and one witness record over the same checkpoint
  continuity

Not supported in `v2.49`:

- additional sponsor boundaries
- multi-network witness or trust-broker services
- generic ecosystem interoperability infrastructure
- Chio-Wall and companion-product work
- multi-product platform hardening

---

## Canonical Commands

Export the bounded trust-network package and shared reviewer exchange bundle:

```bash
cargo run -p chio-mercury -- trust-network export --output target/mercury-trust-network-export
```

Generate the validation package and explicit next-step decision:

```bash
cargo run -p chio-mercury -- trust-network validate --output target/mercury-trust-network-validation
```

These commands must remain wrappers over the existing embedded-OEM,
assurance-suite, governance-workbench, supervised-live, proof, and inquiry
artifacts. Chio stays generic; Mercury stays opinionated.
