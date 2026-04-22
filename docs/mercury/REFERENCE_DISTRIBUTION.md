# MERCURY Reference Distribution

**Date:** 2026-04-03  
**Milestone:** `v2.55`  
**Audience:** product, partnerships, sales, and operators

---

## Purpose

This document freezes the bounded Mercury reference-distribution lane selected
for `v2.55`.

The lane is intentionally narrow:

- one expansion motion only: `landed_account_expansion`
- one distribution surface only: `approved_reference_bundle`
- one Mercury-owned reference program only
- one Mercury-owned buyer-reference approval path only
- one Mercury-owned sales handoff only

The lane reuses already validated Mercury artifacts:

- one controlled-adoption package
- one renewal-evidence manifest and acknowledgement
- one reference-readiness brief
- one release-readiness package
- one trust-network package
- one assurance-suite package
- one proof package
- one inquiry package plus verification report
- one reviewer package plus qualification report

It does not authorize a generic sales platform, CRM workflow, merged shell,
Chio commercial console, or broader Mercury product-family claim.

---

## Frozen Expansion Motion

The expansion motion is fixed for this lane:

- `landed_account_expansion`

That motion label is part of the contract. If Mercury needs multiple landed-
account motions later, that is a new milestone, not an implicit widening of
`v2.55`.

---

## Selected Distribution Surface

The selected distribution surface is:

- `approved_reference_bundle`

That surface packages the existing Mercury truth chain for one bounded
reference-backed landed-account motion. The workflow sentence remains
unchanged:

> Controlled release, rollback, and inquiry evidence for AI-assisted execution
> workflow changes.

---

## Owners

- reference owner: `mercury-reference-program`
- buyer approval owner: `mercury-buyer-reference-approval`
- sales owner: `mercury-landed-account-sales`

Distribution ownership stays inside Mercury. Chio remains the generic substrate
that Mercury consumes; Chio does not become a commercial expansion console.

---

## Supported Scope

Supported in `v2.55`:

- one reference-distribution profile contract
- one reference-distribution package contract
- one account-motion freeze artifact
- one reference-distribution manifest
- one claim-discipline rules file
- one buyer-reference approval artifact
- one sales-handoff brief over the same controlled-adoption, release-
  readiness, trust-network, assurance, proof, and inquiry chain

Not supported in `v2.55`:

- multiple landed-account motions or distribution surfaces
- a generic sales platform, CRM, or commercial console
- a merged Mercury and Chio-Wall shell
- Chio-side commercial control surfaces
- broader Mercury product-family or universal rollout claims

---

## Canonical Commands

Export the bounded reference-distribution package and landed-account bundle:

```bash
cargo run -p chio-mercury -- reference-distribution export --output target/mercury-reference-distribution-export
```

Generate the validation package and explicit proceed decision:

```bash
cargo run -p chio-mercury -- reference-distribution validate --output target/mercury-reference-distribution-validation
```

These commands remain Mercury-owned wrappers over existing Mercury artifacts.
Chio stays generic; Mercury stays opinionated.
