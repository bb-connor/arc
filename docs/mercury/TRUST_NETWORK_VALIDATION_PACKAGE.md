# MERCURY Trust Network Validation Package

**Date:** 2026-04-03  
**Milestone:** `v2.49`

---

## Purpose

`trust-network validate` is the canonical close-out command for the bounded
trust-network lane. It generates the trust-network bundle, writes the
validation report, and emits one explicit expansion decision instead of
implying a generic trust broker, multi-network service, or Chio-Wall program.

---

## Command

```bash
cargo run -p chio-mercury -- trust-network validate --output target/mercury-trust-network-validation
```

---

## Output Layout

```text
target/mercury-trust-network-validation/
├── trust-network/
│   ├── embedded-oem/
│   ├── trust-network-profile.json
│   ├── trust-network-package.json
│   ├── trust-network-summary.json
│   ├── trust-network-interoperability-manifest.json
│   └── trust-network-share/
│       ├── shared-proof-package.json
│       ├── review-package.json
│       ├── inquiry-package.json
│       ├── inquiry-verification.json
│       ├── reviewer-package.json
│       ├── qualification-report.json
│       ├── witness-record.json
│       └── trust-anchor-record.json
├── validation-report.json
└── expansion-decision.json
```

---

## Supported Claim

This package supports one bounded claim only:

> Mercury can share one counterparty-review proof and inquiry bundle through
> one `counterparty_review_exchange` sponsor boundary using one
> `chio_checkpoint_witness_chain` trust anchor and one
> `proof_inquiry_bundle_exchange` interoperability manifest without widening
> into a generic trust broker.

---

## Non-Claims

This package does not claim:

- multiple sponsor boundaries
- multi-network witness or trust-broker services
- generic ecosystem interoperability infrastructure
- Chio-Wall readiness
- multi-product platform hardening
