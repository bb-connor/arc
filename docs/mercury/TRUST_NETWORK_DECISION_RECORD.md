# MERCURY Trust Network Decision Record

**Date:** 2026-04-03  
**Milestone:** `v2.49`

---

## Decision

`proceed_trust_network_only`

Proceed with one bounded trust-network path only.

---

## Approved Scope

- one `counterparty_review_exchange` sponsor boundary
- one `chio_checkpoint_witness_chain` trust anchor
- one `proof_inquiry_bundle_exchange` interoperability surface
- one `counterparty_review` package family derived from the validated
  embedded-OEM lane
- one fail-closed sponsor and Mercury support boundary

---

## Deferred Scope

- additional sponsor boundaries
- multi-network witness or trust-broker services
- generic ecosystem interoperability infrastructure
- Chio-Wall and companion-product work
- multi-product platform hardening

---

## Rationale

The trust-network lane now shares one bounded counterparty-review Mercury
bundle through one checkpoint-backed witness chain without widening Mercury
into a generic trust broker, ecosystem network, or multi-product platform.
The milestone therefore closes with one explicit trust-network path and one
narrow next-step boundary.
