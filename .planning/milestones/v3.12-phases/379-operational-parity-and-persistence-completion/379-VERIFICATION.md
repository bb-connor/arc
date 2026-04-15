---
phase: 379-operational-parity-and-persistence-completion
status: passed
completed: 2026-04-14
---

# Phase 379 Verification

Phase `379` passes targeted operational verification.

## Commands

- `cargo test -p arc-api-protect`
- `cargo test -p arc-tower`
- `go test ./...` in `sdks/k8s/controller`

## Outcome

- `arc-api-protect` persists receipts durably when `receipt_db` is configured
  and exposes the same persisted history across proxy and `/arc/evaluate`
  flows.
- `arc-tower` binds raw request bodies into evaluation on its supported
  replayable body path and preserves the same bytes for downstream handlers.
- The Kubernetes controller rejects missing, untrusted-issuer,
  invalid-signature, expired, out-of-scope, and missing-trust-config
  capability tokens instead of treating annotation presence or self-declared
  issuers as sufficient.
