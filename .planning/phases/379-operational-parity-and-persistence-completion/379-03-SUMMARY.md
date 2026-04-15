---
phase: 379-operational-parity-and-persistence-completion
plan: 03
subsystem: kubernetes
tags: [kubernetes, capability-validation, trust-anchors, admission]
requirements:
  completed: [OPER-03]
completed: 2026-04-14
verification:
  - go test ./...
---

# Phase 379 Plan 03 Summary

The Kubernetes admission controller now validates capability tokens against
configured ARC trusted issuer keys instead of trusting the issuer embedded in
the presented token.

## Accomplishments

- Added explicit trusted-issuer configuration via `ARC_TRUSTED_ISSUER_KEY` and
  `ARC_TRUSTED_ISSUER_KEYS`.
- Made admission validation fail closed when trusted issuer configuration is
  missing or malformed.
- Kept canonicalized Ed25519 signature checks, token time-bound checks, and
  required scope coverage on the same validation path after trust resolution.
- Added focused tests covering allow, invalid-signature, expired-token,
  out-of-scope, untrusted-issuer, and missing-trust-config cases.
- Updated the platform docs to describe the controller trust-anchor
  requirement truthfully.

## Verification

- `go test ./...` in `sdks/k8s/controller`

## Phase Status

Plan `379-03` completes `OPER-03`. Phase `379` is now complete.
