---
phase: 308
status: passed
completed: 2026-04-13
---

# Phase 308 Verification

## Outcome

Phase `308` passed. `@arc-protocol/sdk` and `arc-sdk` are now locally
release-qualified as stable SDK packages, the Python lane has receipt-query
parity, and both packages ship official governed examples that execute against
the real ARC trust-service and hosted-edge flow.

## Automated Verification

- `npm --prefix packages/sdk/arc-ts test`
- `./scripts/check-arc-ts-release.sh`
- `./scripts/check-arc-py.sh`
- `./scripts/check-arc-py-release.sh`
- `./scripts/check-sdk-publication-examples.sh`
- `git diff --check -- packages/sdk/arc-py packages/sdk/arc-ts docs/SDK_PYTHON_REFERENCE.md scripts/check-arc-py.sh scripts/check-arc-py-release.sh scripts/check-arc-ts-release.sh scripts/check-sdk-publication-examples.sh .planning/phases/308-sdk-publication`

## Requirement Closure

- `SDK-01`: the TypeScript SDK remains installable as stable
  `@arc-protocol/sdk` with types and release-artifact smoke checks.
- `SDK-02`: the Python SDK is now installable as stable `arc-sdk` with typed
  root classes including `ReceiptQueryClient`.
- `SDK-03`: both SDKs now include governed examples that initialize a live ARC
  session, discover the issued capability, invoke a governed tool, and read the
  receipt back from the trust service.
- `SDK-04`: both SDK READMEs now document installation, quickstart usage, and
  API-reference entry points.

## Next Step

Proceed to phase `309` to turn the current local ARC runtime path into a
5-minute Docker-based deployable experience.
