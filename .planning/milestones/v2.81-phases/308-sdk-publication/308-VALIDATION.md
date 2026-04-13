---
phase: 308-sdk-publication
created: 2026-04-13
---

# Phase 308 Validation

## Required Evidence

- `npm install @arc-protocol/sdk` succeeds from a packed release artifact and
  exposes the stable typed client surface.
- `pip install arc-sdk` succeeds from wheel and sdist artifacts and exposes
  stable typed Python classes, including receipt queries.
- Both SDK packages contain a governed example that initializes against a
  running ARC hosted edge, discovers the session capability, invokes a tool,
  and reads the resulting receipt from the trust service.
- Both SDK README files document installation, quickstart usage, and where to
  find the API reference.

## Verification Commands

- `npm --prefix packages/sdk/arc-ts test`
- `./scripts/check-arc-ts-release.sh`
- `./scripts/check-arc-py.sh`
- `./scripts/check-arc-py-release.sh`
- `./scripts/check-sdk-publication-examples.sh`

## Regression Focus

- Python distribution identity, version alignment, and wheel/sdist filenames
- receipt-query error handling and pagination in the new Python client
- TypeScript default client metadata and published-surface smoke checks
- package-local SDK examples staying aligned with the real trust-control and
  hosted-edge runtime behavior
