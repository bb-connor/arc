# chio-ts Architecture Note

## Boundaries

- `src/index.ts` is the public SDK facade. It re-exports client, session, transport, DPoP, receipt query, errors, and invariant helpers.
- `src/invariants/` owns low-level cross-language compatibility checks for canonical JSON, hashing, signing, capabilities, and receipts.
- Signed tool manifests are admitted by the generated `chio.manifest.v1` types in `sdks/typescript/packages/conformance`, not by this package.

## Security And API Constraints

- Canonical JSON bytes and signature verification are independent checks.
- `docs/reference/SDK_TYPESCRIPT_REFERENCE.md` documents the invariants export surface.
