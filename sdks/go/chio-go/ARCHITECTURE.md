# chio-go Architecture Note

## Boundaries

- `client/`, `session/`, `transport/`, `auth/`, and `nested/` own the hosted
  SDK runtime surface.
- `invariants/` owns pure-Go compatibility checks for canonical JSON, signing,
  hashing, capabilities, and receipts.
- Signed tool manifests are admitted by the generated `chio.manifest.v1` types
  in `sdks/go/chio-go-http`, not by this module.

## Security And API Constraints

- Canonical JSON byte generation and signature verification are independent
  checks.
- The parity check requires neither CGO nor native bindings.
