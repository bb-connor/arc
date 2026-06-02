# chio-ts Architecture Note

## Current Boundaries

- `src/index.ts` is the public SDK facade. It re-exports client, session, transport, DPoP, receipt query, errors, and invariant helpers.
- `src/invariants/` owns low-level cross-language compatibility checks for canonical JSON, hashing, signing, capabilities, receipts, and manifests.
- `src/invariants/manifest.ts` owns signed manifest parsing, canonical signing-body generation, Ed25519 signature verification, and the TypeScript `structure_valid` result.
- `test/manifest.test.ts` is the local manifest compatibility harness.

## Pain Points

- Rust `chio-manifest::validate_manifest` rejects empty or whitespace-padded tool names, duplicate tool names, non-object `input_schema`, and non-object `output_schema`.
- The TypeScript SDK currently mirrors schema, public-key, non-empty tool list, and duplicate-name checks, but not the stricter per-tool name and schema-shape checks.
- That divergence lets browser or Node callers report `structure_valid: true` for malformed signed manifests that Rust admission and FFI paths reject.

## Security And API Constraints

- Preserve the public `verifySignedManifest` and `verifySignedManifestJson` return shape.
- Preserve signature verification behavior. Structural failure must not hide the independent `signature_valid` result.
- Keep canonical JSON byte generation untouched.
- Treat malformed tool metadata as fail-closed `structure_valid: false`.

## Affected Dependents

- `@chio-protocol/sdk/invariants` consumers depend on `ManifestVerification.structure_valid` matching Rust manifest admission.
- `docs/reference/SDK_TYPESCRIPT_REFERENCE.md` documents the invariants export surface but does not need a signature or API-shape change.
- No Rust crate should change for this SDK parity fix.

## Planned Material Improvement

Mirror Rust manifest structure checks in `src/invariants/manifest.ts`: reject empty or whitespace-padded tool names, reject non-object `input_schema`, and reject non-object `output_schema` when present. Prove with red TypeScript manifest tests before changing the validator.
