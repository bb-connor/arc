# chio-manifest Architecture Notes

## Boundary

`chio-manifest` owns the native Chio tool discovery artifact:
`chio.manifest.v1`. It defines the manifest schema structs, validates
manifest-level invariants, signs manifests over canonical JSON, and verifies
signed manifests against Chio public keys. It should not own adapter-specific
tool synthesis, kernel admission state, capability issuance, guard execution,
or billing enforcement.

## Current Pain Point

The manifest has both discovery metadata and trust metadata. `validate_manifest`
is the structural discovery gate used by adapters and examples before a manifest
is signed. It should reject impossible tool contracts, but it should not require
signed-material parsing. Public-key parsing belongs on the signing and
verification paths, where the crate can compare the embedded manifest key with
the actual signer and fail closed before admitting a signed manifest.

## Security And API Constraints

- `chio.manifest.v1` must stay frozen and backward-compatible for valid
  manifests.
- Unknown schema values, duplicate tool names, malformed server-tool
  allowlists, and non-object per-tool schemas must fail closed in structural
  validation.
- Missing, malformed, or mismatched signer material must fail closed in
  `sign_manifest` and `verify_manifest`, not in unsigned structural validation.
- Validation must use Chio's algorithm-aware `PublicKey` decoder so Ed25519 and
  supported FIPS encodings stay compatible when signed material is evaluated.
- Adapter fixture updates should not be required solely to satisfy unsigned
  structural validation. Fixtures that exercise signed-manifest admission should
  still use deterministic valid keys.

## Affected Dependents

Potential dependents are adapter tests and examples that synthesize manifests
before calling `validate_manifest`. Structural validation should keep rejecting
malformed tool schemas for those dependents, while unsigned/demo manifests with
placeholder public keys should remain usable until a caller explicitly signs or
verifies the manifest.

## Planned Improvement

Keep per-tool JSON schema object checks in `validate_manifest`, but move
embedded public-key parsing out of that structural gate and onto the signing and
verification boundary.
