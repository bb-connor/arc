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
is signed. It should reject impossible tool contracts and malformed manifest
identity or sandbox-permission metadata, but it should not require
signed-material parsing. Public-key parsing belongs on the signing and
verification paths, where the crate can compare the embedded manifest key with
the actual signer and fail closed before admitting a signed manifest.

`lib.rs` also carries schema types, server-tool mapping, structural validation,
and signing in one file. That makes it too easy for caller-facing schema changes
and trust-boundary validation changes to drift together without a clear review
line.

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
- Server identity, display name, version, and required permission entries are
  adapter and kernel admission metadata. Empty, padded, or duplicate text values
  should fail closed during structural validation.
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

Move structural validation into its own module and tighten the unsigned
manifest gate for identity and required-permission text fields. Keep embedded
public-key parsing on the signing and verification boundary.
