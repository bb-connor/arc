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
is signed. It rejects impossible tool contracts and malformed manifest identity
or sandbox-permission metadata, but it does not require signed-material parsing.
Public-key parsing belongs on the signing and verification paths, where the
crate compares the embedded manifest key with the actual signer and fails closed
before admitting a signed manifest.

The signed envelope is a separate trust boundary. The inner `ToolManifest`
already rejects unknown fields, but the envelope must do the same or admission
payloads can carry unsigned side metadata that serde silently discards before
verification. Even if current callers ignore that side metadata, the signed
artifact should have a single canonical shape at parse time.

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
placeholder public keys remain usable until a caller explicitly signs or
verifies the manifest. Signed-manifest JSON with extra envelope fields now
rejects at deserialization.

## Implemented Improvement

Structural validation lives in its own module and tightens the unsigned manifest
gate for identity and required-permission text fields. Embedded public-key
parsing stays on the signing and verification boundary. The signed envelope now
uses `deny_unknown_fields`, matching the inner manifest schema's fail-closed
parsing behavior.
