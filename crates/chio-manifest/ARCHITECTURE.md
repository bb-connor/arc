# chio-manifest Architecture Notes

## Boundary

`chio-manifest` owns the native Chio tool discovery artifact:
`chio.manifest.v1`. It defines the manifest schema structs, validates
manifest-level invariants, signs manifests over canonical JSON, and verifies
signed manifests against Chio public keys. It should not own adapter-specific
tool synthesis, kernel admission state, capability issuance, guard execution,
or billing enforcement.

## Current Pain Point

The manifest has both discovery metadata and trust metadata. Existing branch
work ties `sign_manifest` and `verify_manifest` to the embedded `public_key`,
but plain `validate_manifest` still accepts an unparsable `public_key`. That
leaves adapters that call validation before exposing generated manifests with a
weaker pre-signature boundary than the signed-manifest path.

## Security And API Constraints

- `chio.manifest.v1` must stay frozen and backward-compatible for valid
  manifests.
- Unknown schema values, malformed signer material, duplicate tool names, and
  malformed server-tool allowlists must fail closed.
- Validation must use Chio's algorithm-aware `PublicKey` decoder so Ed25519 and
  supported FIPS encodings stay compatible.
- Adapter fixture updates, if needed, should only replace fake keys with
  deterministic valid keys. They must not change adapter behavior.

## Affected Dependents

Potential dependents are adapter tests and examples that synthesize manifests
with placeholder public-key strings before calling `validate_manifest`. If this
slice exposes those fixtures, the required transitive change is to use real
deterministic public keys while preserving the tested adapter behavior.

## Planned Improvement

Move embedded public-key parsing into `validate_manifest`, so manifest
validation rejects impossible trust metadata before admission, signing, or
adapter exposure.
