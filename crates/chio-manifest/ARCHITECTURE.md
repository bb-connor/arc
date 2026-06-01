# chio-manifest Architecture Notes

## Boundary

`chio-manifest` owns the native Chio tool discovery artifact:
`chio.manifest.v1`. It defines the manifest schema structs, validates
manifest-level invariants, signs manifests over canonical JSON, and verifies
signed manifests against Chio public keys. It should not own adapter-specific
tool synthesis, kernel admission state, capability issuance, guard execution,
or billing enforcement.

## Current Pain Point

The manifest has both discovery metadata and trust metadata. Validation already
checks the schema identifier, duplicate tools, duplicate server-tool entries,
and embedded public-key parsing before signing or verification. The remaining
gap is that `input_schema` and `output_schema` are still arbitrary JSON values
at the manifest boundary. Some adapter edges reject non-object schemas before
projection, but any caller that relies only on `validate_manifest` can still
expose a malformed tool contract as a signed manifest.

## Security And API Constraints

- `chio.manifest.v1` must stay frozen and backward-compatible for valid
  manifests.
- Unknown schema values, malformed signer material, duplicate tool names,
  malformed server-tool allowlists, and non-object per-tool schemas must fail
  closed.
- Validation must use Chio's algorithm-aware `PublicKey` decoder so Ed25519 and
  supported FIPS encodings stay compatible.
- Adapter fixture updates, if needed, should only replace fake keys with
  deterministic valid keys. They must not change adapter behavior.

## Affected Dependents

Potential dependents are adapter tests and examples that synthesize manifests
with non-object schema placeholders before calling `validate_manifest`. If this
slice exposes those fixtures, the required transitive change is to use object
schema placeholders while preserving the tested adapter behavior.

## Planned Improvement

Move per-tool JSON schema object checks into `validate_manifest`, so manifest
validation rejects impossible discovery metadata before signing, verification,
or adapter exposure.
