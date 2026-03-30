# Summary 57-01

Defined the typed SPIFFE/SVID-style workload-identity mapping contract for ARC
runtime attestation.

## Delivered

- `WorkloadIdentity`, `WorkloadIdentityScheme`, and
  `WorkloadCredentialKind` types in `arc-core`
- fail-closed parsing and validation for SPIFFE URIs, empty identities, and
  explicit/raw identity conflicts
- normalized workload-identity projection rules that keep non-SPIFFE
  `runtimeIdentity` values opaque for compatibility

## Notes

- ARC currently standardizes only SPIFFE-derived workload identity
- explicit typed workload identity may narrow ARC trust, but it does not widen
  trust for opaque legacy identifiers
