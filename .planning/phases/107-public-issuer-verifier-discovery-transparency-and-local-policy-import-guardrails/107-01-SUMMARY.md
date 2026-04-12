# Summary 107-01

Defined ARC's signed public issuer-discovery and verifier-discovery artifacts
in `crates/arc-credentials/src/discovery.rs` and exposed them through
`crates/arc-cli/src/trust_control.rs`.

Implemented:

- `arc.public-issuer-discovery.v1` as the signed, versioned projection over
  the existing OID4VCI issuer metadata surface
- `arc.public-verifier-discovery.v1` as the signed, versioned projection over
  the existing OID4VP verifier metadata, `JWKS`, and request-URI surface
- public read-only discovery endpoints for issuer and verifier metadata
- fail-closed rejection of partial, malformed, or missing discovery material

This publishes discovery without turning metadata visibility into trust
admission.
