# Summary 141-02

Defined the public identity-profile artifact for the broadened interop surface.

## Delivered

- added `PublicIdentityProfileArtifact`, `IdentityArtifactReference`,
  `IdentityBindingPolicy`, and `SignedPublicIdentityProfile` in
  `crates/arc-core/src/identity_network.rs`
- published `docs/standards/ARC_PUBLIC_IDENTITY_PROFILE.json`
- required explicit subject-method, issuer-method, credential-family,
  proof-family, and transport declarations

## Result

ARC can now publish one machine-readable public identity profile over the
existing passport and verifier substrate instead of relying on informal
interop claims.
