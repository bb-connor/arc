# Phase 67: Public Verifier Trust and Discovery Model - Context

## Goal

Define how public ARC verifier deployments authenticate themselves and publish
their trust bootstrap material without overclaiming generic federation.

## Why This Phase Exists

Wallet interop is incomplete if holders cannot evaluate verifier identity.
ARC needs one concrete verifier-authentication profile that fits its
operator-scoped web deployment model and rotation rules.

## Scope

- verifier identity profile selection
- metadata, certificates, or related trust bootstrap artifacts
- verifier-key rotation and trust bootstrap rules
- explicit acceptance and rejection boundaries for verifier identity schemes

## Out of Scope

- OpenID Federation
- public mutable verifier trust registries
- implicit runtime trust from directory presence alone
