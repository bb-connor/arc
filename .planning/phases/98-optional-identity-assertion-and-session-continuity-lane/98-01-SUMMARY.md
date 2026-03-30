# Summary 98-01

Defined one canonical optional identity-assertion contract shared across the
wallet exchange, OID4VP verifier, and hosted authorization surfaces.

Implemented:

- `ArcIdentityAssertion` in `arc-core` with canonical subject, continuity,
  verifier, freshness, optional provider or session hint, and optional
  request-binding fields
- OID4VP request and verification embedding so the continuity object is bound
  to the signed verifier request instead of becoming a parallel mutable
  session record
- authorization-context schema support so ARC's standards-facing transaction
  context can carry the same optional identity assertion shape

The continuity lane stays optional by construction. ARC does not require an
external identity provider to use wallet presentation or hosted authorization.
