# Summary 98-02

Added verifier-side continuity binding and replay-safe session mapping over
the canonical wallet exchange state.

Implemented:

- trust-control request creation support for verifier-supplied continuity input
  that is normalized into a verifier-bound `ArcIdentityAssertion`
- wallet exchange and OID4VP verification responses that echo the canonical
  continuity object without inventing a second session authority
- hosted authorization validation that accepts optional identity assertions
  only when they are fresh, bound to the right verifier, and consistent with
  the request context

Stale, mismatched, or contradictory continuity objects now fail closed on both
the verifier and hosted authorization paths.
