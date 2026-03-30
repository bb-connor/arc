# Summary 99-01

Added bounded DPoP sender-constrained continuity across ARC's hosted
authorization and protected-resource runtime.

Implemented:

- request-time sender input through `arc_sender_dpop_public_key`
- persisted sender binding on the authorization code grant instead of a
  best-effort token-side guess
- token `cnf.arcSenderKey` projection so the issued token carries the same
  sender constraint forward
- runtime DPoP validation over nonce, `jti`, `htm`, and `htu` during both
  token exchange and MCP protected-resource admission

Missing, stale, replayed, or mismatched DPoP proofs now fail closed instead
of degrading into bearer-only authorization.
