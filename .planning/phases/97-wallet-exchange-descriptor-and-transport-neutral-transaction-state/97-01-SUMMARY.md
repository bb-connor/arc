# Summary 97-01

Defined one explicit ARC wallet exchange descriptor over the existing OID4VP
verifier flow instead of inventing a second trust root.

Implemented:

- `WalletExchangeDescriptor` with canonical `exchange_id`, verifier/client
  binding, one public descriptor URL, and replay anchors over request id,
  nonce, state, and request-object hash
- transport-mode disclosure for `same-device`, `cross-device`, and `relay`
  while keeping relay aligned to the existing HTTPS launch URL
- trust-control response wiring so OID4VP request creation now returns the
  neutral wallet exchange descriptor alongside the existing request and
  transport bundle

This keeps ARC's neutral wallet contract derived from the current verifier
truth rather than creating a parallel mutable session authority.
