# Summary 97-02

Added canonical wallet exchange transaction state over the persisted verifier
transaction store.

Implemented:

- `WalletExchangeTransactionState` with bounded states `issued`, `consumed`,
  and `expired`
- verifier-store snapshot projection that resolves the neutral transaction
  state without widening admin authority
- a new public read-only exchange endpoint at
  `/v1/public/passport/wallet-exchanges/{request_id}`
- consumed-state projection on successful direct-post verification so replay
  and duplicate submit attempts stay explicit and fail closed

The same canonical state now applies regardless of whether the holder arrived
through same-device, cross-device, or relay delivery.
