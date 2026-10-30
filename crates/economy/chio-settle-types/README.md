# chio-settle-types

`chio-settle-types` holds the settlement vocabulary that the kernel, the SQLite
store and the settlement runtime share: observer hook contracts, leased outcome
claims, retry policy and dead letters, completion-flow row ids, the shared
`SettlementError`, and the channel receipt-authority digest. It depends only on
`chio-core-types` and `chio-security-types`, so a consumer of this vocabulary
does not link any chain, web3 or finding-market crate. The chain-facing
runtime lives in `chio-settle`.

## Usage

```rust
use chio_settle_types::{
    settlement_completion_flow_receipt_id, settlement_completion_flow_row_id,
};

let row_id = settlement_completion_flow_row_id("receipt-1")?;
assert_eq!(row_id, "economic-completion-flow:receipt-1");
assert_eq!(settlement_completion_flow_receipt_id(&row_id)?, "receipt-1");
# Ok::<(), chio_settle_types::SettlementError>(())
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the boundary and invariants.
