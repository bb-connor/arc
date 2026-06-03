# chio-web3 Architecture

`chio-web3` owns Chio's official web3 settlement, anchoring, trust-profile, chain-configuration, oracle-evidence, and settlement lifecycle contracts. It is the source of truth for on-chain artifact shapes; generated bindings live in `chio-web3-bindings`, while execution lives in `chio-settle` and anchoring in `chio-anchor`.

The crate is data-contract heavy. Public structs describe signed key bindings, contract packages, anchor inclusion proofs, settlement dispatches, execution receipts, qualification matrices, and control-state traces. Validator functions enforce schema ids, references, custody boundaries, chain coverage, proof consistency, and terminal settlement state.

The security constraint is live-money exactness. Amounts, currencies, rails, anchor proofs, and oracle evidence must be validated before later crates attempt execution or reconciliation.

Planned improvement: reject non-uppercase settlement currencies in all web3 monetary amounts so dispatch and receipt artifacts cannot carry noncanonical live-money currency codes.
