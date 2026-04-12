# Summary 131-01

Defined receipt-root anchoring artifacts and publication flow.

## Delivered

- added checkpoint statement, receipt inclusion, chain anchor, and anchor
  proof types plus verification in `crates/arc-core/src/web3.rs`
- published `docs/standards/ARC_ANCHOR_INCLUSION_PROOF_EXAMPLE.json`
- verified that anchored Merkle roots reconcile back to canonical ARC receipts

## Result

Receipt roots can now be externally anchored and verified without replacing
ARC's signed receipt truth.
