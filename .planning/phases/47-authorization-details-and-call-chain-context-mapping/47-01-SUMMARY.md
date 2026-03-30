# Summary 47-01

Added the phase 47 governed call-chain and authorization-context contract.

## Delivered

- added typed `call_chain` context to governed intents and governed receipt
  metadata in `crates/arc-core/src/capability.rs` and
  `crates/arc-core/src/receipt.rs`
- ensured governed intent binding hashes and signed receipt metadata preserve
  the delegated call-chain context in `crates/arc-kernel/src/lib.rs`
- defined derived authorization-detail and transaction-context report types in
  `crates/arc-kernel/src/operator_report.rs`

## Notes

- delegated provenance is approval-bound through the governed intent hash
- authorization-context export remains a derived projection from signed receipt
  data, not a second editable document
