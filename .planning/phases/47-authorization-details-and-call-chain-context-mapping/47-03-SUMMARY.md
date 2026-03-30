# Summary 47-03

Closed the fail-closed validation, docs, and regression loop for phase 47.

## Delivered

- added kernel regression coverage for malformed call-chain context in
  `crates/arc-kernel/src/lib.rs`
- added end-to-end trust-control and CLI regression coverage in
  `crates/arc-cli/tests/receipt_query.rs`
- documented the receipt, trust-control, and A2A call-chain projection
  boundary in `spec/PROTOCOL.md` and `docs/A2A_ADAPTER_GUIDE.md`

## Notes

- empty or self-referential delegated call-chain references now fail closed
- the external authorization projection cannot silently widen authority or
  billing scope because it is derived from signed receipt truth
