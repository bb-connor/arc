# Summary 131-02

Defined oracle-evidence envelopes and receipt integration rules.

## Delivered

- added `OracleConversionEvidence` and fail-closed validation in
  `crates/arc-core/src/web3.rs`
- threaded optional `oracle_evidence` into
  `crates/arc-core/src/receipt.rs` and the affected kernel, store, CLI, and
  SIEM test fixtures
- published the oracle-backed settlement example in
  `docs/standards/ARC_WEB3_SETTLEMENT_RECEIPT_EXAMPLE.json`

## Result

Price evidence is explicit, provenance-preserving, and reviewable without
mutating earlier signed receipt truth.
