# chio-settle-types architecture

## Responsibility and boundary

The crate owns the chain-free settlement vocabulary: `SettlementObservation`,
`SettlementOutcome` and the typed failure reasons, the `SettlementHook` and
`SettlementOutcomeStore` traits, leased claim validation, `RetryPolicy`,
`classify_attempt` and `DeadLetterRecord`, the completion-flow row id helpers,
`SettlementError`, and `derive_channel_receipt_authority_digest`. Its normal
dependencies are `chio-core-types`, `chio-security-types`, `serde` and
`thiserror`. It does not own chain clients, signing keys, durable storage or
channel artifacts; those stay in `chio-settle` and `chio-store-sqlite`.

## Trust and invariants

`SettlementHook::observe` consumes observations after receipt signing and
persistence. It is observer-only: implementations must leave the receipt store
unchanged, deduplicate by receipt id, and process observations ordered by
finalization time and then receipt id. Integrity and malformed-data failures
are permanent; only denied, non-economic and zero-charge receipts are skipped.
`SettlementFailureReason` stores a closed code and a detail digest, never the
raw detail.

`RetryPolicy::validate` allows at most 32 retries, nonzero backoff bounded by
one day, and a multiplier in `1..=16`. `validate_settlement_claim` limits worker
ids to 128 UTF-8 bytes, lease durations to one day, and batches to 1,024 rows.
Schema strings on observation, outcome and dead-letter frames are checked on
decode, and unknown fields are rejected, so a mismatched frame fails closed.

`settlement_completion_flow_row_id` and its inverse require a nonblank,
unpadded receipt id and the `economic-completion-flow:` prefix.
`derive_channel_receipt_authority_digest` is a domain-separated SHA-256 over
the canonical JSON of the kernel public key; its only failure is a
canonicalization error.

## Verification

`cargo test -p chio-settle-types` covers hook frame round trips and schema
refusal, failure-code parsing, retry envelopes and dead-letter decoding, claim
validation bounds, and completion-flow row id parsing. The
`settle-types` mode of `cargo xtask check web3-free-closure` is the dependency
gate: the crate's normal closure must not reach `chio-settle`, `chio-core`, any
web3 crate or any finding-market crate.
