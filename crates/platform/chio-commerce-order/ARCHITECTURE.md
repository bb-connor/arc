# chio-commerce-order architecture

## Responsibility and boundary

`verify_commerce_order` accepts `CommerceOrderVerificationBundle` and
returns `CommerceOrderPassportReport`. `CommerceOrderContext` binds
buyer/agent/merchant identities, order/quote references, state, paths, and
artifact digests. The bundle supplies event authority receipts,
payment/mandate/provider/settlement bytes, protocol payloads, optional
coverage, and signer pins.

The verifier replays supplied facts and builds a selective public summary.
It has no PSP client or transfer execution API. External payment
observations and authoritative receipt production occur outside this crate.
Trusted keys and previously verified trust-market context are caller-owned
inputs.

## Structure

`types.rs` defines strict serialized context, bundle, report, coverage
requirements, and trust-market projections. `ids.rs` defines schema
identifiers. `input.rs` bounds and strictly decodes original JSON.
`replay.rs` validates transitions and authority receipt bindings.
`mandate.rs`, `payment.rs`, `provider.rs`, and `settlement.rs` check their
artifact families. `validation.rs` checks money, timestamps, digests, and
safe paths; `error.rs` defines domain failures.

## Data and control flow

Verification checks byte/count budgets, context shape, canonical quote
digest, and each required artifact digest. Optional required coverage and
trust-market gates run before parsing the main artifacts. It decodes the
artifacts and replays the event log, then validates provider trust, mandate
payload bindings, payment lifecycle, and settlement dispatch.

The resulting report includes the replayed state, verified claim list,
canonical context digest, input artifact digests, and a selective-disclosure
policy listing disclosed/redacted fields. This policy is summary metadata;
actual private artifact distribution remains with the caller.

## Trust and invariants

Original JSON rejects duplicate/ambiguous input before typed projection.
Budgets allow at most 16 MiB per document, 64 MiB total, and 4096 supplied
documents. Event replay verifies supplied signed authority receipts using
caller-selected kernel keys. Provider and payment signatures likewise
require selected keys.

Provider freshness is relative to `order_context.issued_at`, including a
one-day maximum age. A required coverage report is authenticated through
`validate_risk_report_signature` and a commerce coverage projection; full
risk-ledger validation is a separate risk-comptroller operation. Required
trust-market context checks references and the selected provider; the public
typed structure does not itself prove prior verification.

## Dependencies

`chio-core-types` supplies receipts, canonical JSON, signatures, and hashes.
`chio-risk-comptroller` authenticates coverage report signatures. `chrono`
parses evidence timestamps. `sha2`/`hex` compute artifact digests;
`serde`/`serde_json` represent strict artifact types, and `thiserror`
preserves typed errors. No optional features are declared.

## Verification

`tests/commerce_order.rs` builds bundles from proof-room fixtures, adds
selected signer/receipt material, and mutates amounts, currencies,
transitions, provider trust, authority receipts, protocol payloads, and
coverage/context bindings. Run `cargo test -p chio-commerce-order`. The
README embeds the valid context, omits the event body, and asserts its
digest rejection. It performs no transaction or network access.
