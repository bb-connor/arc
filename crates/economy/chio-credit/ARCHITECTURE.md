# chio-credit architecture

## Responsibility and boundary

The public surface covers credit evidence, receivable IOUs, obligation state,
factoring, clearing, and capital instructions. It owns the contracts and their
validation. It accepts signed receipts and upstream appraisal or underwriting
evidence, and returns artifacts or verified wrappers to downstream consumers.

`CreditEvaluatorHook` maps a finalized receipt to zero or one legacy IOU.
`LocalCreditAccount` holds a signing backend and receipt trust configuration.
`IouEnvelopeStore` defines persistence by receipt ID; its implementation lives
in `chio-store-sqlite`. The crate has no settlement network client.

## Structure

- `lib.rs` defines exposure-ledger, scorecard, facility, and bond contracts and
  includes the `credit` files for capital books, execution, and allocation.
- `hook` defines the legacy IOU and evaluator trait; `local_account` implements
  minting; `store_binding` defines insertion and lookup errors.
- `obligation` owns atoms, dispositions, status proofs, facility binds, and
  credit-admission authority resolution and reservation records.
- `receivable_iou` binds a receivable envelope to receipt, obligation, settlement
  lifecycle, facility signatures, and committed admission evidence.
- `factor` owns normalized assignment requests, claims, offers, quotes, signed
  authorizations, and assignment results.
- `clearing` separates netting computation, finalization, abort, and lifecycle
  verification, including dispatch, reconciliation, and replay modules.
- `financial_credentials` projects authenticated economic evidence using
  `chio-fincred` types. `risk_reports` carries loss and backtest contracts.
- `formal_economy` supplies checked floor and ceiling conversion helpers;
  `kani_public_harnesses` is compiled under `cfg(kani)`.

## Data and control flow

Legacy minting first verifies the receipt signature, derived receipt ID, action
hash, and membership of the embedded kernel key in configured trust. It then
checks `is_allowed`, financial metadata, and nonzero charged cost. The IOU ID
is derived from the receipt ID, and the configured backend signs the body.
Reevaluation leaves the receipt unchanged; persistence is a separate operation.

The receivable path builds an envelope from an obligation atom, its disposition
and settlement lifecycle, a receipt, and a verified facility bind. Minting and
verification both look up the committed credit admission by operation ID and
validate its exact obligation and facility binding. A signed bind alone cannot
supply that online reservation.

`compute_netting_round` validates trust and input evidence, orders obligations,
resolves participant routes, aggregates checked amounts, cancels bilateral
balances, and returns statements, settlement intents, and digest roots.
`verify_netting_round` recomputes the output. Lifecycle functions validate the
separate evidence needed to advance a round or reconcile an external outcome.

## Trust and invariants

`LocalCreditAccount::new` trusts no kernel signer. The legacy IOU signature
verifier authenticates the embedded issuer key; it supplies no independent
issuer allowlist or source-receipt verification. Its body carries receipt ID,
time, scope, amount, and issuer key.

`verify_credit_facility_bind` checks configured authority, debtor, and creditor
keys and epochs, all three signatures, the lifetime ceiling, and current time.
`SignedReceivableIou::from_canonical_bytes` performs bounded canonical decoding
and body validation. `verify_receivable_iou` adds signatures, crypto floors,
role separation, exact source bindings, and committed store evidence.

`CreditAdmissionStoreAdapter::lookup_committed_by_operation` validates operation
identity and turns a validated committed record into a reservation wrapper.
Preparing reservation records is pure. Authoritative atomic reservation and
exposure updates depend on the integrating store and its mutation boundary.
`IouEnvelopeStore` requires identical reinsertion to return false and different
envelopes for the same receipt to fail with a conflict.

Capital proof validation checks signature and step fields. Envelope validation
adds time coverage and custody-provider approval; instruction validation adds
owner approval and action/reconciliation shape. Default support flags mark
external execution as non-authoritative and automatic dispatch as unsupported.
The crate does not broadcast a capital instruction or settle a clearing intent.

## Dependencies

`chio-core-types` supplies canonical JSON, signatures, receipts, capability
amounts, and economic continuity contracts. `chio-appraisal` and
`chio-underwriting` supply signed risk inputs. `chio-fincred` supplies financial
credential wire types; `chio-did` and `chio-federation` support credential source
identity and trust evidence. Serde models contracts and `thiserror` defines
boundary-specific failures.

## Verification

`cargo test -p chio-credit` exercises local minting, original-byte readers,
credit admission, facility binds, receivable IOUs, factoring, clearing, and
capital contracts. `tests/receivable_iou.rs` covers exact committed admission, source
request binding, role-key reuse, payee substitution, and crypto-floor rejection.
`tests/credit_facility_bind.rs` checks role signatures and lifetime boundaries.
`tests/clearing_lifecycle.rs` checks finalization/abort competition, effect
fencing, unknown outcomes, retries, and reservation release.

Property tests cover IOU invariants and conversion arithmetic. Kani harnesses
have their own toolchain and execution path; enabling the Cargo marker does not
run them. Downstream persistence, kernel observer integration, and settlement
rails require checks in their owning crates and configured runtime.
