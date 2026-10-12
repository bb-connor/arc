# chio-fiscal architecture

## Responsibility and boundary

The crate owns fiscal charter and schedule contracts, governance lifecycle
verification, continuity evidence, and schedule resolution. Five domains cover
tier limits, marketplace discounts, decision premiums, insurance premiums,
and open-market fees and bonds. Public builders produce signed artifacts;
verified wrappers carry checked evidence into lifecycle operations.

Durable storage and live consumer wiring belong to downstream implementations.
`FiscalStateAnchor` abstracts authoritative checkpoint reads and compare-and-swap
updates. Control-plane startup reconciliation combines this seam with the
SQLite fiscal store and installed runtime adapter registry.

## Structure

`fiscal.rs` defines signer IDs, parameters, charter/schedule builders, verified
wrappers, canonical decoding, and schedule lineage rules. `fee_schedule` owns
open-market scope, fee, and bond types and the legacy fee-schedule builder.
`input` routes bounded original bytes through the shared canonical reader.

The private `lifecycle` module re-exports six implementation modules:
`proposal` owns genesis policy, proposal admission, and admission registries;
`activation` verifies approvals and activated schedule/rotation targets;
`continuity` owns authority state, checkpoint advance proofs, and anchor commits;
`readiness` binds the installed runtime adapter registry; `resolver` selects
parameters; `support` centralizes lifecycle digest and validation helpers.

## Data and control flow

`FiscalCharterBuilder` normalizes domains and signer order, derives a canonical
content ID, and validates fields before signing. Charter verification validates
the body, checks its envelope signature, and computes the envelope digest.
Schedule builders bind to the verified charter; schedule verification checks
parameters, charter binding, predecessor sequence, signature, and size.

A proposal is admitted through configured admission trust. Current-charter
members sign approvals bound to that exact proposal and admission. Activation
verification checks membership, approval uniqueness and ordering, threshold,
timelock, validity, retained admission state, and the target's lineage.

A verified continuity advance is committed through the anchor's expected
checkpoint digest. The acknowledgement must verify and equal the exact next
signed checkpoint. Recovery reads the anchor and applies the same comparison.
Only a verified commit can yield `VerifiedFiscalActivationAuthority` for
activation history.

The resolver binds a checkpoint to readiness, genesis policy, authority state,
charter, clock high-water, and per-domain activation history. It returns active
parameters, valid last-known-good parameters, an allowed bootstrap fallback,
or a typed denial reason.

## Trust and invariants

Signer IDs hash raw Ed25519, P-256, or P-384 public-key bytes; hybrid signer keys
are rejected by `fiscal_signer_key_id`. Charter fields require nonempty domains
and signers, unique ordered keys, a nonzero achievable approval threshold,
positive durations, valid sequence/predecessor shape, and the expected self ID.
Parameter validation enforces domain-specific ordering, range, and currency
rules, including finite nonnegative insurance behavioral thresholds.

`VerifiedFiscalCharter::verify` checks the embedded signature. It does not
establish that the signer is an externally trusted governing operator.
`FiscalGenesisPolicy::validate` supplies genesis-authority pinning. Likewise,
a signed schedule has no activation authority until lifecycle and continuity
requirements are satisfied.

Charter and schedule byte loaders reject noncanonical input and enforce 1 MiB
limits through the shared original-byte reader. Object verification checks the
serialized envelope size after receiving an already materialized object.
`FiscalError::Input` retains the shared parser cause.

`FiscalStateAnchor` implementations must supply authoritative atomic
compare-and-swap and persistence. The crate verifies acknowledged evidence;
it cannot establish backend durability from a trait call. Resolver failures
include unavailable anchor, divergence, rollback, missing activated state, and
invalid last-known-good state. Once a domain is activated, its missing state
cannot reopen bootstrap fallback.

## Dependencies

`chio-core-types` provides canonical JSON, signatures, monetary amounts, and
signed envelopes. `chio-listing` supplies namespace normalization and listing
actor/admission classifications for market scopes. Hex decoding supports
classical prefixed key formats; Serde and `thiserror` model wire data and errors.
`chio-test-support` supplies test assertions. No Cargo features are declared.

## Verification

`cargo test -p chio-fiscal` checks deterministic IDs, canonical vectors, signer
key identity, parameter constraints, schedule lineage, and signed decoding.
`lifecycle_tests.rs` checks duplicate/nonmember approvals, threshold failure,
timelock and expiry, untrusted admission, charter rotation, restored-state
rollback, complete activation history, runtime readiness, and anchored fallback.
It also exercises anchor reads, compare-and-swap, and exact acknowledgements.

`tests/original_input.rs` checks duplicate-key rejection, parser-cause retention,
and private marker redaction. Durable recovery and configured fiscal consumers
have additional tests in their owning store and control-plane crates.
