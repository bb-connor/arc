# chio-open-market architecture

## Responsibility and boundary

The crate owns capability-market bid, ask, acceptance, and reservation shapes;
governed penalty evaluation; and finding-specific admission, purchase,
audit, slash allocation, and recovery checks. It signs token offers and
acceptance records. It does not reserve funds, persist allocations, dispatch
settlement, or install issuer trust in a kernel.

`VerifiedReservationReceipt`, `VerifiedFindingAdmission`, and
`VerifiedFindingPurchaseAsk` have private construction state. They represent
the checks performed by their constructors against supplied inputs. Hosts
must supply trusted authorities and current snapshots before using them.

## Structure

`bidding.rs` implements `bid`, `accept`, and reservation authentication.
`fee_schedule.rs` re-exports the fiscal fee-schedule contracts.
`penalty`, `evidence`, `evaluation`, `authority`, and `validation` define
penalty issuance, evaluation findings, scope, and authority checks.
`fiscal_adapter.rs` binds legacy schedules to governed fiscal authorization.

`finding_admission.rs` provides allocation snapshots, expiry bounds,
admission witnesses, and finding-specific bid and accept entry points.
`purchase_verification.rs` checks the portable purchase context.
`recovery.rs` verifies recovery context and mints constrained recovery grants.

`finding_audit.rs` implements reproducible target selection and report
verification. `finding_penalty` and `finding_slash_amount` implement challenge
penalty binding and checked award allocation. `finding_bid_policy` computes
buyer-local bid ceilings; `finding_pheromone` validates carried trust evidence.
The Kani harness module compiles only with `cfg(kani)`.

## Data and control flow

1. A host resolves a `Listing` and supplies a signed buyer `BidRequest`.
2. `bid` verifies signatures and listing/pricing/issuer authority consistency,
   applies price and scope checks, then signs a scoped capability and ask.
3. A funds service produces a reservation statement; the buyer constructs
   `VerifiedReservationReceipt` under the selected service key.
4. `accept` binds that reservation to the ask body digest, agent, listing,
   currency, and total token liability, then signs the acceptance record.
5. The host durably records and executes the accepted economic operation.

Finding publication adds signed venue admission. `verify_finding_admission`
checks the active allocation snapshot and yields the witness used by
`bid_with_finding_admission` or `bid_with_finding_purchase`. The activation
verifier checks an available allocation or an exact prepared replay without
yielding a bid witness. The consuming store commits activation atomically.

`verify_purchase_context_pure` authenticates the finding and venue admission,
recomputes constituent envelope digests, checks seller authority, and binds
the bid/ask/accept handshake to the token and requested output. Deep activation
checks and fresh status remain host responsibilities at their relevant steps.
Recovery verification reuses purchase verification, authenticates the original
capability and purchase terminal, and returns a constrained recovery witness.

## Trust and invariants

Generic bidding binds listing and pricing signers to the body's namespace
owner and selected issuer. `BidMintContext` supplies the agent subject,
token identifier, trusted evaluation time, provider constraints, and DPoP
setting. `bid` does not prove an external relationship between an agent ID
and that subject or install provider authority in a runtime.

Generic bidding uses the listing's retained fresh-state marker and current
pricing window. The host must refresh report freshness and check listing
expiry before minting from a retained discovery result.

`bid` rejects sibling scope prefixes using colon-delimited segment matching,
binds the server to the listing subject, and uses checked expiry and total-cost
arithmetic. The provider supplies the grant constraints. Generic acceptance
requires finite total-cost limits and a reservation at least that large.
Its ask digest hashes the canonical ask body; finding artifact references
separately use complete signed-envelope digests.

Finding admission checks venue identity and signature, seller authorization,
terms and backing identities, current-time windows, collateral authority,
allocation state, penalty posture, schedule authorization, and one-currency
backing size. Admission expiry cannot exceed any supplied constituent bound.
The caller supplies expiry bounds and the allocation snapshot from trusted
state; verification performs no store read or durable compare-and-swap.

Penalty evaluation checks supplied governing keys, signatures, scope,
freshness, bond class and slashability, currency-safe amounts, and reversal
linkage. It returns findings and admission-blocking posture. Issuance and
evaluation do not themselves execute a slash.

`verify_audit_report` re-derives the committed selection and checks signed
attempt/outcome accounting. Budget-capped selection is a local planning
helper; report verification uses the full selection and requires missed
attempt records. Buyer ceiling estimates remain unsigned caller inputs;
checked discount arithmetic establishes a local bidding limit.

## Dependencies

`chio-listing` provides discovery and activation artifacts; `chio-governance`
provides charters and cases. `chio-fiscal` provides fee contracts and governed
authorization. `chio-finding` supplies finding identities and pinned family
verification. `chio-pheromone` supplies trust evidence. `chio-core-types`
provides canonical signatures, export envelopes, and capability types.
`base64`, `serde`, `serde_json`, and `thiserror` implement carriers and errors.

## Verification

`tests/bidding.rs` checks offers, reservations, authority mismatches, stale
listings, scope boundaries, acceptance windows, and overflow. Finding admission
tests cover allocation states, penalty blocks, schedule and expiry bindings,
and delivery-committed purchase offers. Purchase verification, bid-policy,
audit, and cognition-market integration tests exercise their separate paths.

Run `cargo test -p chio-open-market` for the library suites. The conditional
Kani harness targets slash-allocation arithmetic with fixed buyer-slot bounds;
signature, storage, and authority-index validity require separate tests.
Durable activation, funds reservation, runtime invocation, and final settlement
must be checked in the consuming service.
