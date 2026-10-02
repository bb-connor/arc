# Mutually agreed release after unknown work

The protocol now lets two locally configured parties release an unresolved
work payment by separate, exact consent. The original signed incident remains
unknown. A native, fenced economic successor releases the original hold;
the independent Python buyer restores its reservation only after checking a
completed native release receipt. The path runs over the existing HTTPS and
A2A connection and recovers across process kills.

This closes the release seam identified in report 33 and makes the chosen
cross-company work protocol more usable. It remains progress, not an established
breakthrough. The strongest objection is that this is a bounded integration of
familiar signatures, durable intents and idempotent settlement under one
operator. Independent companies completing useful work and recovering failures
through the same contract, with materially less bespoke integration than a
matched alternative, would change the assessment. Local correctness alone does
not demonstrate that result.

## The decision and its evidence

An execution can remain unknown even when both parties decide that no charge
should remain. Conflating those facts would either invent no-effect evidence
or keep a consensually waived claim held forever. This change represents the
new economic decision without revising the historical execution evidence.

| Boundary | Before consent | Accepted release intent | Confirmed release |
| --- | --- | --- | --- |
| Original work terminal | Unknown | Unknown | Unknown |
| Original invocation | Consumed once | Consumed once | Consumed once |
| Original physical payment journal | Authorized | Authorized, retained as history | Authorized, retained as history |
| Effective qualified payment journal | Authorized | Settling, release action | Settled, release action |
| Provider monetary budget exposure | 100 | 0 | 0 |
| Buyer reserved credit | 100 | 100 | 0 after receipt verification |
| Buyer available credit | 900 | 900 | 1,000 after one atomic restoration |

No successful work receipt, checked rejection, Finding, invocation refund or
proof of no execution is invented. The result still reports
`workExecuted: null` and `buyerVerified: false`, with
`paymentResolution: "released_by_agreement"` and `localCreditSettled: true`.
The payment rail is the native provider-local TST ledger, not external money.

## Native authority and recovery

`UnknownPaymentReleasePolicyV1` comes from the receiver's local configuration.
It pins distinct receiver and counterparty keys, rail and currency. Co-signed
terms bind that policy digest, original operation, terminal projection, complete
signed incident, actual capability and exact authorized journal. Qualification
re-reads the original operation and journal from the qualified SQLite store.
It checks both role-separated signatures, historical capability signature and
hash, issuer and subject, incident signer and terminal, precise participant
profile, reversible hold, time window and monetary identity. Requests cannot
select or activate the policy.

The supported native operation is a tool dispatch with broker, budget and
payment participants, no attached tool return and an unknown terminal. Both
parties sign the same canonical terms using distinct signature domains. A
new acceptance must be within the offer's bounded window. An already accepted
intent remains executable after that window expires.

The store appends two immutable `unknown_payment_release_records` rows for the
original operation: accepted intent and completed release. It validates exact
row succession, canonical bytes, hashes, original admission and authorization,
serving fences, global commit coverage, and the matching zero-spend budget
reconciliation. Schema version 10 adds the table. The global authority chain
adds `payment_resolution` references to each immutable record; its prior released
schema definitions migrate without replacing historical commits.

Acceptance atomically commits the co-signed intent and monetary budget
reconciliation, preserving the consumed invocation. The native
`UnknownPaymentReleaseRuntime` then calls the locally wired adapter's `release`
with the original authorization id and original operation reference. Only a
`Released` rail result allows the completion row. The native signed completion
receipt is created afterward. Rail failure leaves the intent pending; startup
finishes that same intent and does not redispatch work.

Normal qualified payment reads derive the effective successor from this
validated history. The unknown terminal validator reads the unchanged original
journal. Existing terminal recovery claims remain unavailable. The new release
kind cannot substitute for the canonical no-effect or zero-charge bundles
required by the old payment transition API.

## Cross-implementation exchange

HTTPS enrollment v2 adds exactly one proof-of-possession grant, `resolve`, to
the prior four negotiation and retrieval grants. Historical v1 enrollments
remain verifiable and carry no resolution permission. The work agreement stays
at v3 because the new consent is a separate amendment.

The provider creates an offer only for the locally verified retained work
incident. The Python buyer verifies the proposal independently, countersigns
it and persists the exact consent before its first acceptance send. Concurrent
buyer processes select one retained intent transactionally. They can retry the
same economic decision without retrying the review. A proposal or saved consent
alone never restores credit.

The public completion package contains the original request, incident, consent
and native receipt. Both verifiers bind it to separately supplied peer keys,
original request and hold, exact signatures, policy, unknown operation, times,
fences and completion fields. Python uses its own JSON and cryptographic checks,
not Rust bindings or a verifier subprocess. Its accounting transaction requires
the local incident and retained consent, stores one receipt, enforces a unique
resolution id and restores 100 units once. Offline replay preserves both the
original incident and that completed economic result.

## Qualification

The [manifest](evidence/34-mutually-agreed-unknown-release/manifest.json) records
source hashes, the final provider binary, public evidence and verification logs.
The previous report's exported artifact hashes remain intact. This is an
uncommitted local checkout, not an exact-commit CI or release qualification.

Seven new isolated HTTPS scenarios cover unknown work before and after its
local write, provider death after intent but before the rail, after the rail
commit but before completion, after receipt creation, buyer death after saving
consent, and buyer death after receipt verification but before local accounting.
Every scenario uses four concurrent recovery clients, checks exactly one
restoration, retains the byte-identical original operation and physical journal,
checks the original invocation remains consumed once, restarts the provider,
and verifies offline replay. Both public verifiers accept the completed result.

The existing 19 HTTPS and 18 legacy HTTP scenarios pass against the same final
binary. They retain successful work, checked rejection, payment and acceptance
crash recovery, ambiguous sends, Unicode, concurrency, sender and transport
denials, and signed unknown incident verification. The 11 new malformed release
vectors carry valid outer provider signatures; both verifiers reject them.
They test invented completion, absent rail confirmation, invalid acceptance
times, changed policy, rewritten outcome, malformed or substituted fences,
changed input and a signature copied between roles. Buyer accounting tests
confirm these records cannot restore a reservation.

Validation passes 72 native admission tests, 13 kernel/SQLite integration tests,
86 SQLite admission tests, 122 budget-store tests, nine global-chain tests,
seven Rust example tests and 23 Python tests. Native and example Clippy checks
pass with warnings denied, as do formatting and diff checks. The paper builds
at 12 pages and 4,998 body words.

The [wire and operator notes](../../../examples/federated-work/RESOLUTION.md)
include commands and the recovery contract. Only the Python buyer implements
this resolution journal; Rust supplies the provider and an independent public
verification command. All process tests still share one Linux host and one
operator. The buyer's ambiguous send with no matching provider incident remains
unresolved. The current buyer cannot silently renew an expired consent that was
never accepted. Unilateral disputes, additional rails, independent deployment,
legal enforceability and general-purpose work interoperability remain open.
