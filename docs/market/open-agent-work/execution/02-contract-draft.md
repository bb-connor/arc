# F1 work agreement, draft 0.1

Date: 2026-09-14. Scope: fixed-price bilateral W0 work, followed by one
separately funded child and then W1. This freezes design choices for the next
experiment. It is not a registered wire profile, deployed contract or completed
M1. [Escrow fit](01-escrow-fit.md) motivates a separate experimental claim
contract; [qualification](../05-qualification.md) remains authoritative for Q1-Q10.

## Parties and trust

The buyer controls its mandate, resources and disclosure. The provider controls
production and its own subcontract budget. An independently designated F1
verifier evaluates the exact agreed predicate, holds retrievable evidence and
signs the financial decision. The selected settlement chain orders funding,
claims and monetary terminals. Discovery and message couriers confer no local
authority. Each honest operator still trusts its own kernel, host and key custody.

The initial executable fixture uses one host, synthetic keys, an in-process
development chain and mock tokens. That fixture cannot establish independent
administration or verifier independence. F1 assumes the designated verifier
does not certify false results or lose promised custody. Misbehavior by that
authority is a limitation to expose, not a property the signature solves.

## Artifacts and ownership

Names prefixed `experimental` below are proposed schema identifiers. They must
be registered with canonical encodings and malformed vectors before becoming
public APIs. Unknown versions and missing required bindings deny admission.

| Owner/artifact | Reuse | Required new bindings |
| --- | --- | --- |
| Buyer `BidRequest` | Requested scope, quote window, signed bid identity | Digest of the immutable proposed work terms in a versioned negotiation profile |
| Provider `AskResponse`, joint `AcceptedBid` | Existing exact bid/ask/token/reservation bindings | Both signatures must bind the same agreement digest; no unsigned metadata extension |
| Joint `experimental.work-agreement.v1` | Existing capability, Finding and disclosure identities | Work ID, buyer/provider keys and payout addresses, input digest, checker/profile digest, output grammar and byte limits, price/asset/domain, verifier/custodian pin, deadlines, disclosure and retention policy, optional parent digest |
| Funding authority allocation | Existing escrow deposit and authoritative observation concepts | Agreement digest, one allocation ID, chain ID, deployment/code pin, token, depositor, beneficiary, worst-case liability and finalized creation block |
| Local admission record | Pool/swarm budget reservations and native durable admission | Exact allocation-to-agreement-to-operation binding; original mandate and admission authority; no re-admission to repair an uncertain transaction |
| Provider `experimental.work-submission.v1` | Existing Finding/verified-fix artifact where the work family fits | Agreement and allocation IDs, exact input/output/checker digests, provider signature and custody receipt; on-chain claim commitment fixes the submitted result |
| Verifier `experimental.work-decision.v1` | Named Finding facets and class-specific challenge evaluation | Submitted commitment, accepted/rejected decision, required-facet results, predicate result, custody digest/horizon, claim ID and financial amount; explicit domain-separated EVM authorization of this canonical decision digest |
| Rail terminal and independent observer | Existing transaction/state verification and receipt lineage | Exact funding/claim/decision/operation correlation; paid, refunded and remaining locked amounts; chain head and finality evidence |

Do not use `BidRequest.payout_destination` as the provider payout field: that
buyer-signed field can designate a reimbursement destination. Do not silently
replace the existing settlement adapter's hashed capability ID with an
agreement hash. Preserve both identities and define the new profile explicitly.

JSON signed artifacts use RFC 8785 and existing Ed25519 verification helpers.
The EVM authorization binds their digest through a separate EIP-712 domain
including chain, contract and agreement. Encoding a body twice is not a license
to accept different input, output, amount or recipient values at the two boundaries.

## Monetary state and exact amounts

The first fixture locks service price **100 mock-token minor units**. Verifier
fee, dispute fee and provider bond are **0** in this functional profile. Gas
and actual checker costs remain separately recorded operator expenses with
predeclared budgets. This is subsidized functional testing, not a positive
margin or cheap-verification result. Nonzero fees require separate funded
liabilities and their own earned/refunded terminals before admission.

For each funding source, `paid + refunded + locked + fees_paid = deposited`;
all quantities remain nonnegative. `locked` conservatively covers the remaining
maximum eligible service and fee claims. Local budget capture records consumption
of an authorized obligation; it must not also initiate an unrelated second
payment. On-chain payment is reconciled to that original hold.

The child example uses a separate 60-unit deposit from the intermediary's own
funding account. Expected parent revenue is never accepted as child collateral.
If the child earns 60 and the parent earns 0, the intermediary bears the 60
loss plus its production and transaction costs. Do not compare gross payments
summed across different funding sources with only the root buyer's ceiling.

## Deadline contract and pending claims

Use chain timestamps for authoritative deadlines. Local clocks schedule work
but establish no payment right. The prototype chooses relative intervals at
creation: `submit_by = t0 + 600`, `challenge_until = t0 + 900`,
`resolve_by = t0 + 1200`, `refund_after = t0 + 1260` seconds. These are test
parameters, not deployment timing recommendations.

1. A finalized deposit binds all terms before the provider admits payable work.
   If confirmation is uncertain, admission waits and the observer reconciles
   that exact allocation. There is no atomic database/chain transaction.
2. The provider obtains custody for the exact output and records its claim
   commitment on-chain at or before `submit_by`. A signed off-chain timestamp
   alone is insufficient. The first profile permits one output commitment,
   with exact retries idempotent and conflicting replacement denied.
3. A timely claim keeps the full amount locked through the challenge and
   resolution interval. A standing challenge can be lodged through
   `challenge_until`; it binds the same claim and evidence. In the minimal F1
   profile the pinned verifier arbitrates after that window, strictly after
   `challenge_until` and at or before `resolve_by`.
4. The verifier records a single accepted or rejected decision on-chain.
   Acceptance establishes `Payable`; beneficiary withdrawal has no expiry and
   requires no subsequent buyer action. Rejection establishes a refundable
   terminal. No alternative decision can replace either recorded terminal.
5. With no recorded decision, refund is available only strictly after
   `refund_after`. It resolves the financial obligation, not the truth of an
   unknown execution. A pending claim cannot be swept during its resolution
   window. The finality policy also controls when observers call this final.

The initial contract pins the verifier key per funded agreement. New-job pause
and future-key rotation must not invalidate already payable withdrawals or
rewrite existing agreement keys. Compromise of a pinned verifier key is an
explicit F1 authority failure; designing a recovery council is outside this
slice. Do not import the legacy registry's current-key requirement and claim
that it preserves earned rights.

Progress assumes the verifier, custodian and rail are available within the
agreed intervals. A provider with only a local submission during a chain
partition has no on-chain timely claim. A verifier outage through resolution
can leave a timely producer unpaid after timeout; the provider bears that
declared production loss. The evidence must distinguish this from rejection.
No finite deadline makes arbitrary partitions harmless.

## Terminal matrix

All amounts below are service amounts in the 100-unit fixture; verifier and
dispute fees are zero. Original execution state and financial state are separate.

| Work observation | Decision authority and sufficient evidence | Service terminal | Refund eligibility | Retrieval and loss owner |
| --- | --- | --- | --- | --- |
| Accepted | Pinned verifier; exact timely claim, required verified facets, passing agreed predicate, retained output; accepted decision recorded in resolution window | `Payable`, then `Paid(100)` on successful beneficiary withdrawal | None, even after later deadlines | Custodian serves buyer/provider/verifier under agreed policy; buyer pays 100 |
| Rejected | Pinned verifier; exact claim and documented predicate/facet failure; rejected decision recorded after challenge window | `Rejected`, no service payment | Depositor receives 100 through one refund withdrawal | Rejection evidence and submitted output retained; provider bears failed production |
| Unsubmitted | Authoritative chain state has no timely claim | Timeout refund; service payment 0 | Strictly after `refund_after`, once | Any local incident evidence retained; provider bears attempted production |
| Unknown execution or missing verifier decision | Original incident remains unknown; observer proves no monetary decision by timeout | `TimedOut`, then `Refunded(100)`; unknown execution remains unknown | Strictly after `refund_after`; never after `Payable` | Retain incident and any custody; provider bears production and unavailability loss |
| Contested | Standing challenge retained; pinned verifier evaluates class-compatible evidence after challenge window | Locked until accepted/rejected decision, otherwise recorded timeout | Only rejected terminal or decision-free timeout permits refund | Retain both submissions and adjudication; loss follows resulting row, never an unsigned challenge summary |

An accepted decision can coexist with an unknown unrelated tool effect only
when the agreed artifact predicate is independently established. It must not
rewrite that tool's history as known. Failed token withdrawal leaves the
claim payable or refund due; it cannot count as completed payment.

## Finding facets and challenge mapping (P45)

Use the existing [13-facet verifier](../../../../crates/trust/chio-finding-verifier/src/verify.rs)
and [challenge evaluation](../../../../crates/trust/chio-finding-challenge/src/evaluate.rs).
`Verified`, `Asserted`, `Unavailable` and `Failed` retain their meanings.
Any required facet that is not `Verified` prevents a positive F1 decision.

| Existing facet | Work-profile treatment |
| --- | --- |
| `ArtifactIntegrity` | Required: exact submitted bytes and signed Finding |
| `IntentBinding` | Required: agreed task/input; add exact agreement binding in the new profile |
| `IssuerLineage` | Required: authorized provider/issuer chain and role identity |
| `KernelAndRevocationTrust` | Required when native execution assurance is promised; ordinary fixture cannot assert it |
| `StatusLiveness` | Required under the selected status policy; stale/unavailable status denies that guarantee |
| `ReceiptAuthenticity` | Required for the native receipt claim; never substitute harness counters |
| `CheckpointMembership` | Required for promised logged execution and receipt inclusion |
| `RecipeBinding` | Required for the pinned acceptance recipe; usefulness still needs the work predicate |
| `MeteredExposureBacking` | Required for the local metered-ceiling claim; distinct from external service collateral |
| `SettledSpendBacking` | Evaluated after settlement; cannot be required as proof of payment before payment or substitute for pre-admission funding |
| `BondBacking` | No bond guarantee in the zero-bond fixture; unavailable does not become verified |
| `RuntimeAssuranceBacking` | Unsupported unless the selected actual host profile qualifies it |
| `GuaranteeConsistency` | Required: no aggregate guarantee stronger than supported facets |

The experimental contract-only harness has synthetic certifications and no
Finding verification. It cannot advertise the native profile above. W1 must
reuse the existing verified-fix payload and add exact base/patch/checker
bindings instead of treating artifact authenticity as repair correctness.

The provider submits; the buyer or another party with profile-defined standing
challenges; the independently pinned F1 verifier arbitrates; the custodian
retains retrievable evidence. Preserve existing class compatibility, standing,
retained authority policy and role separation. Challenge validation alone is
not a financial court decision. Missing evidence never becomes acceptance.

## Commercial evidence and claim ceilings (P47)

Commerce order verification replays supplied evidence, not execution. Passport
or enrollment evidence establishes only the selected identity/trust inputs.
Risk reports, financial credentials, reputation and underwriting formulas are
not deposits. Reuse `chio-fiscal` fee/bond vocabulary with explicit zero amounts
here and funded allocations for any later nonzero promise.

Preserve the [existing blocked claims](../../../../crates/platform/chio-trust-market-context/src/claims.rs):
operated permissionless provider marketplace, global trust score, liquidity
pool, risk syndication, underwriter market, autonomous guarantee sales and
slashing court. A narrow work-payment verifier needs a new versioned claim
decision and denial vectors; this draft does not expand old-profile claims.

## Numeric, parsing and retention boundaries (P53)

New monetary fields use canonical unsigned decimal strings: `0` or a nonzero
digit followed by digits; no sign, whitespace, leading zeros, exponent or
fraction. The first profile caps values and every checked sum at `2^53 - 1`
minor units for compatibility with selected hosted numeric boundaries. Existing
artifacts that support full `u64` remain unchanged; adapters reject overflow
or inexact rescaling, including `2^53` and `u64::MAX` into this profile.
The EVM conversion is exact integer scaling into `uint256`, never a float.
Timestamps are integer seconds within the same safe-integer bound. Hashes have
fixed length and explicit algorithms; EVM identities bind chain and deployment.

Freeze each envelope at at most 256 KiB UTF-8, nesting depth 16, with W0 input
and output each at most 64 KiB for this prototype. Reject duplicates, nonfinite
numbers and unsupported fields/versions in the public profile. Larger W1
patches are content-addressed custody objects with separately negotiated
length limits; do not embed them recursively in a Finding. These new-profile
limits still require parser vectors and implementation; they do not describe
all existing parser limits.

Retain public agreement, allocation, decision and monetary terminal evidence
for at least 30 days after `refund_after` and at least 30 days after the final
payment/refund, whichever is later. Retain encrypted/disclosed output under
the same minimum and the parties' agreed access policy. If a claim remains
payable, contested or financially unknown, keep its authority and custody
until resolution plus that recovery window; no finite garbage-collection
date may erase an unpaid accepted claim. Replay/consumption protection must
outlive replay eligibility, using durable tombstones or on-chain state.

Before each admission reserve evidence capacity as well as money. Security's
current 64-operation retained executor limit cannot be reset or evicted to
serve a 1,800-attempt trial. P53 remains open until sustained retention,
exhaustion denial and supported migration preserve occupied nonces and unknown
effects. The divergent version-10 research/security histories must be mapped
by schema lineage, not just a version integer.

## Local reuse and next obligation

Keep the real finding pool and swarm authority for honest local mandate
enforcement, allocation signatures, store binding, domain leases and rollback
protection. Add finalized external funding admission before paid work; a
post-dispatch settlement observer alone cannot perform that gate. Preserve
committed start, retained caller report, original unknown-payment successor
and verified manifest/session contracts from the selected Security M4 source.

P45/P47/P53 now have explicit design mappings. Their executable parsers,
migrations, custody, claims and sustained-retention tests remain required;
those packages are not complete. The next [implementation plan](../../../superpowers/plans/2026-09-14-funded-work-claim-escrow.md)
must establish claim preservation, then connect one allocation, one admission,
one verifier decision and one reconciled terminal on the reviewed native source.
