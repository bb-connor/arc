# Protocol architecture and funded obligations

Status: proposed design, not a normative specification or implemented guarantee.
Program entry: [README](README.md). Required attacks: [qualification](05-qualification.md).

## 1. Roles and trust boundaries

| Role | Controls | Other parties may rely on |
| --- | --- | --- |
| Resource owner | Local capability roots, guards, disclosure policy, budget mandate and agent credentials | Its own enforcement protects its resources; its signatures authenticate statements |
| Agent | Planning, offers, permitted tool invocations and proposed subcontracts | Nothing beyond independently checked outputs and authorized actions |
| Work provider | Its implementation, private state and delivery mechanism | The agreed result acceptance and funding profile, not an assumption of honest administration |
| Funding authority | An exclusive allocation state on the selected settlement rail | Backing, uniqueness and finality under the rail's explicit trust model |
| Acceptance verifier | A pinned acceptance procedure and, in profile F1, result custody and release decisions | Only the declared acceptance properties and availability commitments |
| Discovery service | Indexes signed offers and profile descriptions | Hints; every consequential claim is checked independently |
| Witness | Observes receipt commitments and conflicting histories | Detection under its availability and consistency policy; it does not manufacture backing |

An honest company's kernel remains trusted to mediate its own agent. A remote
company's administrator is allowed to be malicious in the adversarial model.
That administrator can lie about internal execution and retain any disclosed
data. Remote signatures establish attribution, not truth or runtime integrity.

Local policy selects acceptable funding rails, verifiers, credentials, task
profiles and disclosure destinations. Public offers cannot choose a network
endpoint behind that policy or install a capability issuer. A discovered
company may be accepted under an existing policy without being granted
authority over the receiver's resources.

## 2. Minimum contract surface

The names below are proposed conceptual objects. M1 must decide whether each
is a profile of an existing artifact or requires a new schema. Do not register
parallel versions of existing market objects just to match these names.

| Object | Required binding | Enforcement owner |
| --- | --- | --- |
| Work profile | Input/output grammar, acceptance predicate, checker version and resource limits, supported terminal states | Buyer and receiver independently select the profile |
| Work agreement | Buyer/provider identities, exact terms, input commitment, beneficiary, currency, amount ceilings, deadlines, settlement and verifier profile digests | Both parties sign; receiver validates before admission |
| Funding allocation | Rail/network/contract identity, unique allocation generation, agreement digest, claim schedule, amount, beneficiary and expiry/finality policy | Funding authority atomically locks backing |
| Procurement permit | Parent agreement and request, exact child agreement, delegate, receiver, disclosure commitment, ceilings and remaining depth | Honest payer authorizes; child receiver enforces |
| Delivery package | Agreement, output commitment and retrievable bytes, acceptance evidence, relevant child outcomes, receipt/checkpoint references | Buyer and selected verifier independently check |
| Outcome/claim | Exact obligation and eligible terminal, evidence digest, unique transition sequence and monetary consequence | Settlement profile decides eligibility and consumes the allocation |
| Incident/resolution | Original operation, evidence boundary, unresolved facts, named parties and a distinct financial decision | Durable journal preserves history; funding authority applies only the agreed transition |

All signed encodings use the repository's canonical JSON and domain separation.
Specify exact byte hashing, absent versus null fields, integer ranges, duplicate
key rejection, Unicode handling, array ordering and maximum sizes. Use bounded
integer minor units with an exact currency identifier; reject overflow. An
incompatible change receives a new profile/schema identity. No unsigned field
may change a signed obligation's meaning.

Preserve existing schema encodings. Some qualified pool artifacts represent
full-range `u64` amounts as canonical decimal strings; hosted numeric fields
are bounded by I-JSON limits. P53 must choose the exact encoding for each new
field and require explicit range-checked adapters. Never cast a full-range
amount through a JavaScript number or silently change a frozen signed schema.

The public wire profile must define negotiation, rejection codes, idempotency,
status, delivery retrieval and resolution. A2A task status is a transport-level
observation; it cannot independently make a payment final or turn unknown work
into a completed delivery. Bind application messages to the agreement and
logical operation, not a transport session's incidental identifier.

## 3. Funding conservation

Define a funding source `s` by its settlement domain, asset and exclusive
allocation generation. Let:

- `D_s` be cumulative finalized deposits into that source;
- `P_s` be cumulative disbursements to beneficiaries;
- `R_s` be cumulative releases back to the funder;
- `L_s` be the maximum remaining liability over reachable claim combinations;
- `F_s` be unallocated available balance.

The allocation transition must maintain:

```text
P_s + R_s + L_s + F_s = D_s
P_s, R_s, L_s, F_s >= 0
```

Use a conservative sum of remaining ceilings for `L_s` initially. Treat
terminals as mutually exclusive only when the funding authority enforces that
exclusion. A local diagram or payer signature is insufficient. Count funding
fees, verifier fees, outstanding retries and dispute obligations in their
actual funding sources. Token transfer behavior and rounding must not cause
recorded backing to exceed received funds.

An honest payer separately caps the total liabilities it authorizes across
funding sources and agent sessions. It must reserve a worst-case charge before
a cost-bearing action, including concurrent model calls. A provider API without
an enforceable upper bound cannot enter a profile promising an absolute spend
ceiling merely because its prompt contains a budget.

Do not sum every gross payment in a supply chain against the root buyer's
budget. A payment to an intermediary and its later payment to a specialist
are different transfers; counting both as root consumption double-counts
circulating money. Conversely, a promise of future parent revenue is not
currently available child backing. Initial profiles forbid lending against it.

Every accepted payable child must reference an allocation that the payer cannot
reuse or withdraw while that claim remains eligible. A receiver verifies a
fresh authoritative allocation and its exact binding before performing payable
work. Two receivers must not be able to accept incompatible claims against one
allocation, even if the payer forks every local database and signs both offers.

## 4. Worked failure economics

The following integer units illustrate accounting, not market prices.

Buyer A reserves 300: at most 280 for B's accepted final artifact, 10 for
verification and 10 for bounded settlement expenses. B independently reserves
100: 60 for C, 20 for D, 10 for child verification and 10 for child settlement
expenses. The obligations use explicit allocations even if their backing is
funded through a common wallet.

| Outcome | A's service payment | B's earned service revenue | B's child obligations | Who absorbs unsuccessful production? |
| --- | --- | --- | --- | --- |
| Parent and both children accepted | 280 | 280 | 80 plus applicable bounded fees | B pays its own production costs from margin |
| C accepted; B fails before final delivery; D never admitted | 0 | 0 | C's 60 plus incurred fees | B's prefunded reserve and own compute budget |
| Both children accepted; parent output rejected | 0 | 0 | 80 plus incurred fees | B, within the admitted exposure |
| C's outcome unknown | 0 until parent terms decide otherwise | Unestablished | C allocation remains locked until its agreed resolution path | The contract names timeout costs; uncertainty is retained |
| B refuses to acknowledge C's valid result | Depends on parent outcome | Depends on parent outcome | C can claim under the selected acceptance procedure without B's new signature | B cannot erase an earned child claim |

Fees may remain payable when service payment is zero; the user-facing outcome
must show both. Unperformed D work releases its allocation through an authorized
terminal. Cancelling the parent does not revoke C's already earned payment.
No claim that the whole graph either pays everyone or pays nobody is made.

## 5. First settlement profile: F1

Choose a single existing EVM settlement domain for the research implementation,
first on a local devnet, then a pinned test environment. Start with a bounded
allowlisted asset and no bridge or currency conversion. The specific external
network and asset are selected only after a deployment/cost review. This is a
reuse decision, not a claim that the current contracts already satisfy F1.

F1 uses a verifier selected by both parties before funding. It can check and
retain the complete result, certify eligible payment and deliver the result
to the buyer. Its honesty, key custody and availability are explicit trust
assumptions. It must not be controlled by the provider whose result it judges.
Independence from the buyer is also required if the seller is to rely on it.

The proposed exchange sequence is:

1. Parties sign immutable acceptance and payout terms, including evidence
   submission, dispute, refund and retention deadlines.
2. Backing is finalized and exclusively assigned to those terms. Local dispatch
   remains closed while funding is pending or unverifiable.
3. The seller submits the artifact to the selected verifier/custodian before
   the submission cutoff. Both input and output commitments are checked.
4. A valid result becomes durably retrievable under the agreed custody policy.
   The verifier issues an agreement-bound claim certificate. Invalid results
   receive an explicit rejection; neither self-attestation nor a hash match
   substitutes for the acceptance predicate.
5. The rail consumes the claim once and pays the fixed beneficiary. Buyer
   retrieval can be retried without a second payment. Withholding a buyer
   acknowledgement cannot defeat an otherwise eligible seller claim.
6. If work cannot be established, the declared timeout/resolution procedure
   determines the money outcome and retains the execution uncertainty.

This is trusted-verifier exchange. Availability between certification and
retrieval, confidentiality at the verifier, and adjudicator misconduct remain
dependencies. A malicious verifier is outside F1's positive guarantee and
inside its documented residual-risk tests. Neither a Merkle root nor a
receiver signature proves that private output remains available.

### Existing contract fit is a hard gate

Inspect [ChioEscrow](../../../contracts/src/ChioEscrow.sol), its identity/root
registries and [settlement runtime](../../../crates/economy/chio-settle/README.md).
Map every F1 transition to exact caller restrictions, signatures, finality,
receipt-consumption rules and refund paths. The present escrow has registry,
operator and administrative dependencies. Merkle inclusion is an integrity
check, not a result-correctness predicate.

In particular, prove that timely evidence cannot lose to a unilateral refund
race, and that one allocation cannot be advertised for incompatible jobs.
At the inspected source, `ChioEscrow.refund` checks the escrow deadline and
returns the remaining deposit; that method does not consult a pending work
submission at an off-chain verifier. A timely off-chain submission therefore
does not by itself block the on-chain refund. F1 needs enforceable claim-window
semantics and an explicit timing/availability argument, not just a longer
timeout in the buyer client.
If current methods cannot enforce those conditions, propose a narrowly scoped
adapter or contract change with its own review. Stop F1 admission until that
gap is closed. Do not put the missing condition in a cooperative client only.

F1's implementation must preserve progress independently of Chio's application
coordinator: evidence can be submitted and payouts retrieved through documented
interfaces after that coordinator disappears. The rail and selected verifier
remain required. Timely submission and settlement liveness require bounded
availability assumptions; a permanent network partition does not guarantee
both a deadline refund and eventual payment for an unseen claim.

## 6. State machines and timeout ordering

Keep separate state dimensions. Their labels below are design vocabulary,
not existing enum names:

| Dimension | States |
| --- | --- |
| Work | proposed, admitted, executing, accepted-result, rejected-result, unknown |
| Backing | absent, funding-pending, locked, claim-pending, paid, refund-pending, refunded |
| Delivery | absent, committed, verifier-retained, buyer-retrieved, unavailable |
| Resolution | none, evidence-pending, contested, agreed, adjudicated, timed-out |

Forbidden combinations include paid without an eligible claim, refunded while
an enforceable conflicting claim remains live, and available balance restored
while an old capability can still create a charge. A settlement resolution
does not rewrite the original work state or physical side-effect journal.

Use distinct `accept_by`, `submit_by`, `challenge_until`, `resolve_by` and
`retain_until` deadlines. The selected profile defines their strict ordering,
clock source, finality allowance and outage behavior. A generic shared expiry
is insufficient. Child acceptance windows must leave the parent enough time
to compose and verify results, but the child remains independently claimable
after the parent's execution deadline.

All external calls use stable logical operation IDs. An ambiguous settlement
submission is reconciled against rail state before another transaction is
created. Unknown external tool execution is not blindly replayed. Retrieving
an existing artifact, proving a claim and repeating an idempotent query are
different operations from running the work again.

## 7. Delegation and disclosure

Preserve the current exact procurement-permit rule. Generalize it through a
bounded grant that permits a parent to request specific child allocations,
never to sign unrestricted spending instruments. Admit each child only after
atomically reserving aggregate company exposure and receiving authoritative
funding confirmation.

Use the existing `QualifiedFindingPoolLedger`, signed finding-pool allocation
and swarm graph/continuation interfaces as the starting point for P41/P43.
Their local accounting and graph guarantees are reusable. A swarm budget
object or preflight acceptance alone does not establish a durable debit or
external backing. Preserve store-identity and rollback-anchor requirements
when selecting the local node deployment.

The first composition profile allows one level and at most four children.
A later profile can allow depth three and at most sixteen total edges, after
cycle, resource-amplification and concurrent-admission tests. These are proposed
qualification bounds, not intrinsic protocol limits. A descendant cannot
increase ancestor disclosure permission, accepted task families or delegated
authority. Independently funded child spending is bounded by its own payer's
mandate, not assumed to be a subdivision of the root payment.

Disclose only locally approved exact projections. The parent binds the projected
bytes and permitted destinations before child admission. Check inside the
trusted dispatch path and again at the child receiver. Key separation and
OS isolation reduce agent escape paths; a dishonest remote administrator may
still copy legitimately received plaintext. Do not promise remote deletion.

The parent buyer receives the child evidence required by its selected profile.
Avoid publishing the entire commercial graph by default. A compact summary
may replace full child evidence only after the verifier specifies what
assumptions or proofs make the omitted information unnecessary.

## 8. Research profile F2 and portability

F2 investigates a narrow result family with a certificate or proof checked by
the settlement authorization mechanism, or an explicitly modeled challenge
protocol. It is allowed to reduce verifier trust only for the property it
actually proves. A signature on a test report is not such a proof. Optimistic
verification additionally needs an available challenger, data and incentives.

F2 proceeds only if [verification economics](03-verifiable-work.md) justify its
cost and complexity. F1 remains a separately named profile. Moving to F2 is
not a silent weakening or strengthening of F1's terms.

Portability requires shared object and transition semantics, not identical
databases or a mandatory Chio-hosted service. Other implementations can supply
their own local authorization mechanisms while preserving the receiver-owned
authority boundary and the common acceptance/settlement profile. Funding-rail
adapters are explicit trust adapters; replacing one requires requalification.

## 9. Required integration boundaries

The [repository review](08-repository-review.md) specifies the source-level
basis for these additional design constraints:

| Boundary | Required design decision |
| --- | --- |
| Funding before execution | Verify finalized backing through admission; the existing settlement observer runs after receipt persistence and cannot substitute for this gate |
| One monetary obligation | Map the local payment journal, pool debit, rail intent and settlement outcome to the same obligation; do not layer independent captures on top of each other |
| Prospective resource spend | Atomically reserve enforceable worst-case costs before model/tool/checker calls; workflow `record_step` remains actual-cost accounting |
| Task graph versus commercial graph | Reuse swarm witnesses and joins while distinguishing attenuated resource ceilings from separately funded company-to-company transfers |
| Acceptance and dispute | Reuse Finding facets, standing, retained authority and challenge compatibility; specify F1 custody and payout eligibility in addition to artifact integrity |
| Discovery versus trust import | Admit a new counterparty under an existing local policy without installing its keys as capability roots; honor existing profiles' explicit/manual trust-import requirements |
| Signing | Route each role through the chosen supported signing backend; a delegate must not gain a general signing oracle or an unrestricted settlement key |
| Evidence claims | Map commerce, passport and risk verifiers; old profiles continue rejecting unsupported global-market and insurance claims |
| Disclosure | Bind approval for model providers, custodians and artifact hosts as well as subcontractors; use existing selective-disclosure semantics only for predicates they support |
| Lifecycle retention | Retain backing, nonce, terminal and evidence identities through claim/dispute/recovery horizons; capacity exhaustion cannot release unresolved obligations |

The [security-worktree review](09-security-roadmap-sync-review.md) adds these
implementation constraints to the same protocol:

- For external caller execution, reuse committed native start authorization,
  the pinned executor and its durable claim/report lifecycle. Reservation,
  payment and agreement acceptance are not permission to execute. Raw executor
  reports remain private inputs to the kernel's guarded release path.
- Keep nonterminal `AwaitingCallerReport`, terminal execution-unknown evidence
  and a separate financial successor distinct. Late reports cannot renew a
  start interval or erase an existing terminal; financial resolution must
  compose with retained capture, child claims and current output restrictions.
- Use signed, locally admitted manifest registries and the selected negotiated
  peer profile. Legacy discovery, session recovery or a provider envelope must
  not silently acquire unsupported aggregate/cumulative authority.
- Map disclosure into native flow and one-shot declassification where that
  host profile is selected. Agreement terms cannot authorize broker administration,
  arbitrary key use or disclosure to a new recipient.
- Define supported store/ABI predecessors and sustained custody retention.
  Security's version-34 admission catalog and the paper's version-10 research
  catalog need an explicit integration decision. A 64-operation executor ledger
  without eviction cannot be treated as an indefinitely reusable service.

Choose one supported node profile for the first trial. The existing qualified
SQLite path is the default starting point; use the hosted PostgreSQL/worker
profile only when its tenancy and isolation are needed. Both require their
own actual configuration and qualification. Historical deployment notes do
not establish current live availability.
