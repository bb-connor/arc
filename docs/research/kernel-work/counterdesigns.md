# Strong counterdesigns for recoverable work across owners

Date: 2026-10-02. Task 1, G0 input. These are construction specifications,
not implemented baselines, equivalence proofs or benchmark results. The Chio
side assumes the complete [pinned recovery specification](recovery-baseline.json)
is shipped. The [source audit](task1-source-audit.md) separates inspected
mechanisms from the extensions proposed here.

## 1. One problem for all four designs

A buyer commissions a public issue derived from a private support ticket. A
provider hires a paid specialist. Two data owners control disclosure. The
specialist finishes and earns its payment; the exact issue is approved; the
publication acknowledgement is lost; the buyer then cancels. Separately
authorized sibling work should remain possible. Determine what may execute,
what may be disclosed, what remains committed, and who may be paid.

The challenge is preserving those distinctions across independent stores and
owners. Each implementation must satisfy the same K1-K7 obligations from the
[design](../../superpowers/specs/2026-10-02-kernel-breakthrough-research-design.md).
A safe refusal alone is insufficient: the approved issue, authoritative
reconciliation, earned child payment and independent sibling must have positive
paths under their stated premises.

### Matched trust and resources

| Role or assumption | Granted to Chio, B1, B2 and B3 equally |
| --- | --- |
| Owners | Buyer B, provider P, specialist C, disclosure owners D1 and D2; identities can coincide only where the fixture says so |
| Local execution | Each owner may operate an independent workflow engine, policy root, protected store, keys and fully mediated host; no common execution database is required |
| Adversary | Untrusted agents, tool output, arbitrary counterparties, validly signed malicious messages, message loss/reordering, process death and stale coordinators |
| Trusted local boundary | The honest owner's host, native admission service, durable store and configured authority bindings; a signature alone never establishes remote host enforcement |
| Remote confidential computation | Before releasing a secret, each affected owner must authorize the receiving host for that restriction, or authorize that disclosure outright. Protection after release to a malicious authorized recipient is not supplied by any design |
| Settlement S | The same selected non-equivocating ledger or escrow domain, finality rule, assets and checker trust. No uncollateralized promise is counted as backing |
| Acceptance V | An agreed, authenticated predicate over the exact child work, artifact, terms and allocation, with authority to read its evidence. It does not prove arbitrary usefulness or honesty |
| Capital | B places 100 units in the parent outcome escrow. P separately backs the child with 30 units. Parent failure can refund B's 100 while C keeps an earned 30; P bears that cost in every design |
| Execution exposure | A distinct hard-bounded resource: for example 10 call slots partitioned as child 4, publication 1, sibling 2, recovery reserve 3. Currency, calls, disclosure rights and provider side effects are distinct resources |
| Providers | Identical E1/E2 interfaces, credentials, preconditions, visibility and retention. None receives the experiment oracle's hidden effect count |
| Policy | Identical declared channels, owner/compartment requirements, confidentiality and integrity constraints, revocation boundaries and bounded remedy vocabulary |

Peer-to-peer means owners retain local authority. This profile still selects a
settlement trust domain. It supplies neither trust-free payment nor availability
from an offline owner. A baseline may use OPA/Cedar, receiver-issued OAuth tokens,
macaroons, ordinary fields, additional local transactions, or an equivalent
protected service. Those choices do not disqualify it.

### Provider profiles and the impossibility control

**E1:** the receiver binds a unique key to an exact account and request, durably
deduplicates the operation, and provides authenticated authoritative outcome
lookup. Its contract declares key scope, retention, effect cardinality and
closure/fencing semantics. The initial comparison allows one outbound effect
submission. After ACK loss, use lookup under the original key. Lookup permission
is current recovery authority; it is distinct from permission to publish or read
the result. Deduplicated resubmission is a separately qualified extension, not
assumed permission in this profile.

**E2:** one opaque non-idempotent submission, with no authoritative outcome
lookup. A timeout is compatible with both an applied write and no write. No
observation-based controller can distinguish those histories from that timeout
alone. Keep the possible effect charged and the original workflow blocked from
replacement. This is an application of established partial-observation reasoning,
not a new Chio theorem. A new risk allowance would change the task's authority
and success criterion and must be offered to every side.

For either profile, `not_found` is not final no-effect evidence while an old
sender can still act. Local closure must fence native admission and dispatch;
remote closure must cover any accepted or delayed submission. Expired retention,
partial effects and an unreachable receiver preserve uncertainty. Cancellation,
refund and output denial establish none of those facts.

## 2. B1: independent conventional services

B1 is the primary falsification baseline. Use protected local authorization and
workflow services with serializable local storage, qualified effect adapters,
decentralized information-flow policy and the same S and V. Beldi/RIFL provide
relevant logging patterns, not a license to atomically include arbitrary HTTP
effects in a database transaction. DLM/DStar supply prior art for independently
owned policies and scoped host trust. See S07-S13 and S25-S26 in the source audit.

### Records a builder needs

These are logical records. A builder may combine stores to reduce machinery.
All signed objects bind a version and domain, use canonical serialization,
reject unknown authority variants, and authenticate both the expected issuer
and the issuer's local scope. Credential-bearing custody stays protected.

| Record | Key, content and authoritative owner |
| --- | --- |
| Work edge | Sender/receiver domain, stable edge ID, parent edge, terms/version, allowed scope, allocation IDs, effect profile, checker and acceptance predicate. Sender proposes; receiver durably accepts under its own policy |
| Local operation | Owner + workflow + step + continuation + process-request ID + native-operation ID, with separate intent/process/native-material digests; current serving epoch and lifecycle. Native authority owns execution |
| Action intent | Materialized input/artifact versions, actual destination/account, output disposition, knowledge/influence dependencies, unsigned authorization requirements and effect contract |
| Approval | Exact action/challenge/requirements digest, owner/compartment/authority class, permitted release or endorsement, scoped basis versions, expiry and retained issuance ID. Each issuing owner signs only its own authority |
| Artifact | Immutable version with bytes commitment, producer, provenance and joined restrictions. Hash equality does not merge different provenance or grant read access |
| Allocation | Resource domain + allocation ID, amount/scope, exclusive attribution, parent, holder, state and authority epoch. S owns money; the relevant local resource authority owns execution exposure |
| Obligation | Edge + exact work/acceptance evidence + independently encumbered allocation + beneficiary + irrevocable earned state. S owns settlement, V owns the acceptance assertion |
| Provider operation | Native ID + provider/account/key + exact payload + profile/version + one-send state + authenticated outcome evidence + retention/fencing facts |
| Recovery custody | Exact finalized request and original fixed authorization/nonce issuance, retained separately from credential-free operation history |
| Receipt/export | Authenticated statement about one domain's committed facts. Audience-safe projection and explicit evidence trust; never executable ownership |

Store uniqueness constraints reject reuse of an identity with changed canonical
content. All returned replays receive fresh audience checks. The scope includes
errors, previews, approval metadata, result availability, artifact existence,
logs, streams, fork seeds and return channels. A bare secret-derived digest must
not escape through an otherwise public financial or receipt record; use a
protected reference or a properly hiding commitment with authorized opening.

### Authority and information flow

Keep owner-qualified obligations, not just their intersection of allowed
readers. For a value influenced by D1 and D2, ordinary release requires every
applicable owner/compartment policy. An exception can discharge only its exact
owner, authority class, action and crossing. It cannot reset retained knowledge,
make a whole artifact public, supply missing tool authority, or endorse integrity
when it grants only disclosure. Duplicate signer aliases do not satisfy two
distinct required authorities.

All ordinary children inherit their parent's knowledge and attenuated scope. A
confined specialist may start a distinct observation lineage only through an
authorized, verified isolation boundary. Parent-controlled prompts, filenames,
seeds, environment and launch choices remain information flows. C's success,
failure, logs and bounded return all pass the declared release boundary. A
schema-valid answer still needs disclosure authority. Commit the receiver's
knowledge before delivering the first byte, and retain release identity across
lost delivery acknowledgements. Snapshot restore joins existing restrictions.

Cross-owner labels preserve `(authority-domain, owner, compartment)` identity
and each obligation's meaning. Reject an unsupported translation, unless an
authorized exact exception resolves it. An owner may explicitly qualify a remote
host for a restriction; certificates cannot manufacture that trust. These are
ordinary implementable requirements, not capabilities withheld from B1.

### Local admission and cross-store recovery

The workflow driver has no effect credentials. Its progress records are
projections of native ownership. A transactional outbox alone is insufficient
for E2: a conventional outbox normally retries delivery.

1. Reserve the stable step/continuation identity before approval. Materialize
   inputs and unsigned requirements, acquire each required exact approval, and
   durably retain the signed issuance bodies and finalized request. Do not
   retrofit grants into a previously frozen request.
2. Obtain a durable encumbrance from S for paid work, bound to the edge, operation,
   terms and beneficiary. Replayed requests return that same encumbrance. The
   returned certificate is not a revocable balance snapshot: its backing cannot
   expire or return to the parent while dispatch remains possible or uncertain.
3. Write the admission intent before entering the native authority or beginning
   nonce preflight. Recover an ACK loss by reading the original issuance or
   native record. Never renew the nonce or invent a new operation to finish an
   old bridge.
4. The native service rechecks relevant versions, current revocation, complete
   owner coverage, resource bounds and exact digests. Its owning transaction
   joins grant consumption, reservation, continuation exclusivity and dispatch
   ownership. Only that owner may cross the effect boundary.
5. Attach the resulting native ID to the workflow projection idempotently.
   Failure to attach cannot undo native capture. Recovery reads native truth
   by the retained identity; it neither infers absence from a missing projection
   nor opens another continuation.
6. Before a provider await, commit a one-use send claim. Only its fenced holder
   may send. A crash after that claim may have happened before or after the
   actual send, so recovery performs E1 lookup or records E2 uncertainty. It
   does not resend. Stale owners cannot mutate authoritative state; final
   no-effect closure also proves no old holder can still send.
7. Append authenticated outcome/partial-effect facts. Commit knowledge before
   output release. A release denial leaves the external operation spent. A
   scoped recovery owner may settle existing work after caller revocation,
   subject to current lookup and output-read permissions.

Cross-store transitions use durable intents and idempotent readback, not a
fictional distributed transaction. If S commits the encumbrance before local
capture and the reply is lost, read it back using the same key. If native capture
never occurs, release funding only after authoritative local closure fences
late admission and any send. A timeout does not reclaim it. S can accept that
closure only from the configured authority for this operation or an equivalently
qualified mechanism. The transaction/isolation and trust costs belong in the
comparison. Hosts must bound unresolved intake and reserve recovery capacity.

### Accounting and cancellation

For each additive resource, track disjoint buckets for spent, reserved,
worst-case unresolved and delegated remaining exposure. Their sum cannot exceed
the allocation. A child has one attribution path; its usage is not counted both
as local consumption and as delegated consumption. A remote untrusted peer
cannot mint additional local rights by signing a receipt. Allocation transfers
are serialized by their owning authority or use an equivalently qualified
non-equivocating rights protocol. Ordinary escrowed bounded counters are prior
art, not automatically Byzantine-safe bearer rights.

S marks the child's 30-unit obligation earned only under V's exact acceptance
predicate, and makes that state independent of parent cancellation. Parent
refund is restricted to the parent escrow. If acceptance and cancellation race,
S's serialized transition order and pre-agreed child terms determine whether
the child was earned; cancellation cannot reverse an already earned claim.
Payment does not assert publication success. Cancelling a workflow disables
future admissions while preserving captured effects and narrow recovery.

### Useful continuation procedure

Use a finite, declared remedy registry, not arbitrary program synthesis. For
each proposed action, calculate unmet local authority, release, prerequisite,
allocation and effect conditions. Enumerate registered approvals, compatible
destinations, exact transformations, prerequisite calls, withholding and confined
returns. Keep alternatives that can establish the required conditions under the
same observations and policy. Distinguish a proved historical fact, a predicate
that must hold at capture and a reservation that must still be held.

Every effectful remedy is separately admitted. Enumeration is advisory until
fresh native capture. Exhaustion reports incompleteness, not universal
impossibility. An E1 lookup can resolve the original publication; E2 cannot.
A sibling can continue in its own workflow only with disjoint sufficient
allocation and no unsatisfied dependency on the uncertain publication. The
provider's one unresolved continuation does not globally suspend every owner.

**What B1 costs:** owner/label policy, custody and fencing, bridge recovery,
effect adapters, settlement binding and remedy integration must all be supplied.
They may be reusable libraries. The cost has not been measured; it is not valid
to count each repeated instance as new code after allowing Chio to reuse its
kernel. B1 already gives a plausible construction of every target guarantee.
Task 2 must check its state machine before calling it equivalent.

## 3. B2: durable capability contracts plus qualified local hosts

Use Agoric/Zoe's durable capability and asset-allocation mechanisms as the
contract core, with one owner-controlled local host for each agent/tool boundary.
S may be Zoe's settlement domain in **both** B2 and Chio, or a matched abstract
settlement authority in the first model. A shared SwingSet/Zoe platform is an
explicit platform trust and ordering assumption, not independent local execution
by itself. Independently operated vats or hosts do not inherit a cross-platform
atomic asset transfer: if multiple settlement domains are used, every side needs
the same bridge and its trust/availability assumptions.

### Implementable contract layout

- A durable work object stores the edge, local operation references, immutable
  terms, acceptance evidence and terminal obligation state. Expose distinct
  submission, approval, acceptance, recovery and payout facets; do not give an
  agent the creator or recovery facet by default.
- Parent and child have separately backed allocations. Contract seats and
  reallocations obey offer safety and rights conservation. For off-platform work,
  V issues an authenticated acceptance object/token under the agreed predicate;
  the contract checks that predicate before transferring the child's allocation.
  A token for an acceptance claim is not proof of the real-world deliverable.
- Before hiring C, P funds the child independently. When V accepts C's artifact,
  the contract durably records the earned state and pays C, or preserves its
  payout entitlement. A later parent exit cannot reclaim that child allocation.
- Local D1/D2 approval services issue exact, revocable-by-defined-boundary
  authority for materialized publication. A facet controls who may invoke a
  method; the method must additionally check exact payload, audience, remaining
  exposure and current phase. Possession of a general facet is insufficient.
- Persist operation identity, custody, unresolved sends and acceptance state in
  durable storage from creation. SwingSet transcript recovery and vat upgrades
  are different mechanisms. Ordinary promises can reject across upgrade; read
  a durable operation object (or qualified durable promise/vow abstraction)
  instead of treating rejection as proof that an external effect did not occur.
- The local effect adapter implements B1's one-send E1/E2 protocol. Durable vat
  execution does not atomically include an arbitrary public issue server. Bind
  its exact operation to the contract's encumbrance through the same intent and
  readback protocol. The adapter has narrow effect authority, not authority to
  decide acceptance or mint money.
- Add the same qualified information-flow/host layer as B1 for private artifacts,
  owner-specific exceptions, confined seeds and return channels. Object
  capabilities control access; this comparison does not equate them with
  complete information-flow tracking of arbitrary untrusted computations.

The finite remedy orchestrator can be ordinary code using durable work objects
and narrow facets. It receives the same observations and may call the same
owner approval and outcome services. Count chain finality/fees only where that
deployment actually uses a chain, and give Chio the same settlement latency.

**What B2 costs:** a host/effect/label integration and durable contract application
are needed. Zoe's inspected safety rule protects allocations according to the
proposal; it is not unconditional real-world work completion. Neither those
extensions nor off-platform recovery are impossible for the architecture.

## 4. B3: OpenAPPA with a qualified work host

Pin OpenAPPA at `a96f87d1fec900caf890f14342a089a32b3bfaff`. Reuse its pure
engine, bounded remedy planner, durable SQLite/PostgreSQL event log, pinned
policy basis, exact operation claims and result handling. Its unsettled effect
reservations already constrain `no_prior`; an indeterminate close retains them.
Do not call it a stateless deny-only policy engine.

Add a protected work host with B1's domain-qualified edge and native operation
records, financial allocations, receipt exporter, E1/E2 adapter and complete
declared channel mediation. These are proposed integrations; no claim is made
that this entire combination ships upstream. Conversely, their absence from a
selected source path is not a proof that an equivalent integration cannot exist.

### Bridge rules

| Boundary | Construction and cost to count |
| --- | --- |
| Exact claims | Bind authenticated organization, caller where required, session/root, stable operation ID and canonical input. Use caller-bound claims when owner/caller substitution must be refused; a session-bound receipt is not a cross-owner capability |
| Dispatch | Commit the engine decision and host admission intent before effect ownership. If operation claims and event batches are separate transactions, use idempotent bridge recovery; a policy permit alone cannot drive the network |
| Indeterminate effects | Map only authoritative known-no-effect evidence to a failure that releases a reservation. ACK loss maps to indeterminate, with the original native send state retained. Financial cancellation cannot emit a synthetic successful or no-effect fact |
| Owner policy | Preserve the owner/compartment obligation vector in protected host records. Intersect audiences for ordinary flow checks, but separately verify all owner-specific exceptions and integrity mandates. Retain exact input/code/output and one-crossing scope for transformations |
| Label translation | OpenAPPA `Label::top()` is maximum trust/public, whereas Chio's restrictive top is not that identity. Translate semantics explicitly; reject unsupported variants. Do not map enum names or discard extra owner clauses |
| Artifacts and isolation | Supply persistent provenance, pre-release knowledge joins, governed checkpoint restore, qualified confined contexts and complete return/error mediation. Do not make an experimental file adapter the architecture's maximum possible capability |
| Freshness | OpenAPPA family/flow/subject basis invalidation is preserved. Use separate roots for independent workflows with shared resource accounting. To narrow unnecessary invalidation within a root, a builder may add a sound dependency projection and count that extension |
| Remedies | Use the planner's registered alternatives. Additional cross-owner approvals and reconciliation can be declared host-mediated prerequisites, each separately authorized. Planner completeness remains relative to its supported registry and stage |
| Settlement | Use the identical S/V and child backing. Bind acceptance and cancellation to original edge/operation IDs, retaining earned obligations independently of root trajectory cancellation |

**What B3 costs:** the host bridges and semantic mappings above. Local recovery
planning, durable claims and retained uncertain reservations are supplied prior
art. Chio's potential advantage must survive giving B3 competent extensions.

## 5. Full scenario through each construction

The table is a design walkthrough, not a run log. Every row names a positive
path or an intentional refusal. S's money state, the publisher's effect state
and the owners' release authority remain separate throughout.

| Cut or event | B1 services | B2 capability contracts | B3 OpenAPPA host |
| --- | --- | --- | --- |
| Contract and backing | B escrows 100; P independently escrows 30; receiver accepts exact edge and local allocation | Distinct durable parent/child work objects and funded seats with matching S/V | Host work edge and financial records, same S/V; policy log carries no fictitious money |
| Read private ticket | Host commits D1/D2 knowledge before agent release | Qualified local IFC layer guards access through narrow object facets | Retained flow state plus owner-obligation vector and artifact metadata |
| Hire confined C | Trusted boundary, governed seed, child allocation and exact return contract | C receives only its work/return facets; local host enforces isolation and information flow | Declared confined return and planner rules plus qualified host/isolation and parent resource attribution |
| C finishes and earns 30 | V authenticates exact accepted artifact; S commits C's earned entitlement | V-controlled acceptance transition makes reallocation/payout durable | Host links acceptance to original edge; S commits the identical entitlement |
| Materialize public issue | New exact intent; D1 and D2 approve those bytes/destination; missing owner refuses | Required approval facets attest the same intent; contract/host conjunctively check both | Registered remedies plus host owner coverage; an unqualified authority cannot clear the gap |
| Capture and send | Native transaction consumes authority; one send claim; provider sees original key | External adapter captures once, referencing encumbered work object; a vat retry reads status | Engine/log decision joins qualified native dispatch; no policy-hook bypass or hidden transport retry |
| Crash loses ACK | Durable possible-effect state; recover original request and ownership | Durable external-operation object survives; rejected transient promise does not clear it | Indeterminate close preserves reservation; host retains original effect record |
| E1 recovers | Current scoped lookup returns authoritative original outcome; no second submission | Recovery facet invokes same lookup; record outcome separately from payout | Authorized lookup prerequisite supplies exact evidence; host settles original operation |
| E2 cannot recover truth | Unknown remains charged; no replacement workflow identity for that step | Work object remains unresolved even if money resolves | Indeterminate reservation and native record remain; no fake failure close |
| B cancels/revokes | No new admission; narrow original settlement can continue; B loses revoked read access | Parent cancellation/exit follows its terms; separate earned child allocation survives; recovery/read facets remain distinct | Cancelling host intake cannot erase engine reservations, earned child money or retained knowledge; replay output is freshly authorized |
| Independent sibling | Separate workflow uses its own two slots and satisfied prerequisites | Separate local work object/host and allocation; no dependency on unresolved publication | Separate root/workflow with explicit shared accounting, not a fork that sheds reservations |

If the public issue actually succeeded, a parent's financial refund still cannot
prove no publication occurred. If C's work was accepted, a withheld parent result
does not undo C's earned payment. If any required host/authority is unavailable,
the dependent branch waits; unrelated sufficient authority permits useful work.

## 6. What would defeat the Chio claims

1. **Expressibility:** B1, B2 or B3 implements the same allowed traces and
   refusals with matching assumptions. No new fields, ordinary authority service
   or protected local state may be prohibited to avoid that result. A behavioral
   equivalence proof or faithful executable trace match strengthens this defeat;
   the present designs already make an impossibility claim unsupported.
2. **Composition:** the proposed Chio contract is a restatement of established
   IFC, capability, recovery and escrow interfaces, without a nontrivial
   composition result or substantial demonstrated reuse. Combining names is
   insufficient. A counterexample at one edge defeats an overbroad theorem.
3. **Progress:** the competing finite controller selects the same safe actions
   from the same observations at comparable state/coordination cost. Comparing
   against deny-all, or granting only Chio lookup/current facts, is invalid.
4. **Systems value:** a reusable baseline adapter attains comparable setup,
   recovery and repeated-integration effort. Count its shared library once, just
   as Chio's kernel is counted once; include all assistance and operator repairs.

The open question is the cost and compositional sufficiency of a compact,
reusable interface, not whether ordinary software can store one more field.
The [claim register](claim-register.json) and [G0 decision](G0-DECISION.md) define
the next falsifiable step.
