# Security, formal properties and qualification

Status: required evidence for the proposed profiles. Program: [README](README.md).
Milestone/work-package mapping: [roadmap](04-roadmap.md).

## 1. Qualify a declared profile

Every result names its source version, work profile, funding rail, verifier
policy, delegation bounds, platform and adversary. Separate these adversaries:

- A malicious agent with only its legitimately delegated keys and tools.
- A malicious remote company administrator controlling its keys, process,
  database, offers, responses and network scheduling.
- A faulty or malicious discovery service and untrusted evidence courier.
- A crash, partition, unavailable verifier or settlement-finality disruption.
- A malicious funding or acceptance authority, which demonstrates F1's trust
  boundary rather than an adversary F1 claims to defeat.

Also state which resource owner's local kernel, operating system and key custody
remain trusted. A test with separate processes under one administrator does not
establish resistance to independent hostile administration by itself.

## 2. Properties to establish

| ID | Property | Evidence and limitation |
| --- | --- | --- |
| Q1 | Local authority cannot be enlarged by incoming evidence | Native dispatch-counter tests, issuer substitution and enrollment tests; assumes honest local enforcement |
| Q2 | Each admitted payable obligation has exclusive backing for its worst-case eligible claims | Funding-state model, actual rail allocation tests and independent balance reconstruction |
| Q3 | An obligation cannot produce incompatible monetary terminals or duplicate service payment | Contract/store concurrency tests and rail receipt/state verification |
| Q4 | Parent failure cannot erase a child's independently earned claim | Noncooperative-parent process and rail test with successful child work |
| Q5 | Financial resolution preserves uncertainty about original execution | Native incident/release tests and independent evidence replay |
| Q6 | Acceptance binds the exact agreed predicate, input, output and eligible beneficiary | Parser, signature, checker and settlement-substitution corpus |
| Q7 | Honest local disclosure and resource ceilings survive a hostile agent | Actual sandbox/egress tests and concurrent budget reservation checks |
| Q8 | Independent implementations agree on contract decisions | Cross-implementation vectors and process matrix, including malformed input |
| Q9 | Progress follows the declared availability and deadline assumptions | Recovery and partition experiments; no unconditional liveness claim |
| Q10 | Published evidence supports exactly the advertised property | Offline independent reconstruction, claim completeness and privacy review |

Q2 is per funding source and per honest payer mandate, as defined in the
[protocol](02-protocol.md). It is not a bound on gross payments summed across
the supply chain. Q3 concerns one agreed logical obligation; it does not prove
an arbitrary external tool physically ran exactly once.

The [repository reconciliation](08-repository-review.md) adds integration
packages P40-P55. Their acceptance evidence is required by the owning milestone;
the Q1-Q10 properties remain the stable claim vocabulary.

## 3. Model first, then connect it to code

Build a small executable state model for two funding sources, three work
parties, concurrent child requests and bounded integer amounts. Include
deposit, reserve, dispatch, submit evidence, establish eligibility, pay, release,
cancel, expire, crash, recover and fork-local-state transitions. Model the
funding authority separately from every participant's private journal.

Run a separate comparison against the real qualified finding-pool ledger.
Its store-binding, domain-exclusion and separate-device rollback-anchor
defenses already reject important clone/rollback cases. Identify what the
adversary controls, including the anchor and signing/runtime implementation.
The unsafe toy model does not establish a defect in that production ledger.

Begin with exhaustive bounded exploration that can produce a short trace for
each violation. Retain the broken local-only funding model alongside the
authority-backed model. The counterexample must fail for the claimed reason,
not because of an unrelated malformed signature.

Then prove or explicitly leave open these unbounded obligations:

1. Inductive conservation of the funding-source invariant under each transition.
2. Uniqueness of allocation consumption and incompatibility of payment/refund.
3. Preservation of honest-payer ceilings under concurrent admissions.
4. Preservation of independent child claims when parent state changes.
5. Attenuation and acyclicity within the selected delegation profile.

Use the repository's existing formal methods where they fit. Reuse verified
arithmetic helpers instead of adding a disconnected model with similar names.
Link model transitions to production entry points and run generated traces
against the implementation. A proof of a standalone model is reported as a
model proof until the refinement relationship is established.

## 4. Adversarial acceptance matrix

| Attack or failure | Injection point | Required observation |
| --- | --- | --- |
| Double pledge from forked payer databases | Two receivers accept conflicting claims concurrently | At most the compatible funded set becomes payable; no accepted unbacked claim |
| Relabel an allocation for another job, chain, asset or beneficiary | Receiver's direct admission endpoint | Denial before work and before a new reservation |
| Replay a stale funding snapshot after withdrawal/consumption | Authoritative funding check | No fresh admission based only on the stale proof |
| Forge an allocation with a valid payer signature | Funding adapter | Payer signature cannot substitute for rail authority |
| Race timely result evidence with a refund | Claim and refund entry points | Agreed ordering is enforced at the authority, including transaction reorderings |
| Buyer refuses every new signature | After valid seller submission | Eligible F1 claim remains redeemable under the pre-agreed verifier path |
| Parent dies after child acceptance | Parent process and host | Child payment is retained once, parent revenue may be zero, residual loss has backing |
| Child outcome is unknown | Before/after external side effect and before durable receipt | No blind execution replay; unresolved funds follow the agreed resolution path |
| Both providers die | Each persistence/rail boundary | Recovery depends on retained authoritative evidence, not reconstructed success |
| Correct outer signature on false child proof | Native parent output guard | Rejection before service payment eligibility |
| Imported issuer root or alternate procurement promisor | Receiver capability and permit verifier | Local issuer policy unchanged; no unauthorized dispatch |
| More children than authorized | Concurrent direct clients bypassing the planner | Aggregate bounds enforced at the trusted admission point |
| Onward delegation, cycle or reused ancestor permit | Child admission | Denial within the published depth/edge bounds |
| Expanded data, private canary, unexpected dependency | Actual projection and worker path | Unapproved bytes do not cross the honest owner's boundary |
| Symlink, path traversal or network escape | Hostile worker and checker | No access to host keys/state or unapproved destinations |
| Receipt-log fork | Two observers and funding verifier | Detect under the declared witness policy; cannot create additional funded claims |
| Verifier substitution or downgrade | Agreement negotiation and settlement | Existing signatures do not authorize the weaker profile |
| Duplicate JSON keys, overflow, noncanonical encodings | Both implementations | Identical fail-closed rejection rather than divergent interpretation |
| Key rotation or revocation during outstanding work | Enrollment, claim and identity registry | Old eligible obligations retain their specified resolution path; no new unauthorized work |
| Rail reorg, unavailable RPC, stuck transaction or fee exhaustion | Submission/finality adapter | Pending remains pending; no spend restoration from unfinalized evidence |
| Dishonest F1 verifier | Acceptance and custody service | Demonstrate and label the residual failure; do not claim F1 defeats it |
| Discovery poisoning and offer flooding | Enrollment and lookup | Bounded work, local policy preserved and no discovery-originated authority |
| Reuse a valid allocation against a different qualified store | Native finding-pool debit | Existing store-binding and allocation checks reject; a new adapter preserves this behavior |
| Concurrent calls evaluate the same old budget snapshot | Live model/tool/checker dispatch | Only the set with atomic prospective reservations runs within the ceiling |
| Treat observer success as prior funding | Native settlement-observer/admission boundary | Unfunded work never dispatches; post-dispatch observer state cannot retroactively authorize it |
| Double charge through native payment and external settlement | Reconciled logical obligation | One intended service charge across pool, physical journal and rail; separately declared fees remain distinguishable |
| Ask an old verifier to accept unsupported global-market claims | Commerce/passport/trust-market profile | Existing rejection remains intact unless a separately qualified version supports the exact new claim |
| Grant the agent a remote signer path | Actual worker and signing backend | Agent cannot sign arbitrary receipts, permits, authority documents or fund transfers |
| Hide required evidence or disclose to an unapproved model/custodian | Projection, checker and upload routes | Required acceptance predicates stay checkable and all recipients are locally approved |
| Redirect or resolve an allowed URL into a private endpoint | Actual discovery/RPC/artifact transport | Connect-time egress policy denies; credentials are not forwarded to the new authority |
| Numeric conversion at `2^53` or full `u64` bounds | Python/TypeScript/hosted adapter | Lossless supported encoding or explicit rejection, never rounded signed money |
| Retention/queue pressure while claims remain live | Store, nonce, outbox and artifact retention | Unknown obligations and necessary evidence are preserved; overload refuses new work safely |

Assertions must observe native dispatch, physical ledger state, output bytes
and beneficiary balances as appropriate. Cooperative client rejection alone
does not qualify a receiver boundary. Capture both accepted and denied signed
artifacts so an independent reviewer can establish what actually happened.

## 5. Persistence and concurrency schedule

At each external effect, inject failure before the durable intent, after the
intent, after the external acceptance, after confirmation and before the local
terminal. Include actual process termination and restart, not only exceptions
inside a transaction. For critical recovery paths use multiple concurrent
recoverers and independent clients.

Reconcile unknown submissions by the original operation reference. Never create
a new logical purchase because a network response was lost. Verify final
balances from the funding authority and separately inspect participant
journals. A matching local summary is insufficient if the rail paid twice.

Expired work, exhausted fees and unavailable settlement must have bounded
operating behavior even when progress is impossible. Record frozen capital,
required operator actions and the exact availability condition that permits
resolution. A timeout is not evidence that no external side effect occurred.

## 6. Independent conformance

Publish byte-level vectors, normalized decision outputs and state traces.
Require independently implemented parsing, hashing/signature checks, agreement
validation, claim eligibility and persistence. Document shared cryptographic
libraries; ordinary reviewed crypto reuse is acceptable, shared application
decision code does not establish implementation independence.

The current production Python and TypeScript market SDKs call the Rust `chio`
CLI for proof verification. Record that dependency and test those SDKs for
compatibility, but do not count them as independent application verifiers.
The independently authored provider/verifier must satisfy Q8 separately.

Run every supported buyer/provider pairing. Include all relevant historical
profiles as acceptance or explicit unsupported-version cases. Detect downgrade
attempts in negotiation and ensure omitted new fields cannot silently select
weaker funding or disclosure semantics.

Fuzz the trust-boundary parsers and transition APIs. Register selected fuzz and
formal harnesses according to current repository requirements. If a Cargo
manifest changes selection rules or dependency features, verify that the
required inventory actually runs; a green job with skipped targets is not
coverage of the change.

## 7. Evidence package and release checks

For each qualified run retain source/build hashes, dependency locks, environment
and toolchain, profile/schema versions, public role keys, setup configuration,
funding domain, contract code and registry state, finality policy, raw event
logs, fault schedule, public artifacts, verifier outputs and final balances.
Store private evidence under the trial's disclosure policy and publish explicit
omissions. Never publish secrets to make a reproduction bundle convenient.

Tie each claim to the minimal supporting artifacts and commands. List skipped
tests with their missing prerequisites. Existing `chio-settle` devnet tests can
skip when the contract toolchain is absent; qualification must fail if a required
lane is skipped. Preserve historical manifests rather than replacing them with
the newest source inventory.

Run targeted unit, process, contract and conformance checks for each code slice.
At integration, run the repository's required formatting, Clippy, build/test,
generated-artifact, security and exact-source CI gates for the changed surface.
Do not run full Rust qualification to validate this documentation-only plan.

The [security synchronization review](09-security-roadmap-sync-review.md) adds
required combined-source regression cases: committed start before external
effect; retained executor claim across process loss; late reports without
re-admission; immutable terminal-unknown financial resolution; output rejection
through native release; explicit schema predecessors; signed manifest admission;
negotiated session restoration without upgrade; and custody capacity exhaustion.
Include the actual process stack only when selected and brought onto this same
security checkpoint. A positive ordinary/Disabled host case does not qualify
native flow or an enforced cage.

On the integrated candidate, select the affected inventories from
`check-authenticated-caller-delivery.sh`, `check-native-restart-safety.sh`,
`check-consumer-boundaries.sh`, `check-consumer-sdk-parity.sh` and
`check-flow-security.sh`, then the broader required checks. Preserve their
exact-case requirements and negative calibrations. Security's earlier local
results, open review dispositions and pending hosted runs are input evidence,
not passing qualification of the combined source.

P55 must explicitly select `examples/federated-work`, `examples/composed-baseline`
and `examples/outcome-ledger-comparison` where their behavior supports a claim;
their standalone workspaces are not covered by root-workspace tests. Pin the
chosen native/hosted features and the independent Python suite. Reconcile
`spec/schemas/registry.json`, schema manifests, `spec/errors/registry.yaml` and
the Rust/Python/TypeScript/Go generated artifacts for each new public contract.
Use the existing network or KVM qualification scripts when that deployment
profile is claimed, with their actual prerequisites and clean-candidate gates.

G1-G3 require zero observed violations of the specified safety properties in
their declared corpus. Zero observed failures is not a probabilistic guarantee
of zero latent defects. Liveness, throughput, latency and commercial quality
are measured separately and include failures in their denominators.
