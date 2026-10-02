# Common work-composition model, KW1

Date: 2026-10-02. Task 2. This is a research abstraction over the
[shipped-assumed recovery contracts](recovery-baseline.json), not another native
execution authority. Both candidate and B1 receive this model and its fixtures.
The [crosswalk](recovery-crosswalk.md) supplies requirement IDs C01-C15; J1-J5
identify the additional composition obligations.

## Entities, ownership and production correspondence

| Entity | Mathematical record and controlling principal | Existing recovery boundary |
| --- | --- | --- |
| Owner | Domain, principal, qualified host, activated authority roots, policy components. Each owner controls its own roots and restrictions. A peer cannot activate them with a signature. | Authority-domain / tenant, authority scope, policy generation; C01, C05 |
| WorkEdge | Immutable sender, receiver, source version, action basis, typed prerequisites, allocation and optional backing/acceptance references. Both endpoints retain their own bindings. | `ActionIntentV1`, `AuthorizationRequirementsDigest`, artifact references; J1-J4 |
| LocalWorkflow | Owner, workflow ID, serving epoch, one unresolved effectful continuation. Independent siblings use separate workflows. | `WorkflowId`, `StepId`, `ContinuationId`, `ServingEpoch`; C02 |
| LocalOperation | Original issuance, finalized envelope, process request, native binding, capture and one-send claim; immutable observation history plus a derived view. | `FinalizedRequestEnvelopeV1`, `ProcessRequestDigest`, `NativeAdmissionDigest`, credential-free `RetainedToolAdmissionRequestV1`; C02-C04 |
| ResourceAllocation | Owner, parent, authorized total, disjoint remaining/reserved/unresolved/spent buckets. A child's allocation has one attribution path. | Native logical-call reservation and resource ownership; C02, C13, J2 |
| Observation | Source, operation, provider account/key, contract, outcome, coverage, fence and observation time. The observer controls an assertion, not the local authority that may consume it. | Native retained outcome, admission readback, `RecoveryView`; C03-C04 |
| ReleaseAuthority | Exact action/channel/recipient/basis, distinct owner or compartment releases and integrity endorsements, expiry. Every required component must be discharged by its authorized principal. | Disclosure grant v2 and exact approval issuance; C05, C09-C11 |
| Obligation | Settlement domain, backing allocation, beneficiary, amount, acceptance predicate and operation. The selected non-equivocating settlement service owns backing; the selected verifier supplies acceptance. | Existing funded-work settlement, attached through J2-J3; no new minting API |
| EffectContract | Receiver/account/key scope, retention horizon, one submission, authenticated lookup coverage and closure rule. Receiver guarantees are an explicit assumption. | P1 qualified connector/effect profile; C04, C08, C14 |
| EvidenceRef | Typed issuer, context and immutable record reference. Historical fact, current predicate and held reservation have different lifetime rules. | Verified historical evidence and capture basis, `VerifiedCaptureBasis`; C06 |

These are model entities, not claims that identically named Rust types already
exist. Intent, process and native digests remain distinct. The executable profile
uses small symbolic identities instead of testing hashing, signatures, payload
parsing or byte custody. Authentic observations and durable transactions are
ports supplied by PR #1172's assumed semantics. Wrong-context authentic evidence
is still untrusted for the attempted use.

## State and transitions

Let each honest owner retain `(A, X, K, R, O, H)`: local authority, execution
knowledge, knowledge/release restrictions, resource attribution, backed
obligations and append-only history. No cross-owner atomic database is assumed.
Messages are duplicated, delayed, reordered or malicious; local durable commands
are linearized by their owning store. Multi-store actions use intent/readback
under the original identity. A crash cannot turn an uncertain commit into absence.

An operation progresses from fresh to captured, then an attempted send. An
acknowledged effect is applied or partial. A lost acknowledgement is unknown,
whether the oracle saw zero or one physical effect. Qualified E1 evidence may
append a refinement to applied, partial or closed-no-effect. History is never
rewritten. Contradictory terminal observations quarantine the operation; a repair
can only reconstruct its projection. Unknown remains possible indefinitely.
Result availability, result-release permission, internal settlement and financial
refund are independent state components.

Approvals bind all modeled semantic fields: bytes/version, recipient, provider
account, relevant policy and ACL versions, operation and obligation class.
Unrelated-owner revision does not stale them. Finalization stores the original
issuance and exact symbolic envelope once. Capture rechecks current authority,
approvals, dependencies and affordability, consumes the original nonce once and
reserves exposure. Recovery of a lost acknowledgement returns the original
record. Captured work cannot obtain another send from restart, expiry, refund,
projection repair, advice, garbage collection or a stale coordinator.

Resource buckets are disjoint. Before capture its partition is remaining; after
capture it is reserved; after an unacknowledged attempt it is unresolved; after
an acknowledged applied/partial effect it is spent. Closed-no-effect releases
that operation's exposure only when the effect contract proves closure. The
one-send tombstone remains. No such release is inferred from a refund. Fixed
partitions in KW1 are publication 1, independent sibling 2, child 4 and recovery
3, totaling 10 logical-call units. Monetary amounts use a separate ledger.

The publication parent's 100-unit buyer backing and the specialist's 30-unit
provider backing are distinct allocations. Accepted child work is irrevocably
earned under the agreed checker; parent refund cannot debit it. A separate fork
fixture offers two 60-unit allocations against one 100-unit wallet. The second
must fail. Settlement itself releases commercial metadata: amount, beneficiary,
payment occurrence, exposed timing and acceptance-token existence. KW1 assumes
explicit permission by every affected owner to the actual S/V/public observers
for these limited facts. A variant withholds that permission and blocks the
corresponding external payment. Internal obligation recognition does not disclose
an output and does not require the initiating caller's current read grant.

Knowledge labels are sets of owner/compartment restrictions; accumulation is
monotone. Confidentiality release cannot substitute for integrity endorsement.
Qualified confined children begin with only admitted seeds, receive explicitly
bounded returns, and mediate result, error, status, log and payment channels.
Any parent-controlled seed or metadata carries the parent's restrictions. The
finite model checks exact release coverage at each declared channel; it does
not model arbitrary program noninterference or covert timing channels. Translation
preserves each component injectively; unsupported or merging mappings refuse.

## E1 and E2: what the controller can know

E1 keys are scoped by receiver and provider account and bind the original
operation/basis. The profile permits one outbound submission, including after
an ambiguous send. Reconciliation uses authoritative lookup, not resubmission.
Evidence must be authentic, exact-context, within retention and cover all native
participants. `not_found` is insufficient unless the provider's fence closes the
original key against any delayed write. Partial application stays partial.
Lookup is external work: it requires current connector authority and an available
recovery allocation. Internal settlement requires the serving fence, narrow
recovery authority and the original retained facts, independently of caller
expiry and read permission. Release still checks the current audience authority.

E2 provides no authoritative absence/outcome query. The histories “write applied,
reply lost” and “send lost before application” are observationally identical.
Only the experiment oracle holds the physical effect count. No controller API
receives that count or the fault choice. Both sides must retain uncertainty and
exposure, while separately authorized independent work can proceed. Neither
profile promises arbitrary retry or exactly-once external effects.

## Invariants and progress

Quantify over every honest owner individually. An adversarial peer cannot violate
that owner's local guarantees merely by sending messages. Honesty of every peer
is not required. Continuing secrecy after plaintext release requires a receiving
host qualified by the data owner; a signature alone cannot supply that premise.
Qualified keys, durable storage/anti-rollback fence, complete local mediation,
settlement non-equivocation and the chosen acceptance predicate are assumptions.
A malicious administrator bypassing its own host is outside those local premises.

- K1: each mediated send/release has matching durable authorization at its owner.
- K2: scopes attenuate; separately, spent + reserved + worst-case unresolved +
  delegated remaining is at most the authorized resource, with one attribution.
- K3: possible effects, consumed authority and original identity survive recovery.
- K4: each earned obligation remains independently backed despite parent outcome.
- K5: crossing an edge imports evidence under local trust and lifetime rules;
  it cannot import live authority, drop a restriction or duplicate an allocation.
  Local K1-K4 and K7 suffice only when these interface premises actually hold.
- K6: under eventual delivery of the specified approvals/evidence and a fair
  scheduler, enabled registered remedies and independent authorized work can
  complete. No liveness claim is made for unavailable E2 outcome evidence.
- K7: every modeled release satisfies all source components and exact destination
  authority; retained knowledge and original labels do not disappear afterward.

K5 is an assume/guarantee obligation, not a novel theorem merely because it is
written here. Task 3 must state what, if anything, survives prior constructions.
The executable task can check finite traces; it cannot silently prove K5 for
arbitrary programs, unbounded histories or production Rust.

## Finite executable profile and non-goals

KW1 is a fixed acyclic graph B->P->C and P->E, with an independent sibling
workflow at P. Nodes are owner-local work, not a shared scheduler. Two release
owners and one integrity authority plus one extra compartment fit a four-bit
symbolic label. Three operations (publication, sibling, child) have separate
workflow IDs and partitions. Backing/funding fixtures use bounded integer units.
The initial explorer uses traces of length at most five over declared alphabets,
plus longer directed fixtures and all permutations of explicit fault schedules.
Bounds, alphabet and trace counts must be retained with results.

These are exploration bounds. Production's supplied bounds remain 16 offers,
8 top-level remedy steps, 32 expanded nodes, depth 8, 64 evidence references,
16 approvals, 64 KiB envelopes, nesting 32 and aggregate 4,096 entries. KW1 does
not establish their decoding/allocation checks. Cycles, dynamic graph creation,
Byzantine settlement, arbitrary program semantics, wall-clock performance and
independent deployments are excluded. Report these abstractions beside results.

## Fixture contract

[fixtures.json](fixtures.json) is the single input for both arms. Each family
F01-F16 contains independent variants. Every variant has the plan's required
initial state, commands, faults, visible observations and seven outcome fields.
A refusal names an authorized positive counterpart. Environment updates model
owner-controlled observations, not commands an untrusted agent can use to change
policy. Decisions consume only visible state and commands. Faults are delivered
separately to the oracle/transport after the decision. Expectations check accepted
commands as well as resulting state, so rejecting everything cannot pass.
