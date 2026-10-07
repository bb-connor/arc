# Dynamic work delegation: protocol and argument

## The problem and implemented change

An agent can choose a collaborator after its owner's task is authorized. The
owner needs that choice to preserve the authorized effects, recipients, spending
ceiling and acceptance terms. A crash or another provider offer must not turn
the same allocation into a second independent authorization.

The implemented interface has five operations: create a root, subdivide a slot,
select an offer, seal the selection and execute the original native request.
`chio-workflow::delegation` provides the allocator and portable evidence checker;
`chio-kernel::delegated_work::install_delegated_work` installs the receiving
boundary. These are reusable experimental library APIs with a runnable native
example. They replace scenario-specific decisions with the same operation for
each dynamically created edge. They do not implement a marketplace or discover
new trust roots automatically.

## Roles and records

The **resource owner** configures a protected allocator, root contract and issuer
key. The **holder** can subdivide its slot and sign an exact provider selection.
The **receiver** signs an offer and independently issues a native capability.
The **courier** can carry evidence but cannot change any of those decisions.
A qualified payment rail separately handles actual holds and transfers.

The owner database is authoritative for allocating that owner's capacity. Each
receiver key has one protected native custody/budget domain. Copying either
database or key into a fork with independently spendable state violates this
profile's assumptions. There is no global workflow database or consensus claim;
coordination remains necessary at each shared resource allocator and rail.

| Record | Content committed | Authority |
| --- | --- | --- |
| WorkSlot | ID, holder, exact effect/reader sets, currency, ceiling, expiry, depth, acceptance clauses | Trusted owner creation or authenticated parent subdivision |
| Subdivision | Parent ID, parent allocation digest and complete child slot | Signature by current parent holder |
| WorkOffer | Allocation digest, slot ID and full slot digest, receiver, effect, exact input digest, price ceiling and expiry | Receiver signature; discovery alone is insufficient |
| Selection | Complete signed offer, exact native capability digest, request ID and expected selection revision | Current slot holder signature |
| DispatchPermit | Root ID, allocation digest, immutable slot, signed selection, issuance time | Explicitly accepted allocator key, after durable commitment |

Every signed body uses a distinct versioned domain and RFC 8785 canonical JSON.
Signatures include the signer's identity. A provider signs the complete slot
digest: two allocations with the same name but different acceptance terms cannot
share an offer. The receiver-signed v2 offer prices this checked-output contract:
a result rejected by the agreed predicate earns zero charge. The installed
native profile explicitly opts into the existing reversible-hold contract.

Local names are not global consent. A persistent random allocator namespace,
the complete immutable root slot and the complete target slot form the
allocation digest. Subdivision binds the parent's digest; the offer and
allocator permit bind the selected slot's digest. A selection signs the entire
offer. Each mutation checks its digest inside the same protected transaction
that changes allocation state. Equal names and terms at two honest allocators
therefore do not share holder or receiver consent. The namespace is an identity,
not a new signing authority; cloning its protected state still violates the
single-custodian assumption.

The prepublication signed domains are now v2. Earlier v1 mutations and permits
require fresh signatures. Opening an issued store whose namespace is missing
fails; it cannot silently mint a replacement namespace. No migration of live
v1 commitments is claimed.

## Allocation rule

Let a slot have ceiling B, effect set E, reader set A, expiry t and remaining
depth d. A child (b,e,a,u,k) is admissible only when:

    e is a subset of E
    a is a subset of A
    u <= t and current_time < u
    k < d
    currency(child) = currency(parent)
    allocated(parent) + b <= B

The holder and chosen receiver must appear in the child's reader set. Holder
authentication and all checks occur before an immediate SQLite transaction
commits a child and increments the parent's allocation. Parent capacity cannot
be copied to another child. Root creation is a trusted configuration API, not
an endpoint that an arbitrary agent may call to replenish its allowance.

A slot with children cannot execute. A selected slot cannot gain children.
This avoids counting the same capacity both as a parent invocation ceiling and
as delegated capacity. An internal slot's unused remainder can fund additional
children while preserving the same sum bound. The profile never reclaims a
child allocation. More flexible reclaim requires authoritative closure evidence
and a separate argument; a timeout or failed parent is insufficient.

Children may have different acceptance predicates because they perform
different subtasks. Consequently child success does not establish parent
success. The parent's result still needs its own agreed check. The allocation
rule proves no semantic decomposition of an arbitrary goal.

## Selection, sealing and local execution

An owner-qualified receiver signs an offer. The holder signs the offer plus the
intended native request and capability. A compare-and-swap revision allows a
new selection while rejecting replay of an older selection. Selecting the offer
authorizes its exact execution; any courier may request sealing. A replacement
can win only before sealing commits.

Sealing first makes the selection irreversible, then persists its signed permit
before returning it. A crash between those transactions can strand capacity,
but the frozen identity cannot change. A retry returns the stored permit, with
its original issuance time and signature. There is no extra allocation or new
request. This split intentionally favors safety over reclaiming uncertain work.

The receiver receives `{slot_id, payload, allocation}`. The input commitment is
the canonical digest of the slot ID and exact payload. The enclosing permit is
excluded to avoid circular hashing, and is separately authenticated. Unknown
wrapper fields reject. The receiver checks:

1. The allocator key was locally activated for allocation evidence.
2. The allocator, holder and receiver signatures and full contract digest agree.
3. Slot, subject, receiver, server/tool, payload, native capability and original
   request match the committed selection.
4. Offer and slot are live under the kernel's configured fenced authority clock.
   Native capability validity/revocation also pass.
5. The native grant is one exact invoke grant, with one invocation and monetary
   ceilings no larger than the signed offer, in the same currency.
6. Native durable admission and original request retention protect execution.
7. The exact delivered JSON satisfies the immutable predicate, after transforms.

Step 1 activates no capability CA root. A valid permit without a valid locally
issued native capability does not dispatch. The receiver needs no allocator
database or live allocator connection for these checks. Payment-rail access and
native custody availability remain independent requirements.

The restricted acceptance language contains 1-16 exact JSON-pointer equalities
or inclusive integer ranges. It checks the chosen predicate, not the general
truth or economic value of the answer. The native pricing contract returns a
denial with withheld output and zero charge on a qualifying predicate rejection;
an executed invocation remains consumed. The fixture rail has durable integer
balances, not real assets or public-chain finality.

## Conditional safety argument

**Attenuation.** Every child is a subset in effects and readers and no later in
expiry than its parent. Set inclusion and <= are transitive, so these declared
bounds hold along every created ancestor chain. Strict depth decrease prevents
a cyclic allocation lineage. This concerns declared envelopes; proving that a
tool has no undeclared channels requires the qualified host's confinement and
information-flow enforcement.

**Capacity.** Initially a root's unallocated capacity is B. Subdivision replaces
some unallocated parent capacity b with one child of ceiling b, atomically, only
when the remainder stays nonnegative. Induction over subdivision preserves the
sum of leaf ceilings plus unused internal capacity as B. Sealing consumes no
additional capacity. Because containers cannot execute, native invocations use
only leaf ceilings. With one authoritative custody domain per receiver, exact
one-invocation capability binding and native cost enforcement, admitted charges
are bounded by those ceilings. This is an allocation bound, not evidence of
funding or a proof of payment-rail correctness.

**Stable commitment.** Selection revisions order replacements. Sealing freezes
the complete selection before evidence escapes. A receiver substitution, new
capability, changed input or new request fails the bound comparison. Portable
reverification does not mint authority; native custody determines whether the
original request has already executed. Unknown original effects retain their
allocation. No exactly-once claim for arbitrary external effects follows.

These are ordinary inductive arguments under explicit enforcement assumptions.
There is no mechanized refinement proof from these statements to this Rust
implementation. Native tests establish particular correspondence boundaries.

## Strong alternative and scientific position

A competent conventional implementation can use a transactional reservation
tree, signed attenuated contracts, receiver-local credentials and durable
idempotency. It can export the same kind of bound certificate and use the same
predicate checker. This paper does not disqualify that construction for using
the proposed interface. Capability attenuation, escrow allocation, proof-carrying
code and interface refinement all precede this work.

The concrete new implementation capability in this branch is dynamic tree
formation and provider selection with portable native execution binding. The
previous fixed KW1 and three-owner fixtures did not supply that reusable API.
The hypothesis worth evaluating is whether this interface makes changing work
relationships substantially easier without weakening safety or useful progress.
Local correctness and a small predicate demonstration do not establish that
advantage, a new foundational theorem or an autonomous economy.

## Explicit limits

- One owner allocator per root; an untrusted owner can overissue if its signing
  service or protected state violates the protocol. Signatures cannot prevent it.
- Previously qualified, explicitly permitted receiver/holder keys. Discovery
  does not authorize a new reader, and offline permits do not provide instant
  global revocation of allocator qualification. Native capability revocation
  remains live at the receiver.
- Finite work trees: depth <=32, <=64 children per slot, <=4096 slots per root.
  Currency units and timestamps are at most 2^53-1; envelopes <=64 KiB.
- Monotone declarations do not establish complete data provenance, worker
  isolation, arbitrary error/log/payment-channel mediation or semantic goal
  refinement. Those remain explicit recovery/host integration requirements.
- Completion and recovery recheck contract expiry. Work can remain stranded
  after expiry; the demonstrated recovery cut completes while the contract is
  live. A future earned-output policy must define that lifetime explicitly.
- No automatic post-seal replacement or reclaim. No liveness guarantee under
  network partition, unavailable rails, withheld outputs or dishonest verifiers.
- The executable example uses one administrator, local tool implementations and
  fixture money. Independent interoperability and useful-work economics remain
  unmeasured.
