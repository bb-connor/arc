# Dynamic delegation with durable allocations

## Intent and scientific question

The user approved the following direction: people delegate useful work to a
changing network of independently owned agents while retaining enforceable
control over data, actions and financial exposure. They explicitly requested
design, implementation, review and a paper update in one continuous execution.
This supersedes the earlier manuscript freeze as an editing instruction; it
does not turn unestablished claims into established results.

The bottleneck is repeated bespoke reasoning at each new work relationship.
The proposed mechanism is an executable contract for **allocating, subdividing
and binding work**, with ordinary receiver-local authorization at dispatch.
The consequence sought is runtime formation of work trees using one reusable
enforcement path. Independent utility and integration advantage remain research
questions. PR #1172 recovery semantics remain an assumed shipped foundation;
this implementation must report its actual native coverage separately.

## Approaches and decision

1. Extend the fixed KW1 scenario. Rejected: more trajectories do not change the
   expressiveness or answer the new question.
2. Accept arbitrary provider promises or general program proofs. Rejected for
   this implementation: promises do not establish enforcement, and unrestricted
   semantic implication does not give a small practical checker.
3. Implement a restricted, durable delegation algebra plus a native guard.
   Selected: finite effect/reader sets, exact acceptance contracts, additive
   resource allocation and immutable dispatch bindings have concrete semantics.

This is architectural work. Execute inline with one fresh whole-change review.
No outside outreach, publication, deployment or real funds are authorized.

## Contract and authority

An owner creates a root slot for an authenticated holder. Each slot contains an
identifier, holder public key, effect set (exact server/tool pairs), permitted
reader identifiers, integer budget in one currency, absolute expiry, remaining
delegation depth and a deterministic acceptance predicate. A slot is either a
container of children or a dispatchable leaf. Splitting permanently commits the
child's entire budget from its parent; unused capacity is not automatically
reclaimed. Child effects and readers are subsets, expiry cannot increase and
depth must decrease. A child may choose a different acceptance predicate: its
success is not a proof of the parent's result. The parent's acceptance contract
is immutable. A separate leaf can perform final assembly/checking.

Holders sign subdivision and selection requests. Provider offers are signed by
the receiving kernel's key and bind the exact slot, arguments digest, effect,
price and validity interval. A locally configured, explicit receiver allowlist
qualifies providers; discovery alone grants no authority. Initial enrollment
and application adapters are trusted setup costs, never counted as zero.
Adding a provider to a discovery response requires no change to contract code;
it still requires qualification by the owner before use.

Provider selection binds the offer to an ordinary receiver-issued capability
digest and request ID. The native capability still supplies authority. The
offer and allocation are evidence, never an alternate CA root. A holder cannot
select a provider for another holder's slot. Signed bodies use domain-separated
RFC 8785 canonical JSON and strict Ed25519 verification.

## Durable state and transitions

`chio-workflow::delegation` owns a SQLite allocator, scoped to one resource
owner. It is a reusable experimental API, not a new settlement rail. The
allocator is part of the trusted owner boundary; database rollback, replicated
consensus and multi-region availability are outside this profile.

- Create: trusted owner API creates an immutable root.
- Subdivide: authenticated holder adds an immutable child under an open slot.
  Atomic allocation rejects sibling overcommit and integer overflow. A selected
  slot cannot be subdivided; a container cannot be selected for execution.
- Select: authenticated holder binds a qualified signed offer and exact native
  request/capability. Before dispatch the holder may select a replacement.
- Dispatch: the guard atomically records the selected binding before execution.
  A different request, capability, provider, arguments or offer is rejected.
  Revalidation of the same binding is idempotent. An uncertain operation retains
  its reservation and cannot be replaced or subdivided.
- Check result: the guard checks the immutable predicate on the exact released
  JSON value. Acceptance is separate from financial settlement and does not
  manufacture proof of general usefulness.

There is deliberately no reset, timeout refund, untrusted absence report or
release of dispatched allocations. Existing native durable admission owns
operation replay and recovery. The allocator conservatively retains capacity
even when a later native check prevents dispatch. This is a liveness cost.

SQLite immediate transactions serialize sibling allocation and selection versus
dispatch. Separate connections/processes use the same owner database. Every
mutation validates the trusted clock argument and current expiry. Public methods
accept explicit time for deterministic use; the native adapter obtains wall time.
Store corruption and lock failure fail closed.

## Restricted acceptance language

Support `All` of 1-16 clauses. A clause is exact JSON equality at a valid JSON
pointer or an inclusive signed-integer range. Values are canonicalizable, paths
are bounded and empty/malformed contracts reject at load. This checks the agreed
predicate, not natural-language truth or hidden effects. No arbitrary code or
network call executes inside the checker. Caller-selected replacement offers
cannot change the slot predicate. Native errors and streaming output do not
satisfy this JSON-return profile.

## Native integration

Add an opt-in `DelegatedWorkGuard` to `chio-kernel`, using the shared allocator.
Requests carry `{slot_id, payload}`. Offer hashes bind the complete arguments.
The guard pins its receiving key, checks the selected native capability digest,
subject, request ID, exact server/tool, expiry and bounded monetary grants. It
requires one exact invoke grant, max_invocations=1 and both cost limits no larger
than the offer price, in the slot currency. Native capability verification,
durable operation capture, payment and receipt signing remain in their existing
owners. Require durable request retention in the example/integration setup.
Output checks run after transforms. Pricing remains native; this guard does not
opt into zero-charge rejection or claim paid settlement from an allocation.

The receiving host/tool confinement and declared reader/effect completeness are
explicit assumptions. The guard controls this kernel invocation and result;
it does not magically confine arbitrary host I/O or certify remote behavior.
Tests use separate receiver keys and stores on one administrator's host.

## Argument and comparison

For every allocation tree, local subset/depth checks imply descendant effects,
readers and lifetime remain within each ancestor. Atomic sibling allocation and
the prohibition on executing containers imply the sum of leaf ceilings is at
most the root budget. Immutable dispatch bindings preserve earlier obligations
when new children or providers appear. These are conditional invariants of the
restricted protocol, not a new general composition theorem.

The native result to demonstrate is a provider chosen after root creation,
recursive subdivision by a different holder, a pre-dispatch replacement,
independent sibling progress after an unresolved dispatch, rejection of an
unauthorized result and restart-preserved identities. A conventional reusable
allocator can implement these rules too. Do not claim superiority by forbidding
it the same interface or state. The implementation closes a concrete product
gap; novelty and measured advantage are separate judgments.

Primary intellectual antecedents include Necula's proof-carrying code (1997),
de Alfaro and Henzinger's Interface Automata (2001), capability attenuation,
escrow allocation and the existing Chio recovery research. This is an applied
combination with an explicit live binding, not a claim to invent contracts,
local checking, resource conservation or safe substitution.

## Deliverables and acceptance

1. Reusable Rust allocator/checker, documented trust boundary and meaningful
   concurrency, signature, tampering, expiry, overflow and restart tests.
2. Opt-in native guard and a runnable example that forms a tree dynamically;
   native integration verifies actual dispatch/output behavior and receipts.
3. Short protocol/argument/counterdesign report with retained failing and passing
   evidence. No large synthetic campaign or new independent trial required.
4. Rewrite the manuscript around the delegation problem, mechanism and exact
   contribution; preserve historical funding comparisons and open publication
   gates. Build and inspect the PDF. Source inventories distinguish historical
   evidence from newly qualified source.
5. One fresh review, one correction pass, focused final tests, format and clippy.
   No global release qualification is inferred.

Global constraints: fail closed; no unsafe Rust; no new external dependencies;
reuse workspace rusqlite; signed payloads use RFC 8785; no em dashes; no
unqualified breakthrough claim; retain all meaningful failed evidence.
