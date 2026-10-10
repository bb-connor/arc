# Threshold approval collection

`ThresholdApprovalCollector` is the canonical collection facade. It validates
signed artifacts and current authenticated request context before using
`ThresholdApprovalCollectorStore` for atomic persistence. The SQLite and
in-memory stores are persistence ports, not authorization interfaces.

The collector does not grant execution authority. The kernel independently checks
capability admission, current policy, proposal bindings, token signatures and
expiry, then reserves the verified approval set against replay.

## Execution verification and cryptographic policy

Ordinary tool approvals and governed active-response approvals use the same pure
threshold verifier. The kernel resolves the current route's policy requirement
once and passes that resolution to the verifier; it does not repeat a mutable
policy lookup while assembling replay evidence. Current capability admission and
authenticated active-response submitter separation remain caller obligations.

`ThresholdApprovalVerificationInput::allowed_signing_algorithms` is a trusted
policy input, never an agent-selected negotiation. It replaces the former
`allowed_token_algorithms` field and applies to both the policy authority's
proposal and every approver's vote. Callers constructing this public input must
rename the field and supply algorithms permitted for all of these envelopes.

| Kernel floor | Permitted proposal and vote algorithms |
| --- | --- |
| `AllowClassical` | Ed25519, P-256, P-384 |
| `AllowHybrid` | The classical algorithms above and hybrid classical plus ML-DSA-65 |
| `PqRequired` | Hybrid only |

For every envelope, algorithm metadata must match both its typed public key and
signature. Absent metadata retains the legacy Ed25519 interpretation, not an
algorithm inferred from an arbitrary key. Valid signatures cannot override a
forbidden algorithm or contradictory metadata. A hybrid capability alone does
not permit classical proposals or votes under `PqRequired`.

Both entrypoints preserve the original signed artifacts, canonical approval-set
hash and replay membership. Replay token IDs must fit the existing 512-byte,
non-NUL persistence contract before a set is returned as verified. A replay
projection's constructor is not a substitute for current-policy verification.

The local `threshold_crypto_floor` suite exercises real Ed25519 and hybrid
signatures through the production validators. It does not qualify the whole PQ
runtime.

## Boot-gated proposal issuance

`ChioKernel::with_hybrid_signing_backend` installs the proposal and ordinary receipt signer
only after the existing self-quote gate succeeds. The returned boxed handle and
kernel share one immutable backend. Dropping the handle does not remove the
kernel's signer. Rejected quotes, unavailable PQ support and missing required
seed material leave the previous signer and floor unchanged. Operators must
handle that error; it is not acceptance of the requested new configuration.
`HybridSigningConfig` debug output redacts seed material.

Configure signing before serving cumulative-approval requests. Setting the crypto
floor alone does not install a signer. A cumulative profile with an incompatible
signer denies before reserving budget, including requests that might otherwise
fall below the cumulative threshold. Ed25519 proposals retain the legacy absent
algorithm tag and byte-identical canonical representation. Hybrid proposals bind
the boot-verified backend's full public key and declare `Hybrid` explicitly.

The kernel includes its installed proposal key only in its ordinary threshold
proposal authority set. This does not make that key a general capability issuer
or change an explicitly configured active-response authority set. Those trust
relationships remain operator-owned configuration.

For a retained approval-required operation, durable admission rechecks the
original proposal against current authority, floor, membership, request bindings
and time before resuming budget acquisition or cleanup. The policy callback runs
outside the mutation sequencer; later mutations still require the exact operation
version and store fence. A rejected retry leaves the original proposal and
pending hold intact. It neither re-signs the proposal nor asserts that resources
were released. A real key or membership change may require a new operation and
the pending-operation expiry or cancellation workflow. This revalidation does not
implement cancellation or replace release evidence.

After reconstruction, configure the same still-trusted signer to resume the
original proposal. Rotating to another key does not rewrite retained artifacts or
implicitly preserve trust in the old key. Collector context must still come from
the authenticated request lifecycle, not from the installed signer or proposal.

The `threshold_issuance` suite checks production cumulative admission, original
artifact retention, kernel reconstruction over retained fixture state, and one
dispatch across an approved retry. It is not physical process-crash or SQLite
restart qualification. Ordinary receipts now use the same boot-selected authority,
including the signing queue and its fallback. See [kernel signing authority](kernel-signing-authority.md)
for identity, canonical encoding, recovery and remaining enterprise-custody
boundaries. This still does not qualify a complete `PqRequired` runtime.

## Trusted context

API-protect requires a configured control token and bearer credentials on all
approval routes, including loopback requests. This operator transport gate does
not establish the original request's subject, submitter or current policy.
See [the sidecar control authority contract](sidecar-control-authority.md).

Construct the collector with a `ThresholdApprovalContextResolver`. For each
operation, this resolver loads the original authenticated request by request ID
and rechecks its current authority. Its output is a validated
`ThresholdApprovalProposalCreationContext` containing:

- The request ID, server and tool route.
- The current policy-owned threshold and resolved approver directory.
- The authenticated subject, governed intent hash and exact capability digest.
- The capability and governed-operation expiries.
- The authenticated submitter and configured separation-of-duties rule.

This context must come from the trusted admission/request lifecycle. A signed
proposal, retained collector record or HTTP body cannot supply that authority.
Constructing the context type validates its structure; it does not authenticate
its source. Resolver implementations must check revocation and current policy,
not serve an indefinitely cached snapshot. Missing or unavailable context denies
the operation without changing collector state. Request IDs that resolve to
multiple subjects or admitted operations must reject as ambiguous, not select
whichever record was most recently written.

The create HTTP body contains only `proposal`. Former caller-controlled
`requirement`, `submitter` and `require_submitter_separation` fields are rejected
as unknown fields. `create_proposal` takes the signed proposal and trusted current
time. `get_proposal` also requires trusted current time so a restored future
transition cannot be accepted.

`ProtectProxy::with_threshold_approval_context_resolver` accepts an explicitly
configured trusted source. Without it, threshold collector endpoints remain
unavailable. The default sidecar does not yet supply a production request-context
resolver; its mediated evaluation endpoint continues to reject threshold input
because no threshold policy resolver is configured there. A configured collection
callback alone is not end-to-end runtime qualification.

### Kernel-owned original request resolver

Rust compositions can use `Arc<ChioKernel>::create_threshold_approval_collector`
with a collector store and an operator-owned `ThresholdApprovalCollectionPolicy`.
The policy binds explicit submitter-separation rules to the active kernel policy
hash. It is not deserializable collector input. Complete durable startup
reconciliation before constructing the collector.

The kernel resolver currently supports retained cumulative tool admissions in
`ApprovalRequired`. It selects a unique request ID across all admission namespaces,
kinds and states, including legacy operations without retained material. It
revalidates the full signed capability and ancestry, current revocation and
delegation views, subject binding, matching grants, frozen post-return plan,
governed intent, route, proposal and current threshold policy. A final fenced
read detects operation or source changes during authority resolution. Neither
collection nor delivery reserves approval evidence or invokes the tool.

The submitter is the original capability-bound agent principal, with DPoP checked
at original admission when required by its grants. This is not an assertion about
a separate human submitter or physical-person identity. Separation rules come
from trusted Rust composition, not from the proposal subject or an HTTP field.

`threshold_kernel_lifecycle` exercises the real kernel, SQLite authority and
collector stores through reopen, vote collection, delivery, approved execution,
lost-response retry and another reopen. Execution returns the same signed receipt
without invoking the tool again. Approval resumption obtains the current serving
owner's fenced mutation authority; the retained hold's historical credentials
remain audit evidence, not authority to mutate after restart.

This does not enable the sidecar or implement an original-request source for
governed active-response approvals. The sidecar's execution-nonce configuration
still requires qualified atomic durable composition. Process-crash injection,
durable session recovery, pending-operation cancellation and hosted qualification
remain separate requirements.

## Retained records and migration

Session-scoped continuation is described separately below. It does not reconstruct
collector authority from a retained request digest.

### Retained original request material

Cumulative tool admission now retains the original signed capability, exact
request data, matching-grant indices and frozen post-return steps atomically with
the operation's begin commit. The operation's immutable request and capability
hashes bind this material. The begin commit's participant digest commits its
canonical bytes independently of later operation transitions.

This is private persistence, not authenticated collector registration. Capture
follows capability, revocation, subject, route and applicable DPoP prechecks, but
precedes the remaining governed-input, guard and budget decisions. A prepared or
denied operation is not eligible for collection merely because its original
material was retained. The collector still requires an authenticated resolver;
the default sidecar remains disabled without one.

`AdmissionOperationStore::load_retained_tool_request` returns the operation and
its material in one current-owner-fenced, anchored, trusted-time-checked SQLite
snapshot. Decoding `RetainedToolAdmissionRequestV1` alone establishes neither
storage provenance nor current authorization. The kernel-owned resolver above uses
`load_unambiguous_retained_tool_request` to select at most two indexed matches,
reject ambiguity, and load the operation and its bound original in one snapshot.
Custom store implementations fail closed unless they implement this read port.

The artifact is bounded to 256 KiB. It omits DPoP proofs, execution nonces,
approval votes and proposals, supplemental credentials and declassification
grants. It is not serialized into public receipts or collector responses. Its
diagnostic representation does not reveal the retained capability or arguments.

SQLite admission schema v10 adds immutable retained-request storage without
rewriting existing operation commits. Schema v11 adds the bounded request-ID
lookup index without changing those bytes or commits. Legacy operations remain
readable, but missing originals cannot be synthesized by an exact retry. Such
cumulative retries deny, including legacy pending approvals. Migration does not silently
promote a proposal, receipt or collector snapshot into original request authority.

### Collector record migration

Approval-store schema revision 3 adds the authenticated request route to the
serialized collector record. Older records remain intact with no route binding.
Opening the database updates schema metadata but does not adopt those records as
authorized. Normal reads, voting and delivery deny unbound records. Drain and stop
older collectors before opening the shared database with the upgraded binary;
schema checks at startup do not fence an older process that already has it open.
Do not serve mixed collector versions against the same database.

An operator with an independently authenticated source of the original request
can call `bind_existing_proposal(proposal_id, now)`. Migration revalidates original
signatures, current policy, exact intent/capability bindings, approver eligibility
and separation rules. The store binds the route once using a version comparison
and atomic write. Tokens, state and the previous transition timestamp are not
rewritten. A successful migration increments the version once; repeating it is
read-only. Changed authority, corruption, concurrent changes and arithmetic
overflow reject without partially updating the store.

Do not infer missing context from retained proposal fields, reset terminal state,
reissue votes, or delete history to make a migration succeed. A changed policy or
unrecoverable authenticated request requires a new admitted operation. Schema
revision 3 is intentionally refused on startup by binaries that only support
revision 2. Coordinate binary rollback with the normal durable-store recovery
procedure; do not manually downgrade schema metadata.

## Retries and expiry

Creation retries compare immutable canonical registration material and return the
actual retained state. They do not reset collected votes, versions or timestamps.
An exact signed-vote retry returns its existing acknowledgement without recording
another vote or extending its lifetime. New votes after a terminal transition
reject. Before delivery, replacing an expired vote from the same eligible signer
remains supported with a new unique token ID and digest.

Delivery persists the terminal transition before returning original signed
artifacts. Its timestamp fixes the response membership. If the response is lost,
a retry returns the same proposal and token set, including across a SQLite reopen,
while every originally delivered token is still live. Once any of those tokens
expires, retry rejects even if a smaller remaining set would still meet quorum.
It never silently creates a different replay-reservation set.

The collector rechecks context on retries. A prior successful acknowledgement
does not override revocation, changed authority, proposal expiry or clock
regression. Historical record reads are distinct from authorization to deliver.

## Live session continuation

A cumulative threshold wait remains in flight in the originating session. Its
request lineage is not recorded as terminal merely because the pending response
uses the wire-level `Incomplete` outcome. The normalized session, blocking nested
flow and async nested-flow entrypoints all preserve this wait.

The kernel installs an opaque `PendingThresholdApproval` binding only from its
own persisted-proposal response. It binds the original proposal digest and a
domain-separated canonical digest of the full immutable tool operation. Votes
and approval evidence may be supplied on retry; capability, route, arguments,
intent, supplemental authorization, nonce and metadata cannot change. The retry
also retains the session anchor, agent, parent and progress token. Changed
authentication, cancellation and draining reject. A rejected binding leaves the
wait intact.

Claiming the pending binding is atomic with its comparison. The claim follows
initial admission's lifecycle, authentication and request-lock order, keeping
those authority snapshots stable until ownership commits and releasing all locks
before kernel evaluation. Concurrent retries cannot both resume the same session
wait. A successful claim only permits kernel
evaluation: current capability revocation, policy, proposal and vote checks and
operation-owned replay reservation still run before dispatch. A terminal response
completes the original lineage; terminal session retries remain rejected.

The continuation owner retains the exact host-bound intent beside those digests.
The CLI stdio response carries the signed pending proposal and accepts the original
request with its collected votes on retry. Live continuation does not supply a
collector context resolver or reconstruct a session after restart. The default
sidecar threshold collector still lacks its production request-context source.

The session test composition rejects configured execution-nonce profiles because
its store lacks an atomic nonce participant. These tests do not qualify
threshold-plus-nonce composition. Cancellation,
session shutdown and process restart do not by themselves prove release of a
pending cumulative hold. Operation-owned expiry, cancellation and recovery must
provide their own durable release evidence. No whole-process crash or dropped
async-future recovery claim is made by the live-session tests.

## API ownership

The unused collection methods on `ApprovalStore` have been removed. That trait
continues to own legacy human-approval and operation-owned replay reservation
contracts. The pure validated registration, vote and record projection types
remain at their existing Rust paths, but are not a second persistence facade.

Regression coverage lives in the kernel and SQLite
`threshold_collector_recovery` integration suites, kernel
`threshold_approval_records`, and HTTP `approvals_endpoints`. These local tests
are not proof of whole-database rollback resistance, hosted exact-head
qualification, native confinement or observed pilot behavior. The remaining
launch requirements are tracked in [the launch ledger](launch-plan.md).

## Compliance and product-truth review (October 1, 2026)

The [compliance and product-truth review](../reviews/2026-10-01-compliance-product-truth-review.md) re-verified at `122414b48e` the product defects behind the repository's compliance, security and supply-chain claims: 69 findings, 3 High. Findings recorded at that reviewed revision:

- **AP2, Medium.** Only `serve-http` builds `BoundToolInvocation` intents; unbound intents are still
  accepted with an approval, API protect signs a caller-supplied `parameter_hash`, and no evaluation
  path reads the API-protect approval store, so those approvals gate nothing.
- **AP3, Medium.** Operator-respond signs with the sidecar key and records no approver; any CA,
  authority or kernel key may sign an approval; `approve_above_currency`, `timeout_seconds`,
  `on_timeout` and `approve_when` are parsed but not enforced while the canonical example presents them.
- **KG4, Medium.** `RequireDualApproval` never matches, so grants carrying it always deny.


## Execution-bound ordinary approvals (October 2 implementation)

Session threshold proposals now bind a legacy tool intent at the trusted host
before the initial proposal is created. The binding includes the original
arguments, full capability digest, request and policy, and a canonical scope
digest containing both the owned session ID and optional authenticated tenant.
The existing continuation owner retains
that exact intent with the original wire-request digest. Retries may add signed
votes; they cannot change the wire request or cause the host to construct a new
approved intent. This applies to stdio and both nested-flow session entrypoints.
It preserves the existing live-session continuation contract; restart cannot
recreate missing original continuation authority from a proposal alone.
Fresh presentations of session-created artifacts must match the current owned
session and authenticated tenant scope, including the current request, policy,
capability and arguments. Raw tool entrypoints reject these artifacts without
owned session context. Binding does not grant authority or require approvers for
a call below its cumulative threshold. Required approvals still resolve their
explicit policy-owned roster before proposal creation or execution.

The AP2/AP3 implementation separates an ordinary approver roster from capability
issuers and receipt signers. Tool approvals require a `BoundToolInvocation` in
every kernel path, including callers outside HTTP. Its signed intent commits the
canonical arguments, complete capability, request ID, tenant and current policy.
The host builds that binding; clients cannot supply a trusted parameter digest.

API protect accepts full signed capabilities at submission, checks `requested_by`
against the capability subject, and retains the original request and a separately
signed approver token when the decision resolves. The evaluate route consumes
that retained decision through the existing operation-owned replay authority and
authenticated caller-execution protocol. An explicit deployment config pins the
roster, tenant, previously activated replay source and executor. See the
[API-protect contract](../../crates/products/chio-api-protect/README.md#execution-bound-approvals)
for the wire sequence and CLI configuration.

Approval-store schema revision 4 adds signed decision artifacts beside resolved
ordinary records. Existing records without an original intent and token stay
audit-only. Resolution is immutable. There is no separate per-token revocation
route; current capability/ancestor revocation and signer retirement withdraw
approval authority at fresh admission and dispatch. Expiry and current tenant and
policy bindings are checked again there. This is separate from threshold
collection, whose trusted roster and original-request resolver remain required.

Policy loading rejects ordinary `approve_above_currency`, `timeout_seconds`,
`on_timeout` and `approve_when` fields because this path cannot enforce them.
Nested threshold-collector timeouts retain their existing enforced behavior.
Unsupported dual-approval policy configuration is rejected; direct capabilities
carrying `RequireDualApproval` continue to deny. This batch does not add a second
dual-approval execution path.

AP2/AP3 have local source acceptance in the
[issuer and approval execution record](../reviews/2026-10-02-issuer-lifecycle-approval-authority-execution.md),
including actual API/MCP redemption, retained session scope and native credential
controls. The October 1 review remains a historical snapshot. Hermes execution
resume and the old Docker approval workflow remain unavailable; hosted, whole-process
crash and launch qualification remain separate.
