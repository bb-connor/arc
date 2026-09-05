# Threshold approval collection

`ThresholdApprovalCollector` is the canonical collection facade. It validates
signed artifacts and current authenticated request context before using
`ThresholdApprovalCollectorStore` for atomic persistence. The SQLite and
in-memory stores are persistence ports, not authorization interfaces.

The collector does not grant execution authority. The kernel independently checks
capability admission, current policy, proposal bindings, token signatures and
expiry, then reserves the verified approval set against replay.

## Trusted context

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

## Retained records and migration

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
