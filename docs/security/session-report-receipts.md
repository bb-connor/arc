# Session report receipts

Session transports must not manufacture receipts when evaluation fails. The
kernel owns the signing authority, policy identity, authenticated session binding
and configured receipt persistence contract.

## Two different outcomes

An incompatible approval shape is rejected by the kernel before it registers a
new request or claims an existing threshold continuation. The normalized,
blocking nested-flow and async nested-flow entrypoints use the same shape check
as the wire message. The signed denial names `session_authorization`; the stdio
error projects that signed guard. This rejects the submitted attempt without
completing or releasing the original pending operation.

An arbitrary evaluator error does not establish whether a tool executed. The
host calls `ChioKernel::record_session_tool_failure` with the original normalized
operation and session context. The returned receipt is a `trace_observation`,
with `detect_only`, `observed`, no decision and internal tool origin. Its
`verified` trust level verifies the signed observation, not successful execution
or absence of side effects. It cannot authorize spending or replay.

The stdio result remains `InternalError`, with a fixed message that the execution
outcome is unknown. Raw errors remain redacted diagnostics. Session summaries
count these separately as `evaluation_errors`, not policy denials.

## Signed binding and persistence

The internal `metadata.session_report` event uses `chio.session.report.v1` and
binds its kind, request ID, session ID, agent ID, current session anchor and
authentication epoch. Canonical SHA-256 commitments cover the complete original
normalized operation, context (including parent and progress bindings) and
capability. The receipt action retains and hashes the
original parameters. Its content hash commits to the canonical event, not an
invented tool output.

The report kind is either `authorization_conflict` or
`evaluation_failure_reported`. `execution_outcome` is `unknown`: neither report
claims to settle the original operation. The latter records a host report, not
independent proof that a particular internal exception occurred.

The factory is not a general-purpose signing API. Hosts cannot choose its
decision, semantics, policy identity, signer, tenant or financial metadata.
Tenant identity comes directly from one authenticated session snapshot. An
anonymous snapshot remains untagged even inside an unrelated ambient tenant
scope. Existing lineage must match that authentication epoch; a report cannot
retag an old request into a newly authenticated tenant. Caller metadata and
ambient guard evidence are not copied into authority
fields. Their presence in the original operation affects its digest only.

Both reports use the boot-selected receipt signer and enforce its cryptographic
floor. Signing and canonicalization failures propagate without substituting a
fresh key, placeholder policy identity or empty parameter object. Missing
required persistence, a dead writer or failed append prevents receipt return.
The existing explicitly ephemeral development profile remains ephemeral.

Successful recording uses the ordinary durable receipt store, local mirror and
runtime trace, but never seeds or invokes financial settlement. It does not
mutate admission state, consume approval authority, complete session lineage,
release a hold or authorize automatic execution retry. An append timeout can
remain ambiguous under the store's existing critical-write contract; no rollback
claim is made. If error reporting itself fails, stdio drops the response and
emits a redacted diagnostic rather than returning an unaudited substitute.

## Qualification boundary

Tests cover real stdio responses and SQLite reopen, authority and content
binding, boot cryptographic floors, explicit tenant isolation, failed signing and
persistence, unchanged pending/completed operation authority, all three session
entrypoints, settlement exclusion and durable tool-outcome recovery after a
post-execution signing failure. The exact inventories are pinned in
`chio-tee-fips.yml`.

These reports do not supply the collector's original authenticated request,
transport the pending proposal body, implement durable session recovery, or
compose execution nonces with durable admission. Native confinement, package
closure, full-workspace and hosted qualification, and the observed pilot remain
separate release gates. Automatic response remains unpromoted.
