# Authenticated caller delivery

The negotiated protocol is `chio.caller-delivery.v1`. A reservation is preparation,
not permission to execute. The trusted executor, not the untrusted agent, handles
start authorization, durable claiming and raw delivery evidence.

## Contract

1. `POST /v1/evaluate` reserves the original operation. Success says
   `status: "reserved"`, `execution_authorized: false`, and `start_required: true`.
   Its nonce and receipt cannot authorize an external effect.
2. The trusted control client calls `POST /v1/caller/start` with the protocol,
   original `execution_nonce` and `arguments`. Optional `credentials` presents
   the original DPoP proof, governed approval token, or threshold approval set
   for live revalidation. Start commits the original hold, nonce and required
   custody before returning `status: "dispatch_committed"` and `authorization`.
3. The executor verifies the signed authorization against an independently
   configured kernel key, executor identity and epoch, and expected invocation.
   It claims the original operation in `SqliteCallerExecutionLedger` before its
   effect callback. All processes serving that executor must share the ledger.
4. The trusted client sends the same authorization and signed executor report to
   `POST /v1/caller/report`. The kernel authenticates their exact original binding
   and enters original finalization, not admission. Only the kernel-evaluated
   output and signed receipt may cross back to the agent.

Both control routes require the configured sidecar control bearer token. Never
give that token, the executor signing key, or the raw report to an untrusted
agent. Executor-authenticated evidence is not provider-attested evidence.

The Rust embedding host selects `CallerExecutorIdentityV1` before admission with
`ChioKernel::set_caller_executor` or `ProtectProxy::with_caller_executor`.
The latter requires durable admission and budget stores. Requests cannot select
that key. The original authority profile records the pin, including its epoch;
changing current configuration cannot adopt an existing operation.

The Python SDK exposes `evaluate_tool_call_mediated`,
`start_mediated_execution`, and `report_mediated_execution`. Start and report are
transport helpers, not signature verifiers or executor implementations. They do
not execute callbacks, implement a process-local claim map, or automatically
retry a lost start reply. Use a trusted executor with the durable Rust ledger.

## Failure and custody boundaries

- An unused expired reservation is compensatable. A committed dispatch is not.
- An explicit lost-start recovery returns the same signed authorization and
  interval. It never renews permission. A new executor claim requires a live
  half-open interval; authentication of expired evidence permits only accounting.
- A duplicate executor delivery returns the exact retained report, or an unknown
  outcome if the effect may have happened without a durable report. It never
  executes the callback again. No blind retries of uncertain effects are allowed.
- After kernel restart a committed authenticated caller enters
  `awaiting_caller_report`, retaining capture and custody. A valid late report can
  finish that original operation. Existing terminal unknown-outcome records stay
  immutable and are not reopened or relabeled.
- Duplicate reports replay the original completion receipt. Modified or
  conflicting reports, substituted attempts, changed pins, missing physical
  custody and current revocation fail closed. Completion does not mint a new
  execution nonce.
- DPoP and governed approval require their explicitly activated operation-owned
  authorities. Start re-presents credentials and validates their existing claims;
  report recovery never reconstructs signed credentials from a DTO. The return
  snapshot and its physical histories must retain the original dispatch episode.
- Native release-owner and declassification custody are included in M3's completed
  local acceptance, not deferred. The trusted native host must supply the original
  security context
  through the Rust reservation/start entrypoints; public request data cannot
  select that identity. The native caller frame binds actual native capture and
  release custody. A report cannot manufacture an ordinary `NativeReleaseOwner`.
  Supplemental authorization remains a fail-closed profile boundary.
- Combining threshold approval with credit-facility exposure is not qualified
  by the read-only caller-resume path and fails closed. Ordinary monetary
  exposure and cumulative approval use their original retained budget state;
  no fresh authorization event may substitute for an approved caller hold.

Native caller qualification requires both original native capture and the pinned
executor, using the distinct `native-caller-report:v1:` transport binding. The
private v5 return frame retains the original native ledger, security identity,
secret-free release-request commitment and execution deadline. That frame commits
atomically with native budget/credential capture. Private signed report evidence
is retained with the raw return, not in public receipt metadata. Recovery must
reauthenticate it against the original nonce issuer, executor pin and physical
capture before constructing a distinct release-only owner. The common guarded
output join, current revocation/containment checks and fenced release checkpoint
remain mandatory. This does not change M2's fail-closed rule for missing ordinary
native live owners or qualify deferred process confinement.

For native Rust embeddings, reservation without an execution nonce returns only
the nonce preflight response. The trusted host then refreshes the flow-state
generation from its selected native authority and reserves using that nonce and
current host context. Preflight, reservation and start remain distinct. The
kernel does not silently promote a historical preflight context into current
host authority. Start also rechecks the original classified input join instead
of creating another join after budget reservation.

## Reproducible local acceptance

Run `bash scripts/check-authenticated-caller-delivery.sh` on a Linux host with
the repository's Rust toolchain and SQLite test prerequisites. The gate requires
61 exact tests: 33 caller lifecycle tests, nine executor-ledger tests and 19 native
caller tests. Missing, ignored or renamed cases fail the inventory check. The
native cases also remain in the composed flow gate; its restart subset retains
the ordinary M2 cases alongside the new caller process-loss cases.

The native matrix covers local, egress and declassification profiles, both alone
and composed with runtime, DPoP and approval custody. It uses original retained
authority rows, a separately provisioned executor ledger, signed evidence and
independently counted effects. Process tests abort the child without running Rust
destructors and reopen the same authority under a new serving-owner fence.

| Failure boundary | Required recovery behavior |
| --- | --- |
| Before atomic capture | No start authorization or effect; reversible custody can be compensated |
| Captured, before executor claim | Recover only the original authorization and validity interval |
| Executor claimed, no durable report | Retain capture and an unknown outcome; never repeat the effect |
| Signed report durable, reply lost | Replay exact retained evidence and finalize the original operation |
| Raw return, output join or release checkpoint durable | Reuse original history, without a second join, declassification use or external effect |

Output recovery still checks current classification and inherited restrictions.
A persisted output join cannot authorize a changed classified label. The physical
writer also checks the complete current source inside its replay transaction,
closing the interval between the kernel's observation and acknowledgement.
Tests assert capture, original operation identity, release evidence and absence
of duplicate effects, not merely that an API returned an error.

This gate is local functional and process-loss acceptance. It does not qualify
process confinement, power loss, distributed authority or public activation.
See [launch status](launch-status.md) for the tested candidate and broader gates.

## Compatibility and provisioning

This is an explicit break with reserve/execute/unsigned-report integrations.
The SDK rejects old `status: "authorized"` reservation responses and its old
`reconcile_mediated_authorization` method fails before sending HTTP. A configured
authenticated kernel rejects unsigned reconciliation. An unconfigured legacy
embedding remains available for historical compatibility tests; its reservation
is not an executable authorization. Do not use it for external effects.

Signed wire artifacts have separate schemas:
`chio.caller-dispatch-authorization.v1` and `chio.caller-delivery-report.v1`.
Signatures cover RFC 8785 canonical bodies including the schema domain. Canonical
authorization and report encodings are limited to 32 KiB and 1 MiB respectively.
Signatures, exact bindings, semantic bounds and independently selected keys still
require runtime verification; generated schema types alone confer no authority.

Admission schema v34 adds the nonterminal waiting state without rewriting old
operation or commit bytes. Its offline upgrade verifies the predecessor catalog
and custody before rebuilding the constrained parent table. Old authority
profiles and caller frames do not gain a new executor pin, credential history or
start authority through migration. Ambiguous legacy external effects require
operator reconciliation, not backfilling or recreating reservations.

The executor ledger must be explicitly provisioned in a private directory or
opened as existing history. A missing ledger is an error, never a request to
create a replacement. Capacity is a bounded 1 to 64 retained operations, with no
eviction or implicit rotation. Capacity exhaustion fails closed. Privileged file
rollback, independent provisioned ledgers for one identity, power-loss behavior,
long-running retention and production deployment are not qualified by the local
process-loss tests. No populated operator database is migrated by this work.
