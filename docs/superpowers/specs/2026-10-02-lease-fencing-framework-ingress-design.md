# Lease-fenced writes and framework ingress

Approved continuation of the October 2 issuer/approval batch. Source base:
`14ce46a3edbf75c27162d2c13c1dce07b919b070`. Scope: AC4 and CA3 from the October 1
accounting/clock and campaign reviews. This is source implementation and local
qualification, with publication already authorized; no deployment is implied.

## AC4: current ownership at the committing transaction

Run registration is an insert-only pending record. It cannot overwrite an
existing run, write steps, select a terminal status, or create lease authority.
Protected run, step and evidence-artifact updates require an explicit
`RuntimeRunLease`. Recovery decisions consult artifact presence, so those writes
must share the progress fence. The store
checks run, owner, lease identity and fencing token against the persisted active
lease, including its exclusive expiry, within an IMMEDIATE transaction. It reads
the store-owned clock after acquiring that transaction. Caller timestamps and
copied expiry fields cannot keep expired authority alive.

Successful progress advances the persisted heartbeat without extending expiry,
so subsequent clock regression refuses. A refusal or failed SQL write rolls back
the entire mutation, including that time observation. Step `lease_id` continues
to identify its destructive-operation evidence; it is not the run-owner fence.
The runtime wrapper and CLI must use the same protected APIs. CLI commands acquire
a current lease and commit their run/step/evidence progress atomically. They do not select
or borrow another owner's current token. Explicit fenced release ends successful
one-shot writer ownership. Existing scheduler acquisition/heartbeat semantics
remain separate trusted orchestration APIs.

Alternatives rejected: a preflight lease check outside the transaction has a
takeover race; retaining an unfenced compatibility writer leaves the defect open;
copying the current database token in a caller launders stale ownership.

## CA3: inventory ingress and validate original bodies

Keep direct serde reader classification and add request extractors, transport
response decoding, alternate formats and shared-reader consumers. Responses must
not be counted as request ingress. Dispositions identify actual owners, body
bounds and parsing contracts; moving a decoder to a helper cannot erase its
callers. Census observations are not vulnerability or completion counts.

For control-plane signed and authoritative routes, bound and check original
request bytes before typed extraction. Reuse canonical signed readers and the
duplicate-aware unsigned document reader as appropriate. Preserve ordinary
decimal-bearing unsigned input. Retain existing handler authentication, signature
verification and semantic validation, and exercise the actual router method/path
composition. Standard request limits become explicit, with existing deliberate
larger receipt/evidence limits preserved and tested. Rejected input must not
mutate durable or authority state.

## Acceptance

Retain behavioral RED and terminal GREEN evidence, with compilation errors,
cancelled campaigns and unavailable tests recorded separately. Exercise stale
owners, exact expiry, owned-clock failure/regression, reopen, concurrent takeover
and SQL rollback. Exercise real HTTP routes with honest bodies, top-level/nested
duplicates, numeric and content-type rejection, oversized bodies and invalid
signatures. Source gates must not grow unreviewed debt, lint suppressions, ignored
tests or timeouts. One independent review covers the integrated source batch.

Non-goals: a replacement Rust parser/type resolver, whole-database rollback
defense, a new distributed scheduler, full workspace/hosted qualification or
operator activation. Newly inventoried surfaces require explicit dispositions;
their appearance does not establish an exploit or automatically close remaining
TCB reader work.
