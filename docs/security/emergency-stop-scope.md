# Emergency stop scope

This document states what a kernel stop covers, where it lives, and what it
does not reach. The design is KSPEC-08
(`docs/superpowers/specs/2026-10-04-durable-stop-epoch-design.md`). This page
describes the code as it is; the claim limit at the end is the boundary for
any public statement.

## Two stops

A kernel reads one `StopHeads` value (`chio_kernel::stop`). It reports a stop
when either of two independent sources holds one.

| Source | Set by | Survives restart | Cleared by |
|---|---|---|---|
| Host latch | trusted host code, through `ChioKernel::emergency_stop` | no | `ChioKernel::emergency_resume`, or a new process |
| Kernel-scope stop chain | an operator, through `StopControl::stop` | yes, when a durable admission store is attached | `StopControl::resume`, naming the stopped head |

The host latch is for component failure, such as the native broker authority
service failing. It needs no operator to clear, and an operator resume never
clears it.

## Process scope

Every kernel a host constructs binds the same `StopHeads`:

- `DurableAdmissionRuntime` owns one `StopControl` and binds it to each kernel
  it attaches, before startup reconciliation runs;
- the hosted MCP edge (`chio mcp serve-http`) binds one `StopControl` to every
  session kernel, whether or not durable admission is enabled;
- the api-protect sidecar binds one `StopControl` to its HTTP authority kernel
  and its mediation kernel, durable over the sidecar's admission authority when
  a receipt database is configured;
- trust control holds one `StopControl`, durable on its joint admission
  authority when one is configured; with a cognition-market purchase executor
  that control is the executor's, bound to every purchase kernel it builds;
- a process host binds the one kernel it serves.

A stop through any kernel or control surface of a host therefore reaches every
kernel of that host. It does not reach another process or a remote kernel.

## Durability

With a local durable admission store, an operator stop is a
`chio.stop-epoch.v1` record in `admission_operation_stop_epochs` (admission
schema v1). Records are append-only, hash-chained per scope, covered by the
global authority commit chain and anchored before the call returns. Reason text
is kept in a separate note table; the record holds only its salted commitment.

At open, the runtime loads and verifies the chain before any kernel attaches,
so a host restarted during a stop comes up stopped and denies from its first
request. A chain that cannot be loaded or verified installs a stopped,
`not_ready` view, and resume refuses. If the durable append of a stop fails,
the stop still holds in this process and the result reports
`stop_not_durable` with durability `process_only`.

Without a durable store (development profiles and remote admission profiles),
a stop reports durability `process_local` and ends with the process.

A remote-admission edge keeps a process-local stop of its own. A durable stop
at the trust-control node that serves its admission authority reaches it too:
while that stop holds, the authority refuses to begin admissions with the
`stopped` code, which the edge reports as an unavailable store, so the edge
begins no new admission until resume.

## Ordering and time

A stop never waits on the clock. The host latch is published before authority
time is read, so a failed time read leaves the stop engaged; the test
`emergency_stop_is_published_before_authority_time_is_read` checks every
authority-time read observes the published latch. A durable stop records
`decided_at: unavailable` when authority time cannot be observed. A resume
requires observed authority time and the exact stopped head (`expected_epoch`).

## Enforcement

Every existing in-kernel stop check (evaluation entry, async and nested
evaluation, dispatch, native capture, native egress, caller and native output
release, approval collection, finding pool) reads the shared heads. A stop
denial is a signed deny receipt whose identity disposition is `reusable` and
whose `retryable_after_resume` is `true`: the same request id may be retried
after resume.

The api-protect sidecar's capability mint routes (`/v1/capabilities/mint` and
`/v1/capabilities`) sign outside the kernel; they read the same heads and refuse
with HTTP 503 and `kernel_stopped` while stopped. Its proxy path answers a
request the stopped kernel refuses the same way, after the kernel signs the
deny receipt.

The recovery sweep, at startup and on each periodic batch, leaves a returned
(`Finalizing`) operation untouched while a stop is in force: its output stays
in durable custody, no recovery deferral is recorded, and a sweep or a replay
of the same request after resume releases it. A host restarted during a stop
with such work therefore comes up `ready_stopped`. While a stop holds, the
status on every control surface reports these operations as
`withheld_operations`.

## Operator reach

| Surface | Credential | Recorded authorizer |
|---|---|---|
| `POST /admin/emergency-stop`, `POST /admin/emergency-resume`, `GET /admin/emergency-status` on `chio mcp serve-http` | admin bearer token, compared in constant time | `SharedCredential` for `hosted-mcp:admin-token` |
| `POST /chio/emergency-stop`, `POST /chio/emergency-resume`, `GET /chio/emergency-status` on the api-protect sidecar | sidecar control token, compared in constant time | `SharedCredential` for `api-protect:sidecar-control-token` |
| `POST /v1/admin/emergency-stop`, `POST /v1/admin/emergency-resume`, `GET /v1/admin/emergency-status` on trust control | credential with `admin:emergency` and deployment tenant authority, secret digest matched against `--access-config` | `SharedCredential` for `trust-control:<credential id>` |
| process-host control socket (`control.sock` in the host state directory) | peer uid equal to the host's, plus the per-start `control.token` | `SharedCredential` for `process-host:control-socket` |
| `chio process stop`, `resume`, `stop-status` | uses the control socket when the host serves; otherwise takes the host lease and appends offline | as above, or `process-host:offline-cli` |

Records name a shared credential, not a principal. No principal is known
until the operator identity prerequisite (KSPEC-08 S28) lands.

## Claim limit

Durable, operator-reachable and restart-safe for the kernel scope of a local
durable admission store, enforced early at the in-kernel check sites. Not yet
in force:

- tier-2 predicates inside the dispatch-commit and release transactions;
- the stop-intent journal and the signing obligation, so a stop whose commit
  fails holds only in the process;
- stop checks on issuance paths outside the kernel other than the api-protect
  sidecar's capability mint routes, which refuse while stopped;
- tenant and recovery scopes, restrict and relax, and two-person resume.
