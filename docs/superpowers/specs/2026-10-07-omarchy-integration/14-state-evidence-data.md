# State, evidence and durable data

Status: Proposed. Confidence: high in the ownership and uncertainty rules;
moderate in storage integration until the native prerequisites are delivered.
Dependencies: [controller](04-controller-architecture.md), [operator API](05-operator-protocol.md),
[native authority](06-authority-approvals.md), [host adapters](07-host-provider-adapters.md).

## One authority, several observations

The controller stores a recoverable projection of native state. It cannot turn
a local event, model statement, process exit or file hash into a signed execution
receipt. Native process, authorization, approval, resource, limit and recovery
owners retain their own authoritative records. UI state references those records
by stable opaque ID and, when available, validated digest. Receipt signature and
inclusion checks use the native verifier with the pinned trust root. An invalid,
missing or stale proof is shown as such; an inclusion proof establishes membership,
not that the receipt's effect succeeded.

Every task binds an immutable principal/profile/project enrollment revision,
source snapshot identity, authority/session/process IDs, resource generation,
host/provider tuple, tool inventory digest, governance mode, limit contract and
original deadline. Store their public identifiers and commitments, never guest
bearer credentials. A binding change creates an explicitly reviewed new task
after the original task is settled. It is never a recovery trick.

## Task state machine

The following states describe the task, independently of UI connectivity and
individual native approval states. `offline` and `stale` belong to the connection.

| State | Meaning | Permitted next states |
| --- | --- | --- |
| `preparing` | Durable task intent; enrollment and resource staging in progress | `ready`, `cancelling`, `failed`, `blocked_unknown` |
| `ready` | Bindings established, guest not yet admitted | `running`, `cancelling`, `failed`, `blocked_unknown` |
| `running` | Native admission and confined host execution available | `waiting_approval`, `recovering`, `cancelling`, `succeeded`, `failed`, `blocked_unknown` |
| `waiting_approval` | Exact native proposal pending; no implied grant | `running`, `recovering`, `cancelling`, `failed`, `blocked_unknown` |
| `recovering` | Original native operations are being reconciled | `ready`, `running`, `waiting_approval`, `cancelling`, `cancelled`, `succeeded`, `failed`, `blocked_unknown` |
| `blocked_unknown` | An effect or authority outcome cannot yet be established | `recovering`, `cancelling` |
| `cancelling` | Admission stop and worker teardown requested | `cancelled`, `blocked_unknown` |
| `cancelled` | Admissions stopped, guest absent, all dispatched outcomes accounted for | terminal |
| `succeeded` | Profile completion predicate satisfied with required evidence | terminal |
| `failed` | Known unsuccessful outcome, no unaccounted dispatch remains | terminal |

On controller restart, every nonterminal task becomes `recovering` in the same
durable transaction as the recovery event. Recovery does not itself relaunch a
guest. Original-operation inquiry may run without new work admission. A native
continuation requires explicit operator resume, original constraints and the
qualified continuation contract. States never jump out of a terminal task;
subsequent work has a new task ID and links its settled predecessor.

Process exit is an observation. `succeeded` for `project-v1` requires confined
worker exit, known native outcomes, successful declared fixed checks, a sealed
review artifact, and preserved source repository. A model's success text is not
the completion predicate. Failed checks produce a known `failed` task with its
useful artifact, not a green success badge. A task cancelled during a completed
effect reports that effect truthfully. When teardown succeeds but an effect is
unknown, retain `blocked_unknown` and show `guest_exited=true`; do not label the
whole task `cancelled`. Deadline exhaustion prevents fresh work even in recovery.

## Native operation ledger

Classify each referenced native operation as `not_dispatched`, `in_flight`,
`succeeded`, `failed`, `cancelled_before_dispatch`, or `unknown`. These names are
projection categories; adapters must map the actual native owner's richer states
and include original IDs. Only native evidence can move an uncertain dispatched
operation to a known outcome. A locally missing record is not proof of no dispatch.

Persist intent and stable native request identity before submitting. If native
reservation and local projection cannot be atomic, use an outbox whose replay
submits the identical native key and verifies the original result. The native
owner must support that contract. A non-idempotent native creation API blocks
the profile; a controller-side retry wrapper cannot repair it. Retry a read-only
outcome query with bounds; never manufacture another effect ID. Even a native
side-effect-free retry exemption remains disabled until separately qualified.

## Local storage layout and transactions

Proposed data root: `$XDG_STATE_HOME/chio-desktop` (default `~/.local/state/chio-desktop`).
Operator-owned directories are 0700 and files 0600. Proposed SQLite database
`controller.sqlite3` contains:

| Table | Required keys and contents | Retention rule |
| --- | --- | --- |
| `metadata` | schema version, journal epoch, last sequence, enrollment identity | Never reset silently |
| `tasks` | UUID, revision, state, immutable binding, completion evidence references | Unresolved tasks pinned |
| `mutations` | principal + idempotency key, canonical digest, task revision, native IDs, result reference | No eviction that permits replay as fresh |
| `outbox` | stable native intent ID, request commitment, disposition | Pinned until reconciled |
| `events` | epoch + sequence, task revision, bounded public projection | Bounded replay history |
| `enrollments` | operator-selected roots/profiles and immutable revisions | Referenced revisions retained |
| `artifacts` | sealed descriptor, byte bound, digest, native provenance and retention class | No live authority or arbitrary path |

Use an explicit single-writer controller lock, transactional revision comparisons,
SQLite WAL and `synchronous=FULL` on a qualified local filesystem. Check the
actual filesystem's durability with power-loss tests; an option name is not an
empirical guarantee. Task update, mutation reservation/result and event sequence
commit together where they belong to the same local transition. Protect database,
WAL, SHM, backups and exported diagnostic files equally. No network filesystem
support in the first profile. No database access from QML or the guest.

## Retention, deletion and quotas

Proposed defaults: 30 days for settled task display records, seven days for local
redacted diagnostics, 100 MiB rotating diagnostic total, 512 MiB controller data
budget, and the protocol's 1,024 task/4,096 mutation admission bounds. Native
receipt retention is independently governed and cannot be shortened by UI cleanup.
Artifacts and guest scratch have separate profile quotas from the resource spec.
The operator sees size and expiry before export.

Delete settled display content only after native reconciliation and retention
policy checks. Keep a bounded tombstone with the idempotency binding until the
entire enrollment epoch is explicitly retired and no callers can replay it.
When tombstones fill the mutation budget, refuse new mutations and require an
explicit settled-epoch archival procedure. Never discard a key and continue
accepting it as fresh in the same epoch. Task creation keys are enrollment-epoch
scoped; the enrolled principal's epoch is negotiated, never chosen by the caller. Each
mutation carries that exact `enrollment_epoch`; a retired epoch is permanently
refused. Only fully settled enrollments may roll over, existing connections are
closed, and re-enrollment requires explicit operator action.

At capacity, new task/effect admissions stop; health, inspection, cancellation and
original-operation reconciliation remain possible using reserved control capacity.
The 4,096 budget limits normal mutations. Reserve 128 additional bounded control
records for cancellation/reconciliation; exhaustion still permits native stop
via the trusted operator runbook without pretending the controller persisted it.
Actual ENOSPC causes stop-new-admissions plus native supervisor teardown; report
unknown if durability prevents proving a result. Never GC unresolved records.

## Backup, upgrade and rollback

Use online-consistent database backup with manifest, version and digest. Do not
copy a live SQLite main file without its transactional state. Exclude secrets
from diagnostic bundles. A backup is not an authority rewind: restored controller
state must reconcile forward against native owners before any admission. Missing
newer native operations or retired enrollment epochs keep the service blocked.

Apply versioned forward migrations to a retained backup, verify all unresolved
IDs and commitments, and activate only after checks. An older binary must refuse
a newer schema. Binary rollback does not imply schema rollback. Native stores,
budgets and external effects are never rewound. Import to another machine is a
read-only evidence import unless a separate native transfer protocol qualifies
authority and resource ownership. Omarchy system snapshots do not cover the home
directory and cannot replace this backup/reconciliation protocol.

## Normative requirements

| ID | Requirement | Proposed acceptance |
| --- | --- | --- |
| OM-DAT-001 | Task projections MUST keep immutable native bindings and never manufacture receipt authority. | AT-DAT-001 |
| OM-DAT-002 | State transitions and profile completion predicates MUST distinguish process exit, test failure and unknown effect outcomes. | AT-DAT-002 |
| OM-DAT-003 | Restart MUST reconcile original IDs without automatically restarting guest work or widening limits. | AT-DAT-003 |
| OM-DAT-004 | Durable intent MUST precede dispatch, and native outbox replay MUST be idempotent. | AT-DAT-004 |
| OM-DAT-005 | Task, mutation and event updates MUST commit consistently under concurrent controls. | AT-DAT-005 |
| OM-DAT-006 | Retention MUST pin uncertainty and preserve replay tombstones or retire the whole enrollment epoch. | AT-DAT-006 |
| OM-DAT-007 | Storage exhaustion MUST stop new work while preserving bounded stop/recovery routes. | AT-DAT-007 |
| OM-DAT-008 | Restore, migration and rollback MUST reconcile forward and refuse incompatible schemas. | AT-DAT-008 |

## Proposed acceptance

### AT-DAT-001: Projection forgery
Trigger: replace a local event with a success claim and insert a fake receipt.
Expected: no native authorization or verified success; evidence validation fails.
Oracle: native verifier and resource ledger. Artifact: `projection-forgery.json`.

### AT-DAT-002: Completion truth table
Trigger: successful model text with failed checks, clean guest exit with unknown
dispatch, and full verified profile completion. Expected: failed, blocked_unknown,
and succeeded respectively. Oracle: independent check and effect ledgers.
Artifact: `task-completion-truth-table.json`.

### AT-DAT-003: Restart without new authority
Trigger: restart every nonterminal state, advance deadline, then request resume.
Expected: original reconciliation, no automatic relaunch or deadline reset.
Oracle: process launch observer and native binding comparison.
Artifact: `task-restart-reconciliation.json`.

### AT-DAT-004: Dispatch crash matrix
Trigger: crash before/after reservation, native submission, effect, result and
projection commit. Expected: at most one effect and original IDs at every cut.
Oracle: independent persistent effect counter. Artifact: `outbox-cutpoints.json`.

### AT-DAT-005: Transaction tearing
Trigger: concurrent cancel/resume and forced termination during commits.
Expected: valid revisions and complete corresponding event sequence only.
Oracle: reopened database consistency query and transcript.
Artifact: `projection-transactions.json`.

### AT-DAT-006: Retention replay
Trigger: age out settled tasks, fill tombstones, replay old keys, retain one
uncertain operation. Expected: no duplicate admission; uncertainty survives.
Oracle: native effect count and retained binding audit. Artifact: `retention-replay.json`.

### AT-DAT-007: Disk full and capacity
Trigger: fill task, mutation, reserved-control and disk quotas separately.
Expected: declared refusal/stop semantics; no false durable cancellation.
Oracle: supervisor process observer and native operation inquiry.
Artifact: `storage-exhaustion.json`.

### AT-DAT-008: Restore behind an effect
Trigger: restore a controller backup older than a completed native effect, attempt
old-binary startup and failed migration. Expected: no effect replay, incompatible
startup refused, original backup retained. Oracle: native ledger and schema audit.
Artifact: `migration-restore-matrix.json`.
