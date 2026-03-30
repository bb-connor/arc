# ADR-0009: SIEM Isolation Architecture

- Status: Accepted
- Decision owner: observability and compliance lanes
- Related plan items: phase SIEM exporter pipeline

## Context

ARC needed a SIEM export pipeline to forward signed receipt audit events to
external systems (Splunk HEC, Elasticsearch). The question was where to locate
this pipeline: inside `arc-kernel`, as an extension of `arc-cli`, or as a
separate crate.

Key requirements:

1. The SIEM pipeline must not introduce new dependencies into `arc-kernel`,
   which is the trusted computing base. Adding HTTP client libraries to the
   TCB increases the attack surface.
2. The pipeline reads receipts from the kernel's SQLite store. It must do so
   without requiring the Kernel to be running at the same time (enabling
   asynchronous offline export).
3. The pipeline needs to be independently testable and deployable. Operators
   may want to enable SIEM without enabling all other `arc-cli` features.
4. Failures in the SIEM exporter must not affect kernel receipt signing.

## Decision

The SIEM pipeline is implemented as a **separate crate, `arc-siem`**, with
the following isolation properties:

**No `arc-kernel` dependency.** `arc-siem`'s `Cargo.toml` lists only
`arc-core` as a ARC dependency. It does not depend on `arc-kernel`. This
prevents the HTTP client, retry logic, and exporter configuration from
transitively entering the kernel's dependency tree.

**Direct SQLite read.** `arc-siem` opens the kernel's receipt SQLite
database with `SQLITE_OPEN_READ_ONLY | SQLITE_OPEN_NO_MUTEX` and reads rows
directly via `rusqlite`. It does not call any `arc-kernel` API at runtime.
The schema it reads is a stable column layout that the kernel appends to;
`arc-siem` is a read-only consumer and does not write to the database.

**Persistent read-only connection.** A single `rusqlite::Connection` is
opened at `ExporterManager::new` and reused across all poll cycles under a
`Mutex`. This avoids re-opening the file on every tick and keeps WAL-mode
shared-read semantics stable. The mutex is released before any `.await` point.

**Cursor-pull loop.** `ExporterManager::run` polls on a configurable interval
(default 5 seconds) using a seq-based cursor. The cursor is not persisted to
disk; on restart the manager re-exports from seq=0. Both Splunk HEC and
Elasticsearch handle duplicate events idempotently (timestamp dedup and
`_id` upsert respectively).

**Dead-letter queue.** Events that exhaust all retry attempts are placed on a
bounded in-memory `DeadLetterQueue`. The DLQ capacity is configurable
(default 1000). DLQ overflow drops the oldest entry.

**Feature flag gating.** `arc-siem` is an optional dependency of `arc-cli`.
Operators who do not need SIEM export do not link it.

## Rationale

Separating `arc-siem` from `arc-kernel` enforces a hard boundary between
the TCB and the observability pipeline. If the SIEM exporter has a
vulnerability (e.g., in the HTTP client or JSON serialization), it cannot
affect the kernel's receipt signing or capability enforcement.

Direct SQLite reads are preferred over an IPC channel from the Kernel because:

- No API server needs to be running for SIEM export (air-gapped export is
  possible by copying the SQLite file).
- The read path adds zero latency to the Kernel's hot path.
- SQLite WAL mode allows concurrent reads with no blocking on the write side.

## Consequences

### Positive

- The TCB (`arc-kernel`) has no HTTP client or retry logic dependency.
- SIEM can run as a sidecar process alongside the Kernel, or on a separate
  machine with a replica of the SQLite file.
- Failures in the SIEM pipeline are entirely isolated from receipt signing.

### Negative

- `arc-siem` must stay in sync with the receipt store schema. Schema
  migrations in the kernel's SQLite database require a corresponding update to
  the SQL queries in `arc-siem`.
- The restart-cursor behavior means duplicate events are exported on every
  restart. Downstream SIEM systems must be configured for idempotent ingest.

## Required Follow-up

- Persist the cursor to disk so that restarts do not re-export the full history.
- Add a health endpoint or status metric for DLQ depth.
- Document the schema columns that `arc-siem` depends on so that kernel
  schema migrations include a compatibility check.
