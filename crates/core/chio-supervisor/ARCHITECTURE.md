# chio-supervisor architecture

## Responsibility and boundary

This crate owns worker supervision policy and shared health state.
Its public surface includes `SupervisorConfig`, `SupervisedOutcome`,
`HealthFlag`, `HealthLevel`, `HealthSnapshot`, and `SupervisedThread`.
The optional `async` feature adds `SupervisedTask` and `supervise_task`.
`now_unix_ms` supplies a saturating wall-clock timestamp helper.

Callers own work resources, dispatch checks, recovery authorization, and shutdown
protocols. The crate does not impose a deadline on a stuck iteration.
A TCB-critical flag closes serving only when a caller checks its predicate.

## Structure

- `config.rs` defines policy, outcomes, and capped exponential backoff.
- `health.rs` owns atomics, reason storage, and serialized snapshots.
- `thread.rs` owns the OS thread handle and cooperative shutdown flag.
- `task.rs` owns Tokio supervision and tracked child cancellation.
- `time.rs` supplies timestamp and duration conversion helpers.
- `sync.rs` selects standard or Loom health synchronization primitives.

The crate forbids unsafe code and depends on no other Chio crate.

## Data and control flow

`SupervisorConfig::new` trips after three consecutive failures and terminates
after ten, with 100 ms base backoff and a 60 s ceiling.
The policy fields are public; callers select consistent thresholds and delays.

Thread supervision catches unwinding worker panics and reuses the closure.
A spawn error records failure and raises health directly to `Failed`.
`Continue` records success and immediately invokes the next iteration.
`Restart` records a failure, escalates at the budget, or sleeps before retrying.
`Shutdown` terminates normally.

Tokio supervision runs each future in a child task.
Panics while building a future and panics reported by its join handle both
become restart-worthy failures. A cancelled child ends the supervisor.
The task wrapper tracks the child's abort handle under a mutex so cancellation
also covers the child publication race.

## Trust and invariants

`HealthFlag::raise_to` uses a compare-and-swap loop for monotonic escalation.
`record_ok` resets consecutive failures and stamps liveness without recovery.
`clear` explicitly lowers severity, clears the reason, and preserves total failures.
The API supplies no authorization check for callers invoking `clear`.

`is_serving_closed` combines TCB-critical status with non-Healthy severity.
`HealthSnapshot` reads fields separately; it is not an atomic transaction over
all counters, timestamps, level, and reason.

Dropping `SupervisedThread` signals shutdown but does not join or interrupt
blocking work. `shutdown` joins and can wait for the worker to cooperate.
Dropping or aborting `SupervisedTask` cancels the supervisor and tracked child.
The raw `supervise_task` returns a join handle without the wrapper's coordinated
shutdown API; callers must account for Tokio handle detachment semantics.
Panic catching requires an unwind profile; aborting panics stop the process.

## Dependencies

`serde` serializes health levels and camelCase snapshots.
Optional Tokio supplies task spawning, joining, aborting, and asynchronous sleep.
Loom replaces health synchronization types under its separate cfg.
`proptest` and `serde_json` support health properties and serialization tests.

## Verification

Unit tests cover thresholds, explicit clear, capped backoff, clean shutdown,
panics, and successful iterations between failures.
Async tests cover future-construction panics and tracked child cancellation,
including cancellation racing handle publication.
Property tests cover monotonic levels and failure accounting across clears.
The Loom test models a failure racing a reader and checks the final level.

```bash
cargo test -p chio-supervisor
cargo test -p chio-supervisor --features async
RUSTFLAGS="--cfg loom" cargo test -p chio-supervisor --test loom_health --release
```

Without `cfg(loom)`, this integration test registers no tests.
The command above enables the model. These tests cover supervision primitives;
operator recovery and pre-dispatch integration require caller verification.
