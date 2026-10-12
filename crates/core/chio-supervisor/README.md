# chio-supervisor

`chio-supervisor` supervises background worker iterations and exposes shared
health state to Chio serving processes. It records restart-worthy failures,
uses capped backoff, and preserves degraded health across later successful work.

## Usage

A TCB-critical health flag gives dispatch code an explicit closure predicate:

```rust
use chio_supervisor::{HealthFlag, HealthLevel};

let health = HealthFlag::new(true);
health.record_failure("receipt writer failed", 100, 1);
assert!(health.is_serving_closed());
health.record_ok(101);
assert_eq!(health.level(), HealthLevel::Degraded);
health.clear(102);
assert!(!health.is_serving_closed());
assert_eq!(health.snapshot().restart_total, 1);
```

Use `SupervisedThread::spawn` with `SupervisorConfig` for an OS worker.
Worker iterations return `Continue`, `Restart`, or `Shutdown`.
With `async`, `SupervisedTask::spawn` runs iterations in Tokio child tasks.

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `async` | Off | Enables Tokio-backed `SupervisedTask` and `supervise_task`. |

The default build includes health state, configuration, time helpers, and the
thread supervisor. `cfg(loom)` selects modeled health synchronization primitives.

## Guarantees

- `HealthFlag::record_ok` resets consecutive failures without lowering severity.
- `HealthFlag::clear` resets health explicitly while preserving restart totals.
- `backoff_delay` saturates arithmetic and caps delays at `max_backoff`.
- `SupervisedTask::abort` and its `Drop` cancel the tracked iteration child.

## Status

Implemented supervision primitives with unit, property, and optional Loom tests.
Callers must check `is_serving_closed` before dispatch and arrange cooperative
thread shutdown. There is no built-in deadline or automatic stalled-worker check.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol observability](../../../spec/PROTOCOL.md#13-observability-contract)
- [Bounded collections](../chio-bounded/README.md)

[License](../../../LICENSE)
