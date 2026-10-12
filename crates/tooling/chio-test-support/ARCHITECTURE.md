# chio-test-support architecture

## Responsibility and boundary

The crate owns shared test assertion conventions and fixture utilities.
`plain::{TestResultOk, TestResultErr}` provides context-free extraction methods
and context-labeled variants. `ctx::{TestUnwrap, TestUnwrapErr}` requires
a context string. `prelude` re-exports the `plain` traits.
`loopback` classifies socket bind failures and finds ephemeral addresses.
`private_tempdir` and `clock` support key custody and clock injection in tests.

The intended integration boundary is a development dependency used by tests.
The library itself is compiled normally and exposes these APIs without
`cfg(test)` restrictions. Callers decide where they are imported and invoked.
Assertion failures panic; they are unsuitable for handling expected runtime
authorization or policy errors in a serving path.

## Structure

[src/lib.rs](src/lib.rs) contains assertion traits, loopback helpers,
temporary-directory construction, and their inline unit tests.
[src/clock.rs](src/clock.rs) contains `FixtureClock`, thread-local fixture
selection, `ClockScope`, reading helpers, and cross-thread clock tests.
The crate forbids unsafe code and has no declared Cargo features.

The two assertion families overlap on method names.
Import `prelude::*` or `ctx::*` at a call site and keep the chosen convention
consistent. `plain` renders error payloads with `Debug`; `ctx` uses `Display`.
Error-extraction traits place no `Debug` bound on the successful value type.

## Data and control flow

Extraction matches the `Result` or `Option` directly.
The expected variant returns its contained value; the unexpected variant
panics with the relevant message. `#[track_caller]` preserves the assertion
caller's location for these methods.

Loopback probes bind `127.0.0.1:0` and immediately drop the listener.
`reserve_listen_addr_for` reads the assigned address before releasing it.
The returned address is advisory; the caller must bind its own server and
handle a concurrent process claiming that port.

Each thread selects an `Arc<FixtureClock>` through a thread-local.
The instance stores optional Unix seconds behind a mutex.
`scope_unix_secs` replaces that value and records its predecessor in a guard.
Dropping the guard restores the predecessor on the same instance.
Nested scopes should be dropped in reverse acquisition order for restoration
to reproduce their original readings.

`clock()` returns an `Arc<dyn Clock>` for explicit injection.
Moving that Arc to another thread preserves the selected fixture instance;
a separate thread's own `clock()` selects a different fixture.
`FixtureClock::read` first reads `SystemClock`, retains its monotonic reading,
and substitutes scoped Unix seconds when present.

## Trust and invariants

Fixture time does not replace the production clock globally.
Constructors observe the fixture only through an explicitly supplied clock.
System-clock errors still propagate even when a Unix-seconds override exists.
A poisoned fixture mutex yields `ClockError::Unavailable` while reading;
scope changes and restoration use assertion helpers and panic on lock failure.
Conversion of scoped seconds into milliseconds remains checked by `UnixMillis`.

`is_loopback_bind_denied` recognizes only `ErrorKind::PermissionDenied`.
The strict skip helper panics on unexpected bind failures, preserving failures
such as address conflicts. `loopback_bind_available` is a simpler Boolean
probe that maps every error to false.

`private_tempdir` sets mode `0700` at Unix directory creation independently
of the runner's umask. Non-Unix platforms inherit `tempfile` behavior.
Callers retain responsibility for the contents and lifetime of key fixtures.

## Dependencies

`chio-security-types` with its `std` feature supplies `Clock`, `ClockReading`,
`SystemClock`, and checked Unix-millisecond values.
`tempfile` supplies automatic temporary-directory cleanup and Unix permission
configuration. Assertions, sockets, mutexes, and thread-local storage use `std`.

## Verification

The inline assertion tests cover successful extraction with non-`Debug`
value types and panic messages and locations for both trait families.
Loopback classifier tests distinguish permission denial from address conflicts.
Clock tests check an injected instance across threads and independent fixture
instances selected by separate threads.
Run `cargo test -p chio-test-support` for this coverage.

The [README sample](README.md#usage) exercises successful assertions and a
scoped clock reading. Socket availability and platform-specific directory
permissions depend on the environment in which their callers execute.
