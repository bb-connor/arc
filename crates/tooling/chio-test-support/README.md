# chio-test-support

`chio-test-support` supplies assertion helpers, loopback probes, private
temporary directories, and explicitly injected fixture clocks for Chio tests.
Its extension traits keep test assertions readable under the workspace's
`unwrap_used` and `expect_used` lint rules.

## Usage

Add the crate as a development dependency and import one assertion family.
The default `prelude` exposes methods with optional context labels:

```rust
use chio_test_support::prelude::*;

let parsed: Result<u64, _> = "42".parse();
assert_eq!(parsed.test_expect("parse fixture value"), 42);
assert_eq!(Some("ready").test_unwrap(), "ready");
let denied: Result<(), &str> = Err("denied");
assert_eq!(denied.test_unwrap_err(), "denied");

let scope = chio_test_support::clock::scope_unix_secs(42);
assert_eq!(chio_test_support::clock::unix_seconds(), 42);
drop(scope);
```

The `ctx` family instead requires a `&str` context on every extraction.
Both families define `test_unwrap`; import one family per call site to avoid
ambiguous methods. Fixture clocks affect constructors only when the caller
passes `clock::clock()` as the explicit clock dependency.

## Guarantees

- `plain` and `ctx` panic on an unexpected `Result` or `Option` variant.
  Their extraction methods use `#[track_caller]` for assertion locations.
- `skip_when_loopback_bind_denied` permits a skip only for an operating-system
  `PermissionDenied` bind error; other probe errors panic.
- `private_tempdir` creates directories with mode `0700` on Unix.
  Other platforms use the ordinary `tempfile` constructor.
- `ClockScope` restores the selected fixture clock's previous seconds value
  when dropped, including after transfer to another thread.

## Status

This unpublished library is intended for tests and development dependencies.
Its public helpers are ordinary callable Rust APIs; use in test-only code is
a caller convention. Loopback address helpers release the listener before
returning, so the address can be taken before a test server binds it.
`loopback_bind_available` returns false for any bind failure; use the stricter
skip helper when classifying environmental permission denials.
There are no declared Cargo features.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol components and trust boundaries](../../../spec/PROTOCOL.md#3-components-and-trust-boundaries)
- [Trace validator tests](../chio-trace-validate/README.md)
- [License](../../../LICENSE)
