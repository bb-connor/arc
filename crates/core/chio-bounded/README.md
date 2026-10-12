# chio-bounded

`chio-bounded` supplies process-local collections with an entry capacity and a
readable size gauge. Serving code can use `Ring` for recent history and
`BoundedMap` for caches or rate-limit tables whose growth must stay bounded.

## Usage

A ring returns the oldest entry when an append exceeds capacity:

```rust
use chio_bounded::{Ring, SizeGauge};

let gauge = SizeGauge::new();
let mut recent = Ring::with_capacity(2, gauge.clone());
assert_eq!(recent.push("first"), None);
assert_eq!(recent.push("second"), None);
assert_eq!(recent.push("third"), Some("first"));
assert_eq!(gauge.get(), 2);
assert_eq!(recent.iter().copied().collect::<Vec<_>>(), vec!["second", "third"]);
```

`BoundedMap::new(capacity, idle_ttl_secs, gauge)` takes caller-supplied seconds
on `insert` and `get`. Reads refresh idle time; cleanup runs every 256 inserts.

## Guarantees

- `Ring::push` and `BoundedMap::insert` return incoming values at zero capacity.
- Both insertion paths limit retained entries to the configured capacity.
- `Ring::clone` creates an independent gauge for the cloned snapshot.
- `BoundedMap::insert` moves reinserted keys to their newest insertion position.

## Status

Implemented in-memory collection primitives with unit, property, stress, and
optional Loom tests. Callers own synchronization, persistence, and clock input.
TTL cleanup is periodic and a `get` can refresh an entry before cleanup.
The separate `cfg(loom)` configuration models gauge synchronization in tests.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol observability](../../../spec/PROTOCOL.md#13-observability-contract)
- [Supervisor](../chio-supervisor/README.md)

[License](../../../LICENSE)
