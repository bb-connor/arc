# chio-bounded architecture

## Responsibility and boundary

This crate owns entry-bounded process-local collections and their size gauges.
The public surface exports `Ring<T>`, `BoundedMap<K, V>`, and `SizeGauge`.
The caller selects capacity, supplies timestamps, and decides how to handle
returned capacity evictions.

Collections require mutable access for mutation.
Callers own external locking when sharing a collection across threads.
Persistence, signed records, and authorization are outside this boundary.
Capacity measures entries; it does not bound the byte size of each value.

## Structure

- `ring.rs` stores ordered entries in a `VecDeque`.
- `bounded_map.rs` combines a `HashMap` with an insertion-position queue.
- `gauge.rs` wraps an atomic count in a cloneable shared handle.
- `sync.rs` selects standard or Loom gauge synchronization types.

No unsafe code is permitted in the crate.
The ordinary implementation has no external runtime dependencies.

## Data and control flow

`Ring::push` evicts the oldest item before appending at capacity.
Zero capacity returns the incoming item and stores nothing.
Cloning a ring copies its values and seeds a new independent gauge.

`BoundedMap::insert` sweeps idle entries every 256 insert attempts at nonzero cap.
A new key at capacity evicts the oldest live insertion position.
Reinsertion replaces the value and assigns a new saturating sequence number.
Stale positions are skipped during eviction.
The position queue is compacted when it exceeds twice the configured capacity.

`get` updates `last_seen_secs` without changing insertion order.
The caller supplies `now_secs` on every read and insert.
TTL zero disables idle removal.

## Trust and invariants

Capacity eviction returns one removed key and value for caller handling.
Replacement drops the previous value; idle sweeping also drops removed values.
A caller needing durable custody must account for those separate drop paths.

An idle sweep retains only timestamps greater than
`now_secs.saturating_sub(idle_ttl_secs)`.
Reads do not check expiry, so a read can refresh an unswept stale entry.
The map is unsuitable as a strict expiration verifier by itself.

Gauge stores and loads use relaxed atomics.
Use a dedicated initially zero gauge for each collection.
The gauge is an observational count; it does not synchronize collection access.
The constructors do not reset a reused gauge, and dropping a collection does
not reset outstanding gauge handles.

## Dependencies

Standard collections provide storage and ordering.
`proptest` generates mixed read/insert sequences in tests.
The target-specific Loom dependency replaces gauge atomics under `cfg(loom)`.
External mutexes in concurrency tests protect the map itself.

## Verification

Unit tests exercise eviction, zero capacity, reinsertion, compaction,
idle sweeping, and independent ring clone gauges.
Property tests check capacity and gauge equality after generated operations.
`stress_bounded_map.rs` drives eight threads through an externally locked map.
`loom_bounded_map.rs` models a bounded insertion/read interleaving.

```bash
cargo test -p chio-bounded
RUSTFLAGS="--cfg loom" cargo test -p chio-bounded --test loom_bounded_map
```

Without `cfg(loom)`, this integration test runs an empty body.
The command above enables the model. These checks exercise collection capacity,
eviction, and gauge behavior. Serving-process integration requires caller verification.
