# chio-edge-metrics

Provides per-instance receipt-write counters and Prometheus formatting shared by protocol edges. Each hosting edge chooses its own counter instance.

This crate sits at Chio's protocol boundary. Its embedding application
chooses the surrounding runtime and transport wiring.

## Usage

The example runs locally without opening a listener or spawning an agent.

```rust
use chio_edge_metrics::{ReceiptWriteCounters, ReceiptWriteOutcome};

let counters = ReceiptWriteCounters::new();
counters.record_outcome(ReceiptWriteOutcome::Allow);
assert_eq!(counters.snapshot().total(ReceiptWriteOutcome::Allow), 1);
assert!(counters.render_prometheus().contains("outcome=\"allow\""));
```

## Guarantees

`ReceiptWriteCounters` uses saturating atomic increments. `record` maps unknown labels to error. `ReceiptWriteSnapshot::samples` returns allow, deny, pending approval, and error in stable order.

Recording updates observations; it does not apply a policy decision or persist
a receipt. Hosts select the recording location and liveness label vocabulary.

## Status

Implemented in-memory metrics sink and formatter. Recording is explicit at the hosting edge boundary. Counters provide process-local observations; persistence and receipt storage are caller responsibilities.

The crate is workspace-internal (`publish = false`). Its tests exercise
library behavior; deployment configuration needs its own verification.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol contract](../../../spec/PROTOCOL.md#13-observability-contract)
- [chio-a2a-edge](../chio-a2a-edge/README.md)

## License

See the workspace [license](../../../LICENSE).
