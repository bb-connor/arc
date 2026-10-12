# chio-metrics-spec

`chio-metrics-spec` defines Chio's Prometheus metric names, kinds, labels, and
histogram buckets. Its registry and snapshot make descriptor changes
reviewable. A separate public `runtime` module stores and renders samples for
selected families; serving applications own endpoints and instrumentation.

## Usage

Create a local counter using its registered descriptor and render one sample:

```rust
use chio_metrics_spec::{descriptor_for, CHIO_SOC_EXPORT_TOTAL};
use chio_metrics_spec::runtime::LabeledCounter;

let descriptor = descriptor_for(CHIO_SOC_EXPORT_TOTAL)
    .ok_or("missing SOC export descriptor")?;
let counter = LabeledCounter::new(descriptor.name, descriptor.labels);
counter.preregister(&["offline", "ok"]);
counter.incr(&["offline", "ok"]);
let mut output = String::new();
counter.render(&mut output);
assert!(output.contains("# TYPE chio_soc_export_total counter"));
assert!(output.contains("exporter=\"offline\",outcome=\"ok\"} 1"));
# Ok::<(), Box<dyn std::error::Error>>(())
```

The example uses only `std` and local state. `runtime::families` provides
shared statics for guards, OTEL drops, receipt watchdogs, signing queues, and
alerting. A registry entry alone creates no sample or active producer.

## Guarantees

- `validate_metric_descriptor` checks metric and label syntax, duplicate
  labels, bucket presence and kind, and finite, strictly increasing histogram
  bounds. Label names reject the reserved `__` prefix.
- `validate_registry` also checks sorted, unique metric names.
  `registry_snapshot` serializes descriptor shape and help text; a unit test
  compares it exactly with `metrics.snapshot`.
- `LabeledCounter`, `LabeledGauge`, and `LabeledHistogram` drop updates with a
  label-value arity mismatch or poisoned cell-map lock. Constructors accept
  arbitrary names and label definitions; callers must align them with the
  registry's kind and labels.
- Renderers escape backslash, quote, and newline in label values. Histogram
  bucket labels preserve the registry's original strings, including `1.0`.
- `preregister` seeds zero-valued series without resetting existing values.
  `preregister_known_label_sets` seeds selected fixed domains; configured
  exporter and route domains need separate registration.

## Status

Implemented registry validation, process-local storage, and Prometheus text
rendering with snapshot and runtime regression tests. The crate has no Cargo
features or dependencies and is marked `publish = false`. Runtime APIs are
always available. Applications control label cardinality, acceptable histogram
observations, collection, and scrape availability.

For new metric families, add a name constant and sorted `REGISTRY` descriptor,
update the snapshot, then wire the producer and renderer in their owning
surface. Descriptor registration does not establish deployment coverage.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol trust boundaries](../../../spec/PROTOCOL.md#3-components-and-trust-boundaries)
- [WASM guards](../../guards/chio-wasm-guards/README.md)
- [SIEM export](../chio-siem/README.md)

License: [Apache-2.0](../../../LICENSE).
