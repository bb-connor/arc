# chio-metrics-spec architecture

## Responsibility and boundary

The crate owns Chio metric taxonomy and selected process-local sample stores.
`MetricDescriptor` records a static name, help text, kind, ordered labels,
and histogram bucket strings. `REGISTRY`, name constants, lookup functions,
and validators expose the declaration surface. `runtime` exposes counters,
gauges, histograms, shared family statics, and Prometheus text renderers.

A descriptor establishes a name and shape. Producers must update storage,
and serving applications must select renderers and publish scrape endpoints.
The crate opens no listener and performs no export or file I/O. It declares
no Cargo features, so `runtime` is available in every build.

## Structure

| File | Responsibility |
| --- | --- |
| `src/lib.rs` | Descriptor types, `describe!`, constants, sorted registry, validation and snapshot. |
| `src/runtime.rs` | Local sample stores, shared families, zero registration and text composition. |
| `metrics.snapshot` | Exact `name|kind|labels|buckets|help` descriptor snapshot used by tests. |

`describe!` builds a descriptor from literal metadata and a name expression;
it does not run validation or add the descriptor to the registry.
`descriptor_for` performs a linear search and returns an optional borrowed
descriptor. `is_registered_metric` is a lookup predicate.

## Data and control flow

`validate_metric_descriptor` checks metric names, ordered label names,
duplicate labels, and bucket semantics. Counters and gauges must have no
buckets. Histograms need at least one finite, parseable `f64` bound in
strictly increasing numerical order. Negative finite bounds are permitted.
`validate_registry` applies these checks and checks sorted, unique names.
Neither validation runs automatically in runtime family constructors.

Each `LabeledCounter`, `LabeledGauge`, or `LabeledHistogram` owns a mutex
around a `BTreeMap` keyed by an owned label-value tuple. Resolving a cell
checks tuple arity and locks this map on every update or preregistration,
including updates to existing series. Cells use shared atomic values;
updates and rendering reads use relaxed ordering. The ordered map makes
series ordering deterministic, while a concurrent scrape can observe
individual histogram fields at different points in an update.

Counters add unsigned deltas. Gauges set unsigned values. Histograms look up
bucket bounds by family name, increment every matching cumulative bucket,
and always increment `+Inf` and count. Their sum rounds seconds to integer
nanoseconds and clamps negative contributions to zero. Observation inputs
receive no explicit finite/nonnegative validation. Callers should supply
finite, nonnegative seconds and bound accumulated values.

`preregister` creates a zero series without changing an existing cell.
`preregister_known_label_sets` seeds selected fixed domains, including
signing-queue reasons and retained-hold reconciliation values. Dynamic
exporter and route domains remain a serving application's responsibility.
Registration creates series; it does not produce a scrape by itself.

## Trust and invariants

Metric names accept ASCII letters, digits after the first character, `_`,
and `:`. Labels accept ASCII letters, `_`, and subsequent digits, and reject
the reserved `__` prefix. `MetricValidationError` identifies malformed names,
label duplication, bucket shape, and registry ordering errors.
The validators do not constrain label values, help text, or cardinality.

Runtime constructors accept arbitrary static names and label arrays without
checking name registration, descriptor labels, or kind. Rendering uses the
registry's help text when lookup succeeds; the selected runtime type supplies
the `TYPE` word. A wrongly selected type can therefore disagree with the
registered kind. An unknown histogram name yields no finite buckets.
Consumers should use the descriptor's exact name and labels and choose its
matching runtime type.

Arity mismatches and poisoned map locks drop updates without a panic or
returned error. Renderers write headers before taking the map lock, so a
poisoned map can yield headers with no samples. Atomic counter and histogram
accumulators use unsigned wrapping arithmetic without an overflow report.
There is no series eviction or cardinality ceiling.

Text rendering escapes backslash, quote, and newline in label values.
Histogram `le` values retain original registry strings such as `1.0`;
numerical parsing is used only for observation comparisons. Histogram output
includes finite buckets, `+Inf`, sum, and count. `compose_metrics_body`
concatenates caller-provided render results and performs no deduplication.

Shared statics cover guard families, OTEL drops, receipt watchdogs, signing
queues, settlement holds, and alerting. `render_guard_families`,
`render_otel_drop_families`, `render_receipt_watchdog_gauges`, and
`render_alert_pack_families` expose selected groups. Callers render remaining
shared statics explicitly where their endpoint needs them.

## Dependencies

The manifest has no dependencies. Runtime storage uses `std::collections`,
`std::sync`, and atomics. The registry can be consumed without selecting an
exporter backend or an async runtime. Owning producer crates determine when
registered names are instrumented and which renderer an endpoint composes.

## Verification

Registry tests compare the snapshot byte for byte, require sorted unique
names, check Prometheus syntax and expected labels, and reject malformed
histogram bounds and kind/bucket mismatches. Runtime tests cover concurrent
counter increments, headers, zero registration, arity rejection, cumulative
buckets, original bucket strings, label escaping, and sub-millisecond sums.

Run `cargo test -p chio-metrics-spec` for these checks.
`scripts/check-sre-metrics-registry.sh` compares metric-like names in selected
source, deployment, workflow, script, and runbook paths with the snapshot.
This gate checks declarations in its scanned scope; actual producer and
endpoint behavior require their owning surface's tests.

See the [README](README.md), [SIEM crate](../chio-siem/README.md), and
[protocol trust boundaries](../../../spec/PROTOCOL.md#3-components-and-trust-boundaries).
