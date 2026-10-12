# chio-edge-metrics architecture

## Responsibility and boundary

`ReceiptWriteCounters` owns four atomic counters. `ReceiptWriteSnapshot` and
`ReceiptWriteSample` expose copied observations. The hosting edge owns counter
lifetime, recording placement, exporter routing, and health data.

Provides per-instance receipt-write counters and Prometheus formatting shared by
protocol edges. Each hosting edge chooses its own counter instance.

## Structure

A single `lib.rs` contains metric constants, typed outcome taxonomy, verdict
mapping, counter storage, snapshots, rendering, and unit tests. There are no
transport or storage modules.

`ReceiptWriteOutcome` defines Allow, Deny, PendingApproval, and Error.
`ReceiptWriteSnapshot` stores one copied total per outcome; `ReceiptWriteSample`
pairs a typed outcome with its total. The metric name comes from chio-metrics-spec
as the shared registry identifier.

## Data and control flow

A caller records a typed outcome, string label, or kernel verdict. The counter
increments without wrapping. Reads use relaxed atomics, and snapshots read each
outcome independently. Prometheus rendering emits a HELP/TYPE block and the four
stable labeled samples.

`record_verdict` maps kernel Allow, Deny, and PendingApproval to the corresponding
receipt-write outcome. Error must be recorded explicitly for writer failures or
unknown string labels. `total` returns the current error counter for an unknown
label, and `record` increments that same error counter for an unknown label.

## Trust and invariants

These observations do not validate or write receipts. Separate instances isolate
edges. A snapshot is not an atomic transaction across all counters. Unknown string
labels increment error so emissions remain visible. Liveness formatting accepts the
caller-provided label verbatim; hosts supply a trusted bounded label vocabulary.

`ReceiptWriteCounters` uses saturating atomic increments. `record` maps unknown
labels to error. `ReceiptWriteSnapshot::samples` returns allow, deny, pending
approval, and error in stable order.

`increment_saturating` uses fetch_update with relaxed ordering and saturating_add. A
counter stays at u64::MAX rather than wrapping to zero. Snapshots perform four
separate relaxed loads, so simultaneous updates can appear in different observations
within one snapshot.

## Dependencies

`chio-kernel` supplies the verdict enum used by mapping helpers. `chio-metrics-spec`
supplies the registry metric name. Standard-library atomics supply thread-safe
counters without a runtime or network client.

## Verification

Inline tests cover registry naming, label round trips, stable sample order, instance
isolation, unknown outcomes, saturation, snapshots, and liveness formatting.

Run focused library tests from the workspace root:

```bash
cargo test -p chio-edge-metrics
```

`unknown_outcome_records_under_error` checks fallback accounting.
`receipt_write_counters_saturate_instead_of_wrapping` checks overflow behavior.
`verdict_maps_to_expected_outcome` checks kernel-to-metric classification.
`counters_are_isolated_per_instance` checks independent edge sinks.
