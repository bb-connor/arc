//! Prometheus text exposition for guard metrics.

use chio_metrics_spec::{
    CHIO_GUARD_DENY_TOTAL, CHIO_GUARD_EVAL_DURATION_SECONDS, CHIO_GUARD_FUEL_CONSUMED_TOTAL,
    CHIO_GUARD_HOST_CALL_DURATION_SECONDS, CHIO_GUARD_MODULE_BYTES, CHIO_GUARD_RELOAD_TOTAL,
    CHIO_GUARD_VERDICT_TOTAL, CHIO_SIGNING_QUEUE_BLOCK_TOTAL, GUARD_EVAL_DURATION_BUCKETS_SECONDS,
    GUARD_HOST_CALL_DURATION_BUCKETS_SECONDS,
};

pub use chio_metrics_spec::MetricKind as PrometheusMetricKind;

pub const GUARD_METRICS_PATH: &str = "/metrics";
pub const PROMETHEUS_TEXT_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GuardMetricFamily {
    pub name: &'static str,
    pub help: &'static str,
    pub kind: PrometheusMetricKind,
    pub labels: &'static [&'static str],
    pub buckets: &'static [&'static str],
}

const LABELS_GUARD_VERDICT: &[&str] = &["guard_id", "verdict"];
const LABELS_GUARD_ONLY: &[&str] = &["guard_id"];
const LABELS_GUARD_REASON_CLASS: &[&str] = &["guard_id", "reason_class"];
const LABELS_GUARD_OUTCOME: &[&str] = &["guard_id", "outcome"];
const LABELS_GUARD_HOST_FN: &[&str] = &["guard_id", "host_fn"];
const LABELS_GUARD_EPOCH: &[&str] = &["guard_id", "epoch"];

pub const GUARD_METRIC_FAMILIES: &[GuardMetricFamily] = &[
    GuardMetricFamily {
        name: CHIO_GUARD_EVAL_DURATION_SECONDS,
        help: "WASM guard evaluation duration in seconds.",
        kind: PrometheusMetricKind::Histogram,
        labels: LABELS_GUARD_VERDICT,
        buckets: GUARD_EVAL_DURATION_BUCKETS_SECONDS,
    },
    GuardMetricFamily {
        name: CHIO_GUARD_FUEL_CONSUMED_TOTAL,
        help: "Total WASM guard fuel units consumed.",
        kind: PrometheusMetricKind::Counter,
        labels: LABELS_GUARD_ONLY,
        buckets: &[],
    },
    GuardMetricFamily {
        name: CHIO_GUARD_VERDICT_TOTAL,
        help: "Total WASM guard verdicts by guard and verdict.",
        kind: PrometheusMetricKind::Counter,
        labels: LABELS_GUARD_VERDICT,
        buckets: &[],
    },
    GuardMetricFamily {
        name: CHIO_GUARD_DENY_TOTAL,
        help: "Total WASM guard denies by reason class.",
        kind: PrometheusMetricKind::Counter,
        labels: LABELS_GUARD_REASON_CLASS,
        buckets: &[],
    },
    GuardMetricFamily {
        name: CHIO_GUARD_RELOAD_TOTAL,
        help: "Total WASM guard reload outcomes.",
        kind: PrometheusMetricKind::Counter,
        labels: LABELS_GUARD_OUTCOME,
        buckets: &[],
    },
    GuardMetricFamily {
        name: CHIO_GUARD_HOST_CALL_DURATION_SECONDS,
        help: "WASM guard host-call duration in seconds.",
        kind: PrometheusMetricKind::Histogram,
        labels: LABELS_GUARD_HOST_FN,
        buckets: GUARD_HOST_CALL_DURATION_BUCKETS_SECONDS,
    },
    GuardMetricFamily {
        name: CHIO_GUARD_MODULE_BYTES,
        help: "Loaded WASM guard module size in bytes.",
        kind: PrometheusMetricKind::Gauge,
        labels: LABELS_GUARD_EPOCH,
        buckets: &[],
    },
];

pub use chio_metrics_spec::CHIO_OTEL_INGRESS_DROP_TOTAL as METRIC_CHIO_OTEL_INGRESS_DROP_TOTAL;
pub use chio_metrics_spec::CHIO_OTEL_SINK_DROP_TOTAL as METRIC_CHIO_OTEL_SINK_DROP_TOTAL;

// Advertised runtime (non-guard) families the /metrics endpoint renders via the
// chio-metrics-spec runtime families. Retained as endpoint documentation; the
// actual samples are produced by render_otel_drop_families and the signing
// family render, so this table is not iterated by the renderer.
#[allow(dead_code)]
const RUNTIME_METRIC_FAMILIES: &[GuardMetricFamily] = &[
    GuardMetricFamily {
        name: CHIO_SIGNING_QUEUE_BLOCK_TOTAL,
        help: "Total receipt signing requests blocked by bounded queue capacity or byte budget.",
        kind: PrometheusMetricKind::Counter,
        labels: &["reason"],
        buckets: &[],
    },
    GuardMetricFamily {
        name: METRIC_CHIO_OTEL_INGRESS_DROP_TOTAL,
        help: "Total OTEL ingress batches dropped by bounded queue admission.",
        kind: PrometheusMetricKind::Counter,
        labels: &[],
        buckets: &[],
    },
    GuardMetricFamily {
        name: METRIC_CHIO_OTEL_SINK_DROP_TOTAL,
        help: "Total OTEL receipt sink batches dropped before append.",
        kind: PrometheusMetricKind::Counter,
        labels: &[],
        buckets: &[],
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricsEndpointResponse {
    pub status: u16,
    pub content_type: &'static str,
    pub body: String,
}

#[must_use]
pub fn guard_metrics_endpoint(path: &str) -> Option<MetricsEndpointResponse> {
    if path != GUARD_METRICS_PATH {
        return None;
    }

    Some(MetricsEndpointResponse {
        status: 200,
        content_type: PROMETHEUS_TEXT_CONTENT_TYPE,
        body: render_guard_metrics_prometheus(),
    })
}

/// Render the kernel `/metrics` body from the chio-metrics-spec runtime
/// families (RFC-0009 F75). The kernel renders the guard families and the two
/// OTEL-drop families (whose sole producers are chio-wasm-guards and the OTLP
/// ingress, which cannot be depended on by the kernel) plus the signing-queue
/// block family, so every sample is a real, correctly-labeled counter rather
/// than a hardcoded zero placeholder.
#[must_use]
pub fn render_guard_metrics_prometheus() -> String {
    let mut output = String::new();
    chio_metrics_spec::runtime::render_guard_families(&mut output);
    chio_metrics_spec::runtime::render_otel_drop_families(&mut output);
    chio_metrics_spec::runtime::families::SIGNING_QUEUE_BLOCK.render(&mut output);
    output
}
