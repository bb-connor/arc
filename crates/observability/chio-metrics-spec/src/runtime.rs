//! Process-global metric emission primitives (RFC-0009 Part A).
//!
//! `LabeledCounter`/`LabeledGauge`/`LabeledHistogram` are lock-free on read of a
//! resolved cell and mutex-guarded only when a new label set first appears (cold
//! path), mirroring the chio-wasm-guards pool registry. They render into the
//! `crate::descriptor_for(name)` metadata so emitted `# HELP`/`# TYPE` cannot
//! drift from the registry. All three fail closed: a lock poison or a label
//! arity mismatch drops the sample rather than unwinding, so observability
//! never gates the mediation hot path.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::descriptor_for;

fn escape_label_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn render_label_set(labels: &[&'static str], values: &[String]) -> String {
    if labels.is_empty() {
        return String::new();
    }
    let mut parts = Vec::with_capacity(labels.len());
    for (label, value) in labels.iter().zip(values.iter()) {
        parts.push(format!("{label}=\"{}\"", escape_label_value(value)));
    }
    format!("{{{}}}", parts.join(","))
}

fn render_header(out: &mut String, name: &str, kind_word: &str) {
    if let Some(descriptor) = descriptor_for(name) {
        out.push_str(&format!("# HELP {name} {}\n", descriptor.help));
    }
    out.push_str(&format!("# TYPE {name} {kind_word}\n"));
}

/// Resolve `values` against `labels`; returns an owned key when the arity
/// matches, else `None` (the caller drops the sample fail-closed).
fn key_for(labels: &[&'static str], values: &[&str]) -> Option<Vec<String>> {
    if values.len() != labels.len() {
        // Fail closed: a label arity mismatch is a programming error, but the
        // emission path must never unwind the mediation hot path, so drop the
        // sample rather than panic (even in debug/test builds).
        return None;
    }
    Some(values.iter().map(|value| (*value).to_string()).collect())
}

/// A process-global counter keyed by an ordered label tuple.
pub struct LabeledCounter {
    name: &'static str,
    labels: &'static [&'static str],
    cells: Mutex<BTreeMap<Vec<String>, Arc<AtomicU64>>>,
}

impl LabeledCounter {
    #[must_use]
    pub const fn new(name: &'static str, labels: &'static [&'static str]) -> Self {
        Self {
            name,
            labels,
            cells: Mutex::new(BTreeMap::new()),
        }
    }

    fn cell(&self, values: &[&str]) -> Option<Arc<AtomicU64>> {
        let key = key_for(self.labels, values)?;
        let mut cells = self.cells.lock().ok()?;
        Some(Arc::clone(
            cells
                .entry(key)
                .or_insert_with(|| Arc::new(AtomicU64::new(0))),
        ))
    }

    pub fn incr(&self, values: &[&str]) {
        self.incr_by(values, 1);
    }

    pub fn incr_by(&self, values: &[&str], delta: u64) {
        if let Some(cell) = self.cell(values) {
            cell.fetch_add(delta, Ordering::Relaxed);
        }
    }

    /// Seed the series at zero so it exists before its first event (RFC-0009
    /// contract rule 2). Idempotent: leaves an existing cell untouched.
    pub fn preregister(&self, values: &[&str]) {
        let _ = self.cell(values);
    }

    pub fn render(&self, out: &mut String) {
        render_header(out, self.name, "counter");
        let Ok(cells) = self.cells.lock() else { return };
        for (values, cell) in cells.iter() {
            out.push_str(&format!(
                "{}{} {}\n",
                self.name,
                render_label_set(self.labels, values),
                cell.load(Ordering::Relaxed)
            ));
        }
    }
}

/// A process-global gauge (set, not accumulate).
pub struct LabeledGauge {
    name: &'static str,
    labels: &'static [&'static str],
    cells: Mutex<BTreeMap<Vec<String>, Arc<AtomicU64>>>,
}

impl LabeledGauge {
    #[must_use]
    pub const fn new(name: &'static str, labels: &'static [&'static str]) -> Self {
        Self {
            name,
            labels,
            cells: Mutex::new(BTreeMap::new()),
        }
    }

    fn cell(&self, values: &[&str]) -> Option<Arc<AtomicU64>> {
        let key = key_for(self.labels, values)?;
        let mut cells = self.cells.lock().ok()?;
        Some(Arc::clone(
            cells
                .entry(key)
                .or_insert_with(|| Arc::new(AtomicU64::new(0))),
        ))
    }

    pub fn set(&self, values: &[&str], value: u64) {
        if let Some(cell) = self.cell(values) {
            cell.store(value, Ordering::Relaxed);
        }
    }

    pub fn preregister(&self, values: &[&str]) {
        let _ = self.cell(values);
    }

    pub fn render(&self, out: &mut String) {
        render_header(out, self.name, "gauge");
        let Ok(cells) = self.cells.lock() else { return };
        for (values, cell) in cells.iter() {
            out.push_str(&format!(
                "{}{} {}\n",
                self.name,
                render_label_set(self.labels, values),
                cell.load(Ordering::Relaxed)
            ));
        }
    }
}

struct HistogramCell {
    bucket_counts: Vec<AtomicU64>,
    sum_millis: AtomicU64,
    count: AtomicU64,
}

/// A process-global histogram over the registry-declared bucket bounds.
pub struct LabeledHistogram {
    name: &'static str,
    labels: &'static [&'static str],
    cells: Mutex<BTreeMap<Vec<String>, Arc<HistogramCell>>>,
}

impl LabeledHistogram {
    #[must_use]
    pub const fn new(name: &'static str, labels: &'static [&'static str]) -> Self {
        Self {
            name,
            labels,
            cells: Mutex::new(BTreeMap::new()),
        }
    }

    /// Numeric upper bounds parsed from the registry descriptor (string form).
    fn bounds(&self) -> Vec<f64> {
        descriptor_for(self.name)
            .map(|descriptor| {
                descriptor
                    .buckets
                    .iter()
                    .filter_map(|bound| bound.parse::<f64>().ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn cell(&self, values: &[&str], bucket_len: usize) -> Option<Arc<HistogramCell>> {
        let key = key_for(self.labels, values)?;
        let mut cells = self.cells.lock().ok()?;
        Some(Arc::clone(cells.entry(key).or_insert_with(|| {
            let mut bucket_counts = Vec::with_capacity(bucket_len + 1);
            for _ in 0..bucket_len + 1 {
                bucket_counts.push(AtomicU64::new(0));
            }
            Arc::new(HistogramCell {
                bucket_counts,
                sum_millis: AtomicU64::new(0),
                count: AtomicU64::new(0),
            })
        })))
    }

    pub fn observe(&self, values: &[&str], seconds: f64) {
        let bounds = self.bounds();
        let Some(cell) = self.cell(values, bounds.len()) else {
            return;
        };
        for (index, bound) in bounds.iter().enumerate() {
            if seconds <= *bound {
                if let Some(bucket) = cell.bucket_counts.get(index) {
                    bucket.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        // The +Inf bucket always counts.
        if let Some(inf) = cell.bucket_counts.last() {
            inf.fetch_add(1, Ordering::Relaxed);
        }
        cell.sum_millis.fetch_add(
            (seconds * 1000.0).round().max(0.0) as u64,
            Ordering::Relaxed,
        );
        cell.count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn preregister(&self, values: &[&str]) {
        let bounds = self.bounds();
        let _ = self.cell(values, bounds.len());
    }

    pub fn render(&self, out: &mut String) {
        render_header(out, self.name, "histogram");
        let bounds = self.bounds();
        let Ok(cells) = self.cells.lock() else { return };
        for (values, cell) in cells.iter() {
            let base = render_label_set(self.labels, values);
            let inner = base.trim_start_matches('{').trim_end_matches('}');
            let separator = if inner.is_empty() { "" } else { "," };
            for (index, bound) in bounds.iter().enumerate() {
                let value = cell
                    .bucket_counts
                    .get(index)
                    .map(|counter| counter.load(Ordering::Relaxed))
                    .unwrap_or(0);
                out.push_str(&format!(
                    "{}_bucket{{{inner}{separator}le=\"{bound}\"}} {value}\n",
                    self.name
                ));
            }
            let inf = cell
                .bucket_counts
                .last()
                .map(|counter| counter.load(Ordering::Relaxed))
                .unwrap_or(0);
            out.push_str(&format!(
                "{}_bucket{{{inner}{separator}le=\"+Inf\"}} {inf}\n",
                self.name
            ));
            let sum = cell.sum_millis.load(Ordering::Relaxed) as f64 / 1000.0;
            out.push_str(&format!("{}_sum{base} {sum}\n", self.name));
            out.push_str(&format!(
                "{}_count{base} {}\n",
                self.name,
                cell.count.load(Ordering::Relaxed)
            ));
        }
    }
}

/// Process-global family instances (RFC-0009 Part A). Their sole producers are
/// named in the design; renderers read them here. Names/labels are verified
/// against the registry descriptors this session.
pub mod families {
    use super::{LabeledCounter, LabeledGauge, LabeledHistogram};
    use crate::*;

    pub static FAIL_OPEN_SUSPECTED: LabeledCounter =
        LabeledCounter::new(CHIO_FAIL_OPEN_SUSPECTED_TOTAL, &["surface"]);
    pub static DISPATCH_FAILURE: LabeledCounter =
        LabeledCounter::new(CHIO_DISPATCH_FAILURE_TOTAL, &["surface", "outcome"]);
    pub static CAPABILITY_REVOCATION_LAG: LabeledHistogram =
        LabeledHistogram::new(CHIO_CAPABILITY_REVOCATION_LAG_SECONDS, &["authority"]);
    pub static DLQ_DEPTH: LabeledGauge = LabeledGauge::new(CHIO_DLQ_DEPTH, &["exporter"]);
    pub static SOC_EXPORT_TOTAL: LabeledCounter =
        LabeledCounter::new(CHIO_SOC_EXPORT_TOTAL, &["exporter", "outcome"]);
    pub static SOC_EXPORT_LAG: LabeledHistogram =
        LabeledHistogram::new(CHIO_SOC_EXPORT_LAG_SECONDS, &["exporter", "severity"]);
    pub static ALERT_DISPATCH_TOTAL: LabeledCounter =
        LabeledCounter::new(CHIO_ALERT_DISPATCH_TOTAL, &["route", "outcome"]);
    pub static ALERT_DISPATCH_LATENCY: LabeledHistogram =
        LabeledHistogram::new(CHIO_ALERT_DISPATCH_LATENCY_SECONDS, &["route", "outcome"]);

    pub static GUARD_VERDICT: LabeledCounter =
        LabeledCounter::new(CHIO_GUARD_VERDICT_TOTAL, &["guard_id", "verdict"]);
    pub static GUARD_DENY: LabeledCounter =
        LabeledCounter::new(CHIO_GUARD_DENY_TOTAL, &["guard_id", "reason_class"]);
    pub static GUARD_EVAL_DURATION: LabeledHistogram =
        LabeledHistogram::new(CHIO_GUARD_EVAL_DURATION_SECONDS, &["guard_id", "verdict"]);
    pub static GUARD_RELOAD: LabeledCounter =
        LabeledCounter::new(CHIO_GUARD_RELOAD_TOTAL, &["guard_id", "outcome"]);
    pub static GUARD_HOST_CALL_DURATION: LabeledHistogram = LabeledHistogram::new(
        CHIO_GUARD_HOST_CALL_DURATION_SECONDS,
        &["guard_id", "host_fn"],
    );
    pub static GUARD_FUEL_CONSUMED: LabeledCounter =
        LabeledCounter::new(CHIO_GUARD_FUEL_CONSUMED_TOTAL, &["guard_id"]);
    pub static GUARD_MODULE_BYTES: LabeledGauge =
        LabeledGauge::new(CHIO_GUARD_MODULE_BYTES, &["guard_id", "epoch"]);

    pub static OTEL_INGRESS_DROP: LabeledCounter =
        LabeledCounter::new(CHIO_OTEL_INGRESS_DROP_TOTAL, &[]);
    pub static OTEL_SINK_DROP: LabeledCounter = LabeledCounter::new(CHIO_OTEL_SINK_DROP_TOTAL, &[]);

    // Signing gains a `reason` label in Task 8 (descriptor edit); constructed
    // with the label here so the producer and renderer agree from the start.
    pub static SIGNING_QUEUE_BLOCK: LabeledCounter =
        LabeledCounter::new(CHIO_SIGNING_QUEUE_BLOCK_TOTAL, &["reason"]);

    // Receipt-log watchdog gauges (RFC-0009 F83). Producer: the serve-mode
    // watchdog loop sampling ReceiptStoreHealthReport; renderer: the kernel
    // /metrics endpoint.
    pub static RECEIPT_UNCHECKPOINTED_RANGE: LabeledGauge =
        LabeledGauge::new(CHIO_RECEIPT_UNCHECKPOINTED_SEQ_RANGE, &[]);
    pub static RECEIPT_CHECKPOINT_AGE_SECONDS: LabeledGauge =
        LabeledGauge::new(CHIO_RECEIPT_SECONDS_SINCE_LAST_CHECKPOINT, &[]);
}

/// Seed every KNOWN label set at zero once at startup so `absent_over_time`
/// alerts fire only on a true scrape gap, never on a healthy-but-quiet
/// deployment (RFC-0009 contract rule 2, the F57 Codex fix). Idempotent.
pub fn preregister_known_label_sets() {
    families::FAIL_OPEN_SUSPECTED.preregister(&["tower"]);
    families::DISPATCH_FAILURE.preregister(&["http_authority", "denied"]);
    families::DISPATCH_FAILURE.preregister(&["http_authority", "error"]);
    families::CAPABILITY_REVOCATION_LAG.preregister(&["control_plane"]);
    families::SIGNING_QUEUE_BLOCK.preregister(&["channel_full"]);
    families::SIGNING_QUEUE_BLOCK.preregister(&["byte_budget"]);
    families::SIGNING_QUEUE_BLOCK.preregister(&["oversized"]);
    families::OTEL_INGRESS_DROP.preregister(&[]);
    families::OTEL_SINK_DROP.preregister(&[]);
    // DLQ/SOC/alert-dispatch known exporters and routes are seeded by the SIEM
    // serve mode (Task 12) from configured exporter/backend names, because their
    // label domain is deployment-configured rather than fixed.
}

/// Render the 7 guard families the kernel `/metrics` endpoint owns. One
/// producer per family (chio-wasm-guards); the kernel only renders.
pub fn render_guard_families(out: &mut String) {
    families::GUARD_VERDICT.render(out);
    families::GUARD_DENY.render(out);
    families::GUARD_EVAL_DURATION.render(out);
    families::GUARD_RELOAD.render(out);
    families::GUARD_HOST_CALL_DURATION.render(out);
    families::GUARD_FUEL_CONSUMED.render(out);
    families::GUARD_MODULE_BYTES.render(out);
}

/// Render the 2 OTEL-drop families (producer: the OTLP ingress).
pub fn render_otel_drop_families(out: &mut String) {
    families::OTEL_INGRESS_DROP.render(out);
    families::OTEL_SINK_DROP.render(out);
}

/// Render the receipt-log watchdog gauges (producer: the serve-mode watchdog).
pub fn render_receipt_watchdog_gauges(out: &mut String) {
    families::RECEIPT_UNCHECKPOINTED_RANGE.render(out);
    families::RECEIPT_CHECKPOINT_AGE_SECONDS.render(out);
}

/// Render the alert-pack families that serving surfaces compose.
pub fn render_alert_pack_families(out: &mut String) {
    families::FAIL_OPEN_SUSPECTED.render(out);
    families::DISPATCH_FAILURE.render(out);
    families::CAPABILITY_REVOCATION_LAG.render(out);
    families::DLQ_DEPTH.render(out);
    families::SOC_EXPORT_TOTAL.render(out);
    families::SOC_EXPORT_LAG.render(out);
    families::ALERT_DISPATCH_TOTAL.render(out);
    families::ALERT_DISPATCH_LATENCY.render(out);
}

/// Concatenate render sources into one Prometheus text body.
#[must_use]
pub fn compose_metrics_body(sources: &[&dyn Fn() -> String]) -> String {
    let mut out = String::new();
    for source in sources {
        out.push_str(&source());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn counter_sums_concurrent_increments() {
        let counter = LabeledCounter::new(crate::CHIO_SOC_EXPORT_TOTAL, &["exporter", "outcome"]);
        let counter = Arc::new(counter);
        let mut handles = Vec::new();
        for _ in 0..8 {
            let counter = Arc::clone(&counter);
            handles.push(std::thread::spawn(move || {
                for _ in 0..1000 {
                    counter.incr(&["splunk", "ok"]);
                }
            }));
        }
        for handle in handles {
            let _ = handle.join();
        }
        let mut out = String::new();
        counter.render(&mut out);
        assert!(
            out.contains("chio_soc_export_total{exporter=\"splunk\",outcome=\"ok\"} 8000"),
            "unexpected render: {out}"
        );
    }

    #[test]
    fn render_emits_help_and_type_from_descriptor() {
        let counter = LabeledCounter::new(crate::CHIO_FAIL_OPEN_SUSPECTED_TOTAL, &["surface"]);
        counter.incr(&["tower"]);
        let mut out = String::new();
        counter.render(&mut out);
        assert!(out.contains("# HELP chio_fail_open_suspected_total"));
        assert!(out.contains("# TYPE chio_fail_open_suspected_total counter"));
        assert!(out.contains("chio_fail_open_suspected_total{surface=\"tower\"} 1"));
    }

    #[test]
    fn preregister_seeds_a_zero_series_before_first_event() {
        let counter =
            LabeledCounter::new(crate::CHIO_DISPATCH_FAILURE_TOTAL, &["surface", "outcome"]);
        counter.preregister(&["http_authority", "denied"]);
        let mut out = String::new();
        counter.render(&mut out);
        // The series exists at 0 so absent_over_time only fires on a real gap.
        assert!(
            out.contains(
                "chio_dispatch_failure_total{surface=\"http_authority\",outcome=\"denied\"} 0"
            ),
            "preregister must emit a zero series: {out}"
        );
    }

    #[test]
    fn arity_mismatch_drops_the_sample_without_panicking() {
        let counter = LabeledCounter::new(crate::CHIO_FAIL_OPEN_SUSPECTED_TOTAL, &["surface"]);
        // Two values for a one-label family: dropped, no panic, no series.
        counter.incr(&["tower", "extra"]);
        let mut out = String::new();
        counter.render(&mut out);
        assert!(
            !out.contains("surface=\"tower\""),
            "arity mismatch must not record: {out}"
        );
    }

    #[test]
    fn histogram_observes_into_registry_bucket_bounds() {
        let hist = LabeledHistogram::new(
            crate::CHIO_SOC_EXPORT_LAG_SECONDS,
            &["exporter", "severity"],
        );
        hist.observe(&["splunk", "info"], 45.0);
        let mut out = String::new();
        hist.render(&mut out);
        // 45.0 falls in the le="60" bucket (bounds 30,60,120,...). +Inf and count present.
        assert!(out.contains("chio_soc_export_lag_seconds_bucket{exporter=\"splunk\",severity=\"info\",le=\"60\"} 1"), "{out}");
        assert!(out.contains("chio_soc_export_lag_seconds_bucket{exporter=\"splunk\",severity=\"info\",le=\"30\"} 0"), "{out}");
        assert!(out.contains("chio_soc_export_lag_seconds_bucket{exporter=\"splunk\",severity=\"info\",le=\"+Inf\"} 1"), "{out}");
        assert!(
            out.contains(
                "chio_soc_export_lag_seconds_count{exporter=\"splunk\",severity=\"info\"} 1"
            ),
            "{out}"
        );
    }

    #[test]
    fn preregister_known_label_sets_seeds_fail_open_and_dispatch() {
        preregister_known_label_sets();
        let mut out = String::new();
        families::FAIL_OPEN_SUSPECTED.render(&mut out);
        families::DISPATCH_FAILURE.render(&mut out);
        assert!(
            out.contains("chio_fail_open_suspected_total{surface=\"tower\"} 0"),
            "{out}"
        );
        assert!(
            out.contains(
                "chio_dispatch_failure_total{surface=\"http_authority\",outcome=\"denied\"} 0"
            ),
            "{out}"
        );
        assert!(
            out.contains(
                "chio_dispatch_failure_total{surface=\"http_authority\",outcome=\"error\"} 0"
            ),
            "{out}"
        );
    }
}
