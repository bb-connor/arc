//! Latency for an admitted call and durable bytes per call.
//!
//! The same shape as the Chio local decomposition: repeated admitted calls
//! through the whole receiver path against one SQLite store in WAL with
//! `synchronous = FULL`, timing the path and reading the store's growth. Both
//! durability orderings are measured, because the difference between them is
//! the cost of putting the record before the response.

use crate::harness::Runner;
use crate::receiver::DurabilityMode;
use crate::request::ComposedEnvelope;
use crate::scenario::{self, Keys};
use crate::store::BaselineStore;
use serde::Serialize;
use std::path::Path;
use std::time::Instant;

#[derive(Debug, Clone, Serialize)]
pub struct LatencySummary {
    pub samples: usize,
    pub p50_us: f64,
    pub p99_us: f64,
    pub mean_us: f64,
    pub min_us: f64,
    pub max_us: f64,
    pub ci_low_us: f64,
    pub ci_high_us: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct MeasurementResult {
    pub profile: String,
    pub durability: String,
    pub calls: u64,
    pub dispatched: u64,
    /// The whole receiver path, durable append included.
    pub latency: LatencySummary,
    /// The path to the point the caller could be answered. Under
    /// `before_dispatch` this equals the whole path; under `after_dispatch` it
    /// stops before the audit append, and the difference between the two
    /// profiles is the cost of putting the record before the response.
    pub response_latency: LatencySummary,
    /// The checks alone: the span from the start of peer resolution to the end
    /// of rule evaluation, less the durable replay claims inside it. The
    /// argument digest, the decision parse, the record encoding and the record
    /// signature are outside it. This is the span in which the two wirings'
    /// checks differ.
    pub checks_latency: LatencySummary,
    /// The durable replay claims alone: one insert under the composed wiring,
    /// two under the hardened wiring. The difference between the two is the
    /// cost of claiming the authorization's own identifier, measured rather
    /// than inferred from two whole-path medians.
    pub claim_latency: LatencySummary,
    pub store_bytes_before: u64,
    pub store_bytes_after: u64,
    pub durable_bytes_per_call: f64,
    pub decision_record_bytes_p50: usize,
    pub request_wire_bytes: usize,
}

const BOOTSTRAP_RESAMPLES: usize = 10_000;
const BOOTSTRAP_SEED: u64 = 1;
const CONFIDENCE: f64 = 0.95;

fn percentile(ordered: &[f64], quantile: f64) -> Result<f64, String> {
    if ordered.is_empty() {
        return Err("cannot take a percentile of an empty sample".to_string());
    }
    let position = quantile * ((ordered.len() - 1) as f64);
    let lower = position.floor() as usize;
    let upper = position.ceil() as usize;
    if lower == upper {
        return Ok(ordered[lower]);
    }
    let weight = position - (lower as f64);
    Ok(ordered[lower] * (1.0 - weight) + ordered[upper] * weight)
}

/// xorshift64star, so the interval is reproducible without a dependency.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn index(&mut self, bound: usize) -> usize {
        (self.next_u64() % (bound as u64)) as usize
    }
}

fn bootstrap_ci(values: &[f64]) -> Result<(f64, f64), String> {
    if values.len() < 2 {
        return Err("a summary needs at least two observations".to_string());
    }
    let mut rng = Rng(BOOTSTRAP_SEED.max(1));
    let count = values.len();
    let mut means = Vec::with_capacity(BOOTSTRAP_RESAMPLES);
    for _ in 0..BOOTSTRAP_RESAMPLES {
        let mut total = 0.0f64;
        for _ in 0..count {
            total += values[rng.index(count)];
        }
        means.push(total / (count as f64));
    }
    means.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let alpha = (1.0 - CONFIDENCE) / 2.0;
    Ok((percentile(&means, alpha)?, percentile(&means, 1.0 - alpha)?))
}

pub fn summarize(values: &[f64]) -> Result<LatencySummary, String> {
    if values.len() < 2 {
        return Err("a latency summary needs at least two observations".to_string());
    }
    let mut ordered = values.to_vec();
    ordered.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let sum: f64 = ordered.iter().sum();
    let (ci_low, ci_high) = bootstrap_ci(&ordered)?;
    Ok(LatencySummary {
        samples: ordered.len(),
        p50_us: percentile(&ordered, 0.50)?,
        p99_us: percentile(&ordered, 0.99)?,
        mean_us: sum / (ordered.len() as f64),
        min_us: ordered[0],
        max_us: ordered[ordered.len() - 1],
        ci_low_us: ci_low,
        ci_high_us: ci_high,
    })
}

fn store_bytes(path: &Path) -> u64 {
    let mut total = 0u64;
    for suffix in ["", "-wal", "-shm"] {
        let candidate = if suffix.is_empty() {
            path.to_path_buf()
        } else {
            let mut name = path.as_os_str().to_os_string();
            name.push(suffix);
            std::path::PathBuf::from(name)
        };
        if let Ok(metadata) = std::fs::metadata(&candidate) {
            total += metadata.len();
        }
    }
    total
}

/// Drive `calls` admitted calls through one receiver and one store.
pub fn measure(
    keys: &Keys,
    runner: &Runner<'_>,
    root: &Path,
    calls: u64,
    warmup: u64,
) -> Result<MeasurementResult, String> {
    if calls < 2 {
        return Err("a measurement needs at least two calls".to_string());
    }
    let state = runner.state(crate::harness::StateVariant::Default);
    let path = root.join(format!(
        "measure-{}-{}.sqlite",
        runner.profile.as_str(),
        match runner.durability {
            DurabilityMode::BeforeDispatch => "before",
            DurabilityMode::AfterDispatch => "after",
        }
    ));
    let _ = std::fs::remove_file(&path);
    let store = BaselineStore::open(&path).map_err(|error| error.to_string())?;

    let envelopes: Vec<ComposedEnvelope> = (0..(calls + warmup))
        .map(|index| scenario::admissible(keys, format!("measure-{index}").as_str()))
        .collect::<Result<Vec<_>, String>>()?;

    let request_wire_bytes = envelopes
        .first()
        .ok_or_else(|| "no envelopes were built".to_string())?
        .request
        .wire_bytes()
        .map_err(|error| error.to_string())?;

    for envelope in envelopes.iter().take(warmup as usize) {
        let outcome = runner
            .admit(&state, &store, envelope, scenario::NOW_MS)
            .map_err(|error| error.to_string())?;
        if !outcome.dispatched {
            return Err(format!(
                "a warmup call was not dispatched: {:?}",
                outcome.denial_code
            ));
        }
    }

    store.checkpoint().map_err(|error| error.to_string())?;
    let before = store_bytes(&path);

    let mut samples = Vec::with_capacity(calls as usize);
    let mut response_samples = Vec::with_capacity(calls as usize);
    let mut checks_samples = Vec::with_capacity(calls as usize);
    let mut claim_samples = Vec::with_capacity(calls as usize);
    let mut record_bytes = Vec::with_capacity(calls as usize);
    let mut dispatched = 0u64;
    for envelope in envelopes.iter().skip(warmup as usize) {
        let started = Instant::now();
        let outcome = runner
            .admit(&state, &store, envelope, scenario::NOW_MS)
            .map_err(|error| error.to_string())?;
        let elapsed = started.elapsed();
        if !outcome.dispatched {
            return Err(format!(
                "a measured call was not dispatched: {:?}",
                outcome.denial_code
            ));
        }
        dispatched += 1;
        samples.push(elapsed.as_secs_f64() * 1_000_000.0);
        response_samples.push(outcome.response_ready.as_secs_f64() * 1_000_000.0);
        checks_samples.push(outcome.checks.as_secs_f64() * 1_000_000.0);
        claim_samples.push(outcome.durable_claims.as_secs_f64() * 1_000_000.0);
        record_bytes.push(outcome.decision_record_bytes);
    }

    store.checkpoint().map_err(|error| error.to_string())?;
    let after = store_bytes(&path);
    let logged = store.decision_count().map_err(|error| error.to_string())?;
    if logged != calls + warmup {
        return Err(format!(
            "the decision log holds {logged} records for {} calls; refusing to report a per-call cost",
            calls + warmup
        ));
    }

    record_bytes.sort_unstable();
    let median_record = record_bytes[record_bytes.len() / 2];

    Ok(MeasurementResult {
        profile: runner.profile.as_str().to_string(),
        durability: match runner.durability {
            DurabilityMode::BeforeDispatch => "before_dispatch".to_string(),
            DurabilityMode::AfterDispatch => "after_dispatch".to_string(),
        },
        calls,
        dispatched,
        latency: summarize(&samples)?,
        response_latency: summarize(&response_samples)?,
        checks_latency: summarize(&checks_samples)?,
        claim_latency: summarize(&claim_samples)?,
        store_bytes_before: before,
        store_bytes_after: after,
        durable_bytes_per_call: ((after.saturating_sub(before)) as f64) / (calls as f64),
        decision_record_bytes_p50: median_record,
        request_wire_bytes,
    })
}
