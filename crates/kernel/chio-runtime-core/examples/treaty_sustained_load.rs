//! Sustained admitted treaty load, swept over the number of calls held in flight.
//!
//! ```text
//! cargo run --release -p chio-runtime-core --example treaty_sustained_load -- \
//!     --seconds 60 --out sustained.json
//! ```
//!
//! Every call goes through the same receiver kernel as the
//! `treaty_predispatch_allow` benchmark: store resolution, treaty binding
//! checks, both Ed25519 verifications, continuation and lease consumption,
//! pre-dispatch revalidation, dispatch, the signed allow receipt in SQLite,
//! and the in-process bilateral co-signature. Each call also carries its
//! origin-side setup (a fresh continuation, lineage, invocation, and signed
//! DSSE envelope), so calls per second is wall-clock throughput of the whole
//! exchange.
//!
//! One worker thread drives one private admission path: its own receiver
//! kernel over its own SQLite receipt store. The concurrency sweep runs the
//! ladder of in-flight counts for a short hold each, picks the count that
//! produced the highest throughput, and then holds that count for the full
//! requested duration. Throughput is reported against the wall clock of the
//! hold, alongside the in-flight count that produced it and the peak number of
//! calls the run actually had outstanding at once.
//!
//! The sweep, the per-stage latency split, and the core count are all written
//! to the report so the limiting resource is read off the measurements rather
//! than assumed. Every median carries a percentile bootstrap interval.
//!
//! The program exits nonzero when any call is denied, when the tool server did
//! not run exactly once per call, or when a phase could not hold the number of
//! calls in flight it asked for.

#[path = "../benches/fixtures/treaty_admission_allow_fixture.rs"]
mod treaty_admission_allow_fixture;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use treaty_admission_allow_fixture::{CallOutcome, TreatyPredispatchAllowFixture};

const USAGE: &str = concat!(
    "usage: treaty_sustained_load --seconds <N> --out <path.json>\n",
    "                            [--sweep-seconds <N>] [--concurrency <N[,N...]>]\n",
    "                            [--store-dir <path>]\n",
    "The concurrency ladder always includes one call in flight as the baseline."
);

/// Hold for each sweep point when `--sweep-seconds` is absent.
const DEFAULT_SWEEP_SECONDS: u64 = 5;
/// Largest in-flight count a derived ladder will reach.
const MAX_DEFAULT_CONCURRENCY: usize = 32;
/// Resamples behind every reported median interval.
const BOOTSTRAP_RESAMPLES: usize = 1_000;
const BOOTSTRAP_SEED: u64 = 1;
/// Observations a median interval resamples. Runs that collect more are
/// subsampled, which widens the interval rather than narrowing it.
const BOOTSTRAP_MAX_OBSERVATIONS: usize = 20_000;
const CONFIDENCE: f64 = 0.95;
/// Share of peak throughput a sweep point must reach to count as the knee.
const KNEE_SHARE_OF_PEAK: f64 = 0.95;
/// Scaling efficiency at the peak above which the host CPU is the limit.
const CPU_BOUND_EFFICIENCY: f64 = 0.7;
/// Longest wait for every worker to finish building its admission path.
const READY_TIMEOUT: Duration = Duration::from_secs(600);

type BoxError = Box<dyn std::error::Error>;

struct Options {
    seconds: u64,
    sweep_seconds: u64,
    concurrency: Vec<usize>,
    store_dir: Option<PathBuf>,
    out: PathBuf,
}

fn parse_positive(value: &OsString, flag: &str) -> Result<u64, String> {
    value
        .to_str()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| format!("{flag} needs a positive integer"))
}

fn parse_concurrency(value: &OsString) -> Result<Vec<usize>, String> {
    let text = value
        .to_str()
        .ok_or_else(|| "--concurrency needs a comma separated list".to_string())?;
    let mut levels = vec![1_usize];
    for field in text.split(',') {
        let level = field
            .trim()
            .parse::<usize>()
            .ok()
            .filter(|level| *level > 0)
            .ok_or_else(|| format!("--concurrency holds a nonpositive level: {field}"))?;
        levels.push(level);
    }
    levels.sort_unstable();
    levels.dedup();
    Ok(levels)
}

fn parse_options(mut args: impl Iterator<Item = OsString>) -> Result<Options, String> {
    let mut seconds = None;
    let mut sweep_seconds = None;
    let mut concurrency = None;
    let mut store_dir = None;
    let mut out = None;
    while let Some(flag) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("{} needs a value", flag.to_string_lossy()))?;
        match flag.to_str() {
            Some("--seconds") => seconds = Some(parse_positive(&value, "--seconds")?),
            Some("--sweep-seconds") => {
                sweep_seconds = Some(parse_positive(&value, "--sweep-seconds")?);
            }
            Some("--concurrency") => concurrency = Some(parse_concurrency(&value)?),
            Some("--store-dir") => store_dir = Some(PathBuf::from(value)),
            Some("--out") => out = Some(PathBuf::from(value)),
            _ => return Err(format!("unknown flag {}", flag.to_string_lossy())),
        }
    }
    Ok(Options {
        seconds: seconds.ok_or_else(|| "--seconds is required".to_string())?,
        sweep_seconds: sweep_seconds.unwrap_or(DEFAULT_SWEEP_SECONDS),
        concurrency: concurrency.unwrap_or_else(|| default_concurrency(host_cores())),
        store_dir,
        out: out.ok_or_else(|| "--out is required".to_string())?,
    })
}

fn host_cores() -> usize {
    std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1)
}

/// Powers of two from one call in flight to one step past the core count, so
/// the curve carries at least one point on either side of the knee.
fn default_concurrency(cores: usize) -> Vec<usize> {
    let mut ladder = vec![1_usize];
    let mut level = 2_usize;
    while level <= cores.max(1) && level <= MAX_DEFAULT_CONCURRENCY {
        ladder.push(level);
        level = level.saturating_mul(2);
    }
    if level <= MAX_DEFAULT_CONCURRENCY {
        ladder.push(level);
    }
    ladder
}

// ---- Statistics ------------------------------------------------------------

/// Deterministic generator so a rerun reproduces the reported intervals.
struct SplitMix64(u64);

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut word = self.0;
        word = (word ^ (word >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        word = (word ^ (word >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        word ^ (word >> 31)
    }

    fn below(&mut self, bound: usize) -> Result<usize, String> {
        if bound == 0 {
            return Err("cannot draw from an empty range".to_string());
        }
        Ok((self.next_u64() % bound as u64) as usize)
    }
}

/// Linear interpolation between order statistics, matching the aggregation the
/// benchmark script applies to the component and workflow samples.
fn percentile(ordered: &[f64], quantile: f64) -> Result<f64, String> {
    let last = ordered
        .len()
        .checked_sub(1)
        .ok_or_else(|| "cannot take a percentile of an empty sample".to_string())?;
    let position = quantile * last as f64;
    let lower = position.floor() as usize;
    let upper = position.ceil() as usize;
    let low = *ordered
        .get(lower)
        .ok_or_else(|| "percentile index is out of range".to_string())?;
    let high = *ordered
        .get(upper)
        .ok_or_else(|| "percentile index is out of range".to_string())?;
    if lower == upper {
        return Ok(low);
    }
    let weight = position - lower as f64;
    Ok(low * (1.0 - weight) + high * weight)
}

/// Median of an unordered slice, by selection rather than a full sort.
fn median_in_place(values: &mut [f64]) -> Result<f64, String> {
    let last = values
        .len()
        .checked_sub(1)
        .ok_or_else(|| "cannot take the median of an empty sample".to_string())?;
    let position = 0.5 * last as f64;
    let lower = position.floor() as usize;
    let upper = position.ceil() as usize;
    let (_, at_lower, above) = values.select_nth_unstable_by(lower, f64::total_cmp);
    let low = *at_lower;
    if lower == upper {
        return Ok(low);
    }
    let high = above.iter().copied().fold(f64::INFINITY, f64::min);
    Ok(0.5 * (low + high))
}

fn mean(values: &[f64]) -> Result<f64, String> {
    if values.is_empty() {
        return Err("cannot take the mean of an empty sample".to_string());
    }
    Ok(values.iter().sum::<f64>() / values.len() as f64)
}

/// Percentile bootstrap interval for the median of `values`.
fn median_interval(values: &[f64]) -> Result<(f64, f64), String> {
    let mut rng = SplitMix64::new(BOOTSTRAP_SEED);
    let mut pool = values.to_vec();
    let draw = pool.len().min(BOOTSTRAP_MAX_OBSERVATIONS);
    for index in 0..draw {
        let remaining = pool.len() - index;
        let pick = index + rng.below(remaining)?;
        pool.swap(index, pick);
    }
    pool.truncate(draw);
    let mut replicate = vec![0.0_f64; draw];
    let mut medians = Vec::with_capacity(BOOTSTRAP_RESAMPLES);
    for _ in 0..BOOTSTRAP_RESAMPLES {
        for slot in replicate.iter_mut() {
            let pick = rng.below(draw)?;
            *slot = *pool
                .get(pick)
                .ok_or_else(|| "resample index is out of range".to_string())?;
        }
        medians.push(median_in_place(&mut replicate)?);
    }
    medians.sort_by(f64::total_cmp);
    let alpha = (1.0 - CONFIDENCE) / 2.0;
    Ok((
        percentile(&medians, alpha)?,
        percentile(&medians, 1.0 - alpha)?,
    ))
}

struct Summary {
    samples: usize,
    p50: f64,
    p50_ci_low: f64,
    p50_ci_high: f64,
    p90: f64,
    p99: f64,
    mean: f64,
    min: f64,
    max: f64,
}

fn summarize_us(samples_ns: &[u64]) -> Result<Summary, String> {
    if samples_ns.len() < 2 {
        return Err("a summary needs at least two observations".to_string());
    }
    let values: Vec<f64> = samples_ns.iter().map(|ns| *ns as f64 / 1000.0).collect();
    let (p50_ci_low, p50_ci_high) = median_interval(&values)?;
    let mut ordered = values;
    ordered.sort_by(f64::total_cmp);
    Ok(Summary {
        samples: ordered.len(),
        p50: percentile(&ordered, 0.50)?,
        p50_ci_low,
        p50_ci_high,
        p90: percentile(&ordered, 0.90)?,
        p99: percentile(&ordered, 0.99)?,
        mean: mean(&ordered)?,
        min: percentile(&ordered, 0.0)?,
        max: percentile(&ordered, 1.0)?,
    })
}

fn summary_json(summary: &Summary) -> serde_json::Value {
    serde_json::json!({
        "samples": summary.samples,
        "p50_us": summary.p50,
        "p50_ci_low_us": summary.p50_ci_low,
        "p50_ci_high_us": summary.p50_ci_high,
        "p90_us": summary.p90,
        "p99_us": summary.p99,
        "mean_us": summary.mean,
        "min_us": summary.min,
        "max_us": summary.max,
    })
}

// ---- Load engine -----------------------------------------------------------

/// One call's wall-clock cost, split into origin-side setup and receiver
/// admission.
struct CallTiming {
    prepare: Duration,
    evaluate: Duration,
    denial: Option<String>,
}

/// One private admission path driven by a single worker.
trait AdmissionPath {
    /// Runs one whole exchange: origin-side setup, then receiver admission.
    fn call(&mut self) -> Result<CallTiming, String>;
    /// Calls this path has run since it was built.
    fn calls(&self) -> u64;
    /// Tool dispatches this path has made since it was built.
    fn dispatches(&self) -> u64;
    /// Bytes the path's receipt store occupies right now.
    fn receipt_store_bytes(&self) -> u64;
}

struct WorkerOutcome {
    calls: u64,
    dispatches: u64,
    denials: u64,
    first_denial: Option<String>,
    latency_ns: Vec<u64>,
    prepare_ns: Vec<u64>,
    evaluate_ns: Vec<u64>,
    receipt_store_bytes_before: u64,
    receipt_store_bytes_after: u64,
}

struct Phase {
    concurrency: usize,
    requested_seconds: u64,
    elapsed: Duration,
    calls: u64,
    dispatches: u64,
    denials: u64,
    first_denial: Option<String>,
    in_flight_peak: usize,
    latency: Summary,
    prepare: Summary,
    evaluate: Summary,
    receipt_store_bytes_before: u64,
    receipt_store_bytes_after: u64,
}

impl Phase {
    fn calls_per_second(&self) -> f64 {
        self.calls as f64 / self.elapsed.as_secs_f64()
    }

    fn receipt_store_bytes_per_second(&self) -> f64 {
        self.receipt_store_bytes_after
            .saturating_sub(self.receipt_store_bytes_before) as f64
            / self.elapsed.as_secs_f64()
    }
}

fn drive_worker<P: AdmissionPath>(
    path: &mut P,
    stop: &AtomicBool,
    in_flight: &AtomicUsize,
    in_flight_peak: &AtomicUsize,
) -> Result<WorkerOutcome, String> {
    let receipt_store_bytes_before = path.receipt_store_bytes();
    let mut denials = 0_u64;
    let mut first_denial = None;
    let mut latency_ns = Vec::new();
    let mut prepare_ns = Vec::new();
    let mut evaluate_ns = Vec::new();
    while !stop.load(Ordering::Relaxed) {
        let entered = in_flight.fetch_add(1, Ordering::Relaxed) + 1;
        in_flight_peak.fetch_max(entered, Ordering::Relaxed);
        let timing = path.call();
        in_flight.fetch_sub(1, Ordering::Relaxed);
        let timing = timing?;
        if let Some(failure_code) = timing.denial {
            denials += 1;
            if first_denial.is_none() {
                first_denial = Some(failure_code);
            }
        }
        let prepare = u64::try_from(timing.prepare.as_nanos()).unwrap_or(u64::MAX);
        let evaluate = u64::try_from(timing.evaluate.as_nanos()).unwrap_or(u64::MAX);
        prepare_ns.push(prepare);
        evaluate_ns.push(evaluate);
        latency_ns.push(prepare.saturating_add(evaluate));
    }
    Ok(WorkerOutcome {
        calls: path.calls(),
        dispatches: path.dispatches(),
        denials,
        first_denial,
        latency_ns,
        prepare_ns,
        evaluate_ns,
        receipt_store_bytes_before,
        receipt_store_bytes_after: path.receipt_store_bytes(),
    })
}

/// Holds `concurrency` calls in flight for `hold`, one worker thread per call,
/// and returns what the wall clock saw.
fn run_phase<P, B>(concurrency: usize, hold: Duration, build: B) -> Result<Phase, String>
where
    P: AdmissionPath,
    B: Fn(usize) -> Result<P, String> + Sync,
{
    if concurrency == 0 {
        return Err("a phase needs at least one call in flight".to_string());
    }
    let ready = AtomicUsize::new(0);
    let go = AtomicBool::new(false);
    let stop = AtomicBool::new(false);
    let in_flight = AtomicUsize::new(0);
    let in_flight_peak = AtomicUsize::new(0);
    let build = &build;

    let (outcomes, elapsed) = std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(concurrency);
        for worker in 0..concurrency {
            let ready = &ready;
            let go = &go;
            let stop = &stop;
            let in_flight = &in_flight;
            let in_flight_peak = &in_flight_peak;
            handles.push(scope.spawn(move || {
                let built = build(worker);
                ready.fetch_add(1, Ordering::SeqCst);
                while !go.load(Ordering::Acquire) {
                    std::thread::yield_now();
                }
                let mut path = built?;
                drive_worker(&mut path, stop, in_flight, in_flight_peak)
            }));
        }

        let ready_deadline = Instant::now() + READY_TIMEOUT;
        while ready.load(Ordering::SeqCst) < concurrency && Instant::now() < ready_deadline {
            std::thread::yield_now();
        }
        go.store(true, Ordering::Release);
        let started = Instant::now();
        std::thread::sleep(hold);
        stop.store(true, Ordering::Relaxed);
        let mut outcomes = Vec::with_capacity(concurrency);
        for handle in handles {
            outcomes.push(
                handle
                    .join()
                    .map_err(|_| "a load worker panicked".to_string()),
            );
        }
        (outcomes, started.elapsed())
    });

    let mut calls = 0_u64;
    let mut dispatches = 0_u64;
    let mut denials = 0_u64;
    let mut first_denial = None;
    let mut latency_ns = Vec::new();
    let mut prepare_ns = Vec::new();
    let mut evaluate_ns = Vec::new();
    let mut receipt_store_bytes_before = 0_u64;
    let mut receipt_store_bytes_after = 0_u64;
    for outcome in outcomes {
        let outcome = outcome??;
        calls = calls.saturating_add(outcome.calls);
        dispatches = dispatches.saturating_add(outcome.dispatches);
        denials = denials.saturating_add(outcome.denials);
        if first_denial.is_none() {
            first_denial = outcome.first_denial;
        }
        latency_ns.extend_from_slice(&outcome.latency_ns);
        prepare_ns.extend_from_slice(&outcome.prepare_ns);
        evaluate_ns.extend_from_slice(&outcome.evaluate_ns);
        receipt_store_bytes_before =
            receipt_store_bytes_before.saturating_add(outcome.receipt_store_bytes_before);
        receipt_store_bytes_after =
            receipt_store_bytes_after.saturating_add(outcome.receipt_store_bytes_after);
    }
    let in_flight_peak = in_flight_peak.load(Ordering::Relaxed);
    if in_flight_peak != concurrency {
        return Err(format!(
            "the phase asked for {concurrency} calls in flight but never held more than {in_flight_peak}"
        ));
    }

    Ok(Phase {
        concurrency,
        requested_seconds: hold.as_secs(),
        elapsed,
        calls,
        dispatches,
        denials,
        first_denial,
        in_flight_peak,
        latency: summarize_us(&latency_ns)?,
        prepare: summarize_us(&prepare_ns)?,
        evaluate: summarize_us(&evaluate_ns)?,
        receipt_store_bytes_before,
        receipt_store_bytes_after,
    })
}

fn phase_json(phase: &Phase) -> serde_json::Value {
    serde_json::json!({
        "concurrency": phase.concurrency,
        "requested_seconds": phase.requested_seconds,
        "elapsed_seconds": phase.elapsed.as_secs_f64(),
        "calls": phase.calls,
        "calls_per_second": phase.calls_per_second(),
        "dispatch_count": phase.dispatches,
        "denials": phase.denials,
        "in_flight_peak": phase.in_flight_peak,
        "latency_us": summary_json(&phase.latency),
        "prepare_us": summary_json(&phase.prepare),
        "evaluate_us": summary_json(&phase.evaluate),
        "receipt_store_bytes_before": phase.receipt_store_bytes_before,
        "receipt_store_bytes_after": phase.receipt_store_bytes_after,
    })
}

// ---- Reading the limit off the sweep ---------------------------------------

/// What the sweep says about the resource that stops throughput from rising.
struct Bottleneck {
    classification: &'static str,
    peak_concurrency: usize,
    knee_concurrency: usize,
    cores: usize,
    speedup_at_peak: f64,
    efficiency_at_peak: f64,
    efficiency_at_knee: f64,
    latency_growth_at_peak: f64,
    dominant_stage: &'static str,
    dominant_stage_share: f64,
    sweep_truncated: bool,
}

/// The highest-throughput sweep point, taking the fewest calls in flight when
/// two points tie.
fn peak_point(sweep: &[Phase]) -> Result<&Phase, String> {
    let mut peak: Option<&Phase> = None;
    for phase in sweep {
        let better = match peak {
            None => true,
            Some(current) => {
                let rate = phase.calls_per_second();
                let held = current.calls_per_second();
                rate > held || (rate >= held && phase.concurrency < current.concurrency)
            }
        };
        if better {
            peak = Some(phase);
        }
    }
    peak.ok_or_else(|| "the concurrency sweep produced no points".to_string())
}

fn classify(sweep: &[Phase], cores: usize) -> Result<Bottleneck, String> {
    let baseline = sweep
        .iter()
        .find(|phase| phase.concurrency == 1)
        .ok_or_else(|| "the concurrency sweep lacks its one-call-in-flight baseline".to_string())?;
    let baseline_rate = baseline.calls_per_second();
    if baseline_rate <= 0.0 {
        return Err("the one-call-in-flight baseline admitted nothing".to_string());
    }
    let peak = peak_point(sweep)?;
    let peak_rate = peak.calls_per_second();
    let knee = sweep
        .iter()
        .filter(|phase| phase.calls_per_second() >= KNEE_SHARE_OF_PEAK * peak_rate)
        .min_by_key(|phase| phase.concurrency)
        .unwrap_or(peak);
    let largest = sweep
        .iter()
        .map(|phase| phase.concurrency)
        .max()
        .unwrap_or(peak.concurrency);
    let speedup_at_peak = peak_rate / baseline_rate;
    let efficiency_at_peak = speedup_at_peak / peak.concurrency as f64;
    let sweep_truncated = peak.concurrency == largest && largest > 1;
    let evaluate_share =
        peak.evaluate.p50 / (peak.evaluate.p50 + peak.prepare.p50).max(f64::MIN_POSITIVE);
    let (dominant_stage, dominant_stage_share) = if evaluate_share >= 0.5 {
        ("evaluate", evaluate_share)
    } else {
        ("prepare", 1.0 - evaluate_share)
    };
    let classification = if peak.concurrency == 1 {
        // Extra calls in flight bought nothing, so one resource carries them all.
        "serialized"
    } else if sweep_truncated {
        // Throughput was still climbing at the last point on the ladder.
        "undetermined_sweep_truncated"
    } else if efficiency_at_peak >= CPU_BOUND_EFFICIENCY && peak.concurrency >= cores {
        // Scaling tracked the core count all the way to it.
        "host_cpu"
    } else {
        // Throughput flattened well below the core count.
        "contended"
    };
    Ok(Bottleneck {
        classification,
        peak_concurrency: peak.concurrency,
        knee_concurrency: knee.concurrency,
        cores,
        speedup_at_peak,
        efficiency_at_peak,
        efficiency_at_knee: knee.calls_per_second() / baseline_rate / knee.concurrency as f64,
        latency_growth_at_peak: peak.latency.p50 / baseline.latency.p50.max(f64::MIN_POSITIVE),
        dominant_stage,
        dominant_stage_share,
        sweep_truncated,
    })
}

fn bottleneck_json(bottleneck: &Bottleneck, hold: &Phase) -> serde_json::Value {
    serde_json::json!({
        "classification": bottleneck.classification,
        "peak_concurrency": bottleneck.peak_concurrency,
        "knee_concurrency": bottleneck.knee_concurrency,
        "cores": bottleneck.cores,
        "speedup_at_peak": bottleneck.speedup_at_peak,
        "efficiency_at_peak": bottleneck.efficiency_at_peak,
        "efficiency_at_knee": bottleneck.efficiency_at_knee,
        "latency_growth_at_peak": bottleneck.latency_growth_at_peak,
        "dominant_stage": bottleneck.dominant_stage,
        "dominant_stage_share": bottleneck.dominant_stage_share,
        "sweep_truncated": bottleneck.sweep_truncated,
        "receipt_store_bytes_per_second": hold.receipt_store_bytes_per_second(),
    })
}

// ---- The measured path -----------------------------------------------------

/// Size of the SQLite database plus its `-wal` and `-shm` files when present.
fn receipt_store_bytes(database: &Path) -> u64 {
    ["", "-wal", "-shm"]
        .into_iter()
        .map(|suffix| {
            let mut path = database.as_os_str().to_owned();
            path.push(suffix);
            std::fs::metadata(path)
                .map(|metadata| metadata.len())
                .unwrap_or(0)
        })
        .sum()
}

struct KernelAdmissionPath {
    fixture: TreatyPredispatchAllowFixture,
    database: PathBuf,
    calls_before: u64,
    dispatches_before: u64,
}

impl KernelAdmissionPath {
    fn new(database: PathBuf) -> Result<Self, String> {
        if let Some(parent) = database.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
        }
        let fixture = TreatyPredispatchAllowFixture::new(&database)
            .map_err(|error| format!("cannot build the admission path: {error}"))?;
        let calls_before = fixture.calls();
        let dispatches_before = fixture.tool_invocations();
        Ok(Self {
            fixture,
            database,
            calls_before,
            dispatches_before,
        })
    }
}

impl AdmissionPath for KernelAdmissionPath {
    fn call(&mut self) -> Result<CallTiming, String> {
        let prepare_started = Instant::now();
        let request = self
            .fixture
            .prepare_request()
            .map_err(|error| format!("origin-side setup failed: {error}"))?;
        let prepare = prepare_started.elapsed();
        let evaluate_started = Instant::now();
        let outcome = self
            .fixture
            .evaluate_once(&request)
            .map_err(|error| format!("{error}"))?;
        let evaluate = evaluate_started.elapsed();
        Ok(CallTiming {
            prepare,
            evaluate,
            denial: match outcome {
                CallOutcome::Admitted => None,
                CallOutcome::Denied { failure_code } => Some(failure_code),
            },
        })
    }

    fn calls(&self) -> u64 {
        self.fixture.calls().saturating_sub(self.calls_before)
    }

    fn dispatches(&self) -> u64 {
        self.fixture
            .tool_invocations()
            .saturating_sub(self.dispatches_before)
    }

    fn receipt_store_bytes(&self) -> u64 {
        receipt_store_bytes(&self.database)
    }
}

struct Report {
    hold: Phase,
    sweep: Vec<Phase>,
    bottleneck: Bottleneck,
}

fn check_phase(phase: &Phase, label: &str) -> Result<(), String> {
    if phase.denials != 0 {
        let code = phase.first_denial.as_deref().unwrap_or("unknown");
        return Err(format!(
            "{label} recorded {} denials, the first with failure code {code}",
            phase.denials
        ));
    }
    if phase.dispatches != phase.calls {
        return Err(format!(
            "{label} made {} dispatches over {} calls",
            phase.dispatches, phase.calls
        ));
    }
    Ok(())
}

/// Runs one phase over its own throwaway receipt stores.
fn measure(root: &Path, label: &str, concurrency: usize, hold: Duration) -> Result<Phase, String> {
    let phase_root = root.join(label);
    let phase = run_phase(concurrency, hold, |worker| {
        KernelAdmissionPath::new(phase_root.join(format!("worker-{worker}/receipts.sqlite3")))
    });
    let removal = std::fs::remove_dir_all(&phase_root);
    let phase = phase?;
    removal.map_err(|error| format!("cannot clear {}: {error}", phase_root.display()))?;
    check_phase(&phase, label)?;
    Ok(phase)
}

fn run(options: &Options) -> Result<Report, BoxError> {
    let held;
    let root = match &options.store_dir {
        Some(path) => {
            std::fs::create_dir_all(path)?;
            path.clone()
        }
        None => {
            held = tempfile::tempdir()?;
            held.path().to_path_buf()
        }
    };
    let cores = host_cores();
    let sweep_hold = Duration::from_secs(options.sweep_seconds);
    let mut sweep = Vec::with_capacity(options.concurrency.len());
    for concurrency in &options.concurrency {
        let phase = measure(
            &root,
            &format!("sweep-{concurrency}"),
            *concurrency,
            sweep_hold,
        )?;
        eprintln!(
            "sweep: {concurrency} in flight, {} calls in {:.1} s ({:.1} calls/s, p50 {:.1} ms)",
            phase.calls,
            phase.elapsed.as_secs_f64(),
            phase.calls_per_second(),
            phase.latency.p50 / 1000.0
        );
        sweep.push(phase);
    }
    let bottleneck = classify(&sweep, cores)?;
    let hold = measure(
        &root,
        "hold",
        bottleneck.peak_concurrency,
        Duration::from_secs(options.seconds),
    )?;
    Ok(Report {
        hold,
        sweep,
        bottleneck,
    })
}

fn write_report(path: &Path, report: &Report) -> Result<(), BoxError> {
    let hold = &report.hold;
    let json = serde_json::json!({
        "seconds": hold.requested_seconds,
        "calls": hold.calls,
        "calls_per_second": hold.calls_per_second(),
        "dispatch_count": hold.dispatches,
        "denials": hold.denials,
        "receipt_store_bytes_before": hold.receipt_store_bytes_before,
        "receipt_store_bytes_after": hold.receipt_store_bytes_after,
        "concurrency": hold.concurrency,
        "in_flight_peak": hold.in_flight_peak,
        "cores": report.bottleneck.cores,
        "hold": phase_json(hold),
        "sweep": report.sweep.iter().map(phase_json).collect::<Vec<_>>(),
        "bottleneck": bottleneck_json(&report.bottleneck, hold),
        "statistics": {
            "percentile": "linear interpolation between order statistics",
            "confidence": CONFIDENCE,
            "bootstrap": {
                "statistic": "median",
                "resamples": BOOTSTRAP_RESAMPLES,
                "seed": BOOTSTRAP_SEED,
                "max_observations": BOOTSTRAP_MAX_OBSERVATIONS,
            },
        },
    });
    let mut text = serde_json::to_string(&json)?;
    text.push('\n');
    std::fs::write(path, text)?;
    Ok(())
}

fn main() -> ExitCode {
    let options = match parse_options(std::env::args_os().skip(1)) {
        Ok(options) => options,
        Err(message) => {
            eprintln!("{message}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let report = match run(&options) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("sustained treaty load failed: {error}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(error) = write_report(&options.out, &report) {
        eprintln!("failed to write {}: {error}", options.out.display());
        return ExitCode::FAILURE;
    }
    let hold = &report.hold;
    let bottleneck = &report.bottleneck;
    eprintln!(
        "held {} calls in flight for {} s: {} calls in {:.2} s ({:.1} calls/s), \
         {} dispatches, {} denials, receipt store {} -> {} bytes",
        hold.concurrency,
        hold.requested_seconds,
        hold.calls,
        hold.elapsed.as_secs_f64(),
        hold.calls_per_second(),
        hold.dispatches,
        hold.denials,
        hold.receipt_store_bytes_before,
        hold.receipt_store_bytes_after
    );
    eprintln!(
        "call latency p50 {:.2} ms (95 percent CI {:.2} to {:.2} ms), p99 {:.2} ms",
        hold.latency.p50 / 1000.0,
        hold.latency.p50_ci_low / 1000.0,
        hold.latency.p50_ci_high / 1000.0,
        hold.latency.p99 / 1000.0
    );
    eprintln!(
        "limit: {} (peak at {} of {} cores, knee at {}, {:.2}x over one call in flight, \
         {} holds {:.0} percent of call latency)",
        bottleneck.classification,
        bottleneck.peak_concurrency,
        bottleneck.cores,
        bottleneck.knee_concurrency,
        bottleneck.speedup_at_peak,
        bottleneck.dominant_stage,
        bottleneck.dominant_stage_share * 100.0
    );
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// A stand-in path that will not finish its first call until every worker
    /// is inside one, so a phase that leaves a single call outstanding cannot
    /// reach the requested number in flight.
    struct RendezvousPath {
        arrived: Arc<AtomicUsize>,
        target: usize,
        calls: u64,
    }

    impl AdmissionPath for RendezvousPath {
        fn call(&mut self) -> Result<CallTiming, String> {
            let started = Instant::now();
            self.arrived.fetch_add(1, Ordering::SeqCst);
            let deadline = started + Duration::from_secs(5);
            while self.arrived.load(Ordering::SeqCst) < self.target && Instant::now() < deadline {
                std::thread::yield_now();
            }
            std::thread::sleep(Duration::from_micros(200));
            self.calls += 1;
            Ok(CallTiming {
                prepare: Duration::from_micros(1),
                evaluate: started.elapsed(),
                denial: None,
            })
        }

        fn calls(&self) -> u64 {
            self.calls
        }

        fn dispatches(&self) -> u64 {
            self.calls
        }

        fn receipt_store_bytes(&self) -> u64 {
            self.calls.saturating_mul(16)
        }
    }

    fn summary_of(value_us: f64) -> Summary {
        let sample = (value_us * 1000.0) as u64;
        match summarize_us(&[sample, sample, sample, sample]) {
            Ok(summary) => summary,
            Err(error) => panic!("{error}"),
        }
    }

    fn sweep_point(concurrency: usize, calls_per_second: f64, latency_us: f64) -> Phase {
        let elapsed = Duration::from_secs(4);
        Phase {
            concurrency,
            requested_seconds: elapsed.as_secs(),
            elapsed,
            calls: (calls_per_second * elapsed.as_secs_f64()) as u64,
            dispatches: (calls_per_second * elapsed.as_secs_f64()) as u64,
            denials: 0,
            first_denial: None,
            in_flight_peak: concurrency,
            latency: summary_of(latency_us),
            prepare: summary_of(latency_us * 0.1),
            evaluate: summary_of(latency_us * 0.9),
            receipt_store_bytes_before: 0,
            receipt_store_bytes_after: 4096,
        }
    }

    #[test]
    fn a_phase_holds_every_call_it_asks_for_in_flight() {
        let concurrency = 4;
        let arrived = Arc::new(AtomicUsize::new(0));
        let phase = run_phase(concurrency, Duration::from_millis(400), |_| {
            Ok(RendezvousPath {
                arrived: Arc::clone(&arrived),
                target: concurrency,
                calls: 0,
            })
        });
        let phase = match phase {
            Ok(phase) => phase,
            Err(error) => panic!("{error}"),
        };
        assert_eq!(phase.in_flight_peak, concurrency);
        assert_eq!(phase.concurrency, concurrency);
        assert!(phase.calls >= concurrency as u64, "calls {}", phase.calls);
        assert_eq!(phase.dispatches, phase.calls);
        assert_eq!(phase.denials, 0);
        assert!(phase.elapsed >= Duration::from_millis(400));
    }

    #[test]
    fn throughput_is_reported_with_the_concurrency_that_produced_it() {
        let sweep = vec![
            sweep_point(1, 100.0, 10_000.0),
            sweep_point(2, 185.0, 10_800.0),
            sweep_point(4, 190.0, 21_000.0),
            sweep_point(8, 150.0, 53_000.0),
        ];
        let bottleneck = match classify(&sweep, 8) {
            Ok(bottleneck) => bottleneck,
            Err(error) => panic!("{error}"),
        };
        assert_eq!(bottleneck.peak_concurrency, 4);
        assert_eq!(bottleneck.knee_concurrency, 2);
        assert!(!bottleneck.sweep_truncated);
        assert_eq!(bottleneck.classification, "contended");
        assert!((bottleneck.speedup_at_peak - 1.9).abs() < 0.01);
        assert_eq!(bottleneck.dominant_stage, "evaluate");
    }

    #[test]
    fn the_reading_does_not_depend_on_the_sweep_order() {
        let sweep = vec![
            sweep_point(8, 150.0, 53_000.0),
            sweep_point(2, 185.0, 10_800.0),
            sweep_point(4, 190.0, 21_000.0),
            sweep_point(1, 100.0, 10_000.0),
        ];
        let bottleneck = match classify(&sweep, 8) {
            Ok(bottleneck) => bottleneck,
            Err(error) => panic!("{error}"),
        };
        assert_eq!(bottleneck.peak_concurrency, 4);
        assert_eq!(bottleneck.knee_concurrency, 2);
    }

    #[test]
    fn the_fewest_calls_in_flight_wins_a_tie() {
        let sweep = vec![
            sweep_point(1, 100.0, 10_000.0),
            sweep_point(4, 190.0, 21_000.0),
            sweep_point(8, 190.0, 42_000.0),
        ];
        let bottleneck = match classify(&sweep, 8) {
            Ok(bottleneck) => bottleneck,
            Err(error) => panic!("{error}"),
        };
        assert_eq!(bottleneck.peak_concurrency, 4);
        assert!(!bottleneck.sweep_truncated);
    }

    #[test]
    fn a_flat_sweep_reads_as_a_serialized_path() {
        let sweep = vec![
            sweep_point(1, 100.0, 10_000.0),
            sweep_point(2, 99.0, 20_000.0),
            sweep_point(4, 98.0, 40_000.0),
        ];
        let bottleneck = match classify(&sweep, 8) {
            Ok(bottleneck) => bottleneck,
            Err(error) => panic!("{error}"),
        };
        assert_eq!(bottleneck.classification, "serialized");
        assert_eq!(bottleneck.peak_concurrency, 1);
        assert!(bottleneck.latency_growth_at_peak > 0.0);
    }

    #[test]
    fn a_sweep_that_never_turns_over_is_not_given_a_limit() {
        let sweep = vec![
            sweep_point(1, 100.0, 10_000.0),
            sweep_point(2, 200.0, 10_100.0),
            sweep_point(4, 400.0, 10_200.0),
        ];
        let bottleneck = match classify(&sweep, 64) {
            Ok(bottleneck) => bottleneck,
            Err(error) => panic!("{error}"),
        };
        assert_eq!(bottleneck.classification, "undetermined_sweep_truncated");
        assert!(bottleneck.sweep_truncated);
    }

    #[test]
    fn a_sweep_without_its_baseline_is_rejected() {
        let sweep = vec![sweep_point(2, 100.0, 10_000.0)];
        assert!(classify(&sweep, 8).is_err());
    }

    #[test]
    fn every_median_carries_an_interval_around_it() {
        let samples: Vec<u64> = (1..=101).map(|value| value * 1_000).collect();
        let summary = match summarize_us(&samples) {
            Ok(summary) => summary,
            Err(error) => panic!("{error}"),
        };
        assert!((summary.p50 - 51.0).abs() < 1e-9);
        assert!(summary.p50_ci_low < summary.p50);
        assert!(summary.p50_ci_high > summary.p50);
        assert!(summary.p50_ci_low >= summary.min);
        assert!(summary.p50_ci_high <= summary.max);
    }

    #[test]
    fn median_intervals_are_reproducible() {
        let samples: Vec<f64> = (1..=200).map(f64::from).collect();
        let first = median_interval(&samples);
        let second = median_interval(&samples);
        match (first, second) {
            (Ok(first), Ok(second)) => assert_eq!(first, second),
            _ => panic!("median interval failed"),
        }
    }

    #[test]
    fn percentiles_interpolate_between_order_statistics() {
        let ordered = [1.0, 2.0, 3.0, 4.0];
        match percentile(&ordered, 0.5) {
            Ok(value) => assert!((value - 2.5).abs() < 1e-12),
            Err(error) => panic!("{error}"),
        }
        assert!(percentile(&[], 0.5).is_err());
    }

    #[test]
    fn the_concurrency_ladder_always_carries_its_baseline() {
        let parsed = match parse_concurrency(&OsString::from("8,2,8")) {
            Ok(parsed) => parsed,
            Err(error) => panic!("{error}"),
        };
        assert_eq!(parsed, vec![1, 2, 8]);
        assert!(parse_concurrency(&OsString::from("0")).is_err());
        assert!(parse_concurrency(&OsString::from("two")).is_err());
        assert_eq!(default_concurrency(4), vec![1, 2, 4, 8]);
        assert_eq!(default_concurrency(1), vec![1, 2]);
    }

    #[test]
    fn a_phase_with_denials_fails_the_run() {
        let phase = sweep_point(2, 100.0, 10_000.0);
        assert!(check_phase(&phase, "sweep-2").is_ok());
        let denied = Phase {
            denials: 3,
            first_denial: Some("treaty_scope_mismatch".to_string()),
            ..sweep_point(2, 100.0, 10_000.0)
        };
        assert!(check_phase(&denied, "sweep-2").is_err());
    }
}
