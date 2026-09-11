//! Security components used by the bilateral-admission paper evaluation.
//!
//! `receipt_append_sqlite` times one SQLite append per invocation, with the
//! receipt signed outside the timed window. When `CHIO_PAPER_SAMPLES_DIR` is
//! set, every measured invocation's latency is written to
//! `<dir>/receipt_append_sqlite.csv` next to Criterion's own estimates.

use std::cell::RefCell;
use std::fs;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use chio_store_sqlite::SqliteReceiptStore;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tempfile::tempdir;

#[path = "fixtures/dispatch_request_fixture.rs"]
mod dispatch_request_fixture;

use dispatch_request_fixture::DispatchAllowFixture;

/// Per-invocation latencies for one benchmark, grouped by `iter_custom` call.
///
/// Criterion drives warm-up and measurement through the same closure, so the
/// warm-up calls land here too. `write` keeps only the trailing calls that
/// Criterion's `sample.json` accounts for and checks that each of them holds
/// exactly the iteration count Criterion recorded for that sample.
struct InvocationSamples {
    bench_name: &'static str,
    directory: PathBuf,
    calls: Vec<Vec<u64>>,
}

impl InvocationSamples {
    fn from_env(bench_name: &'static str) -> Option<Self> {
        std::env::var_os("CHIO_PAPER_SAMPLES_DIR").map(|directory| Self {
            bench_name,
            directory: PathBuf::from(directory),
            calls: Vec::new(),
        })
    }

    fn begin_call(&mut self, iters: u64) {
        self.calls
            .push(Vec::with_capacity(usize::try_from(iters).unwrap_or(0)));
    }

    fn record(&mut self, elapsed: Duration) {
        let elapsed_ns = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        if let Some(call) = self.calls.last_mut() {
            call.push(elapsed_ns);
        }
    }

    fn write(self) -> Result<(), Box<dyn std::error::Error>> {
        if self.calls.is_empty() {
            return Ok(());
        }
        let sample_path = criterion_output_directory()
            .join(self.bench_name)
            .join("new")
            .join("sample.json");
        let sample: serde_json::Value = serde_json::from_slice(&fs::read(&sample_path)?)?;
        let sample_iters = sample
            .get("iters")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| format!("{} has no iters array", sample_path.display()))?;
        let measured_calls = sample_iters.len();
        if measured_calls == 0 || self.calls.len() < measured_calls {
            return Err(format!(
                "{} recorded {} iter_custom calls but {} lists {measured_calls} samples",
                self.bench_name,
                self.calls.len(),
                sample_path.display()
            )
            .into());
        }
        let measured = &self.calls[self.calls.len() - measured_calls..];
        for (index, (call, expected)) in measured.iter().zip(sample_iters).enumerate() {
            let expected = expected.as_f64().and_then(iteration_count).ok_or_else(|| {
                format!(
                    "{} lists a non-integral iteration count {expected} at sample {index}",
                    sample_path.display()
                )
            })?;
            if call.len() != expected {
                return Err(format!(
                    "{} sample {index} recorded {} invocations but Criterion ran {expected}",
                    self.bench_name,
                    call.len()
                )
                .into());
            }
        }
        fs::create_dir_all(&self.directory)?;
        let path = self.directory.join(format!("{}.csv", self.bench_name));
        let mut out = BufWriter::new(fs::File::create(&path)?);
        writeln!(out, "invocation,elapsed_ns")?;
        for (index, elapsed_ns) in measured.iter().flatten().enumerate() {
            writeln!(out, "{index},{elapsed_ns}")?;
        }
        out.flush()?;
        Ok(())
    }
}

fn iteration_count(value: f64) -> Option<usize> {
    if value.is_finite() && value >= 0.0 && value.fract() == 0.0 {
        usize::try_from(value as u64).ok()
    } else {
        None
    }
}

/// Mirrors Criterion's output directory resolution: `CRITERION_HOME`, then
/// `CARGO_TARGET_DIR/criterion`, then the `cargo metadata` target directory,
/// then `target/criterion`.
fn criterion_output_directory() -> PathBuf {
    if let Some(home) = std::env::var_os("CRITERION_HOME") {
        return PathBuf::from(home);
    }
    if let Some(target) = std::env::var_os("CARGO_TARGET_DIR") {
        return PathBuf::from(target).join("criterion");
    }
    if let Some(target) = cargo_metadata_target_directory() {
        return target.join("criterion");
    }
    PathBuf::from("target/criterion")
}

fn cargo_metadata_target_directory() -> Option<PathBuf> {
    let output = Command::new(std::env::var_os("CARGO")?)
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .output()
        .ok()?;
    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    metadata
        .get("target_directory")?
        .as_str()
        .map(PathBuf::from)
}

/// Times each invocation of `run` individually; `prepare` runs outside the
/// timed window. The per-sample total feeds Criterion, and each invocation
/// latency is recorded when `CHIO_PAPER_SAMPLES_DIR` is set.
fn bench_per_invocation<R>(
    c: &mut Criterion,
    name: &'static str,
    mut prepare: impl FnMut() -> R,
    mut run: impl FnMut(&R),
) {
    let samples = RefCell::new(InvocationSamples::from_env(name));
    c.bench_function(name, |b| {
        b.iter_custom(|iters| {
            let mut samples = samples.borrow_mut();
            if let Some(samples) = samples.as_mut() {
                samples.begin_call(iters);
            }
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let input = prepare();
                let started = Instant::now();
                run(&input);
                let elapsed = started.elapsed();
                if let Some(samples) = samples.as_mut() {
                    samples.record(elapsed);
                }
                total += elapsed;
            }
            total
        });
    });
    if let Some(samples) = samples.into_inner() {
        if let Err(error) = samples.write() {
            panic!("failed to write per-invocation samples for {name}: {error}");
        }
    }
}

pub fn bench(c: &mut Criterion) {
    let fixture = DispatchAllowFixture::new();

    c.bench_function("receipt_sign", |b| {
        b.iter(|| black_box(fixture.receipt_sign_once()));
    });

    c.bench_function("receipt_verify", |b| {
        b.iter(|| {
            assert!(
                black_box(fixture.receipt_verify_once()),
                "receipt verification benchmark rejected its signed fixture"
            );
        });
    });

    let directory = match tempdir() {
        Ok(directory) => directory,
        Err(error) => panic!("failed to create receipt append benchmark directory: {error}"),
    };
    let store = match SqliteReceiptStore::open(directory.path().join("receipts.sqlite3")) {
        Ok(store) => store,
        Err(error) => panic!("failed to open receipt append benchmark store: {error}"),
    };
    let mut sequence = 0_u64;
    bench_per_invocation(
        c,
        "receipt_append_sqlite",
        || {
            sequence = sequence.saturating_add(1);
            fixture.signed_receipt_with_id(format!("bench-receipt-{sequence}"))
        },
        |receipt| match store.append_chio_receipt_returning_seq(receipt) {
            Ok(appended_sequence) => {
                black_box(appended_sequence);
            }
            Err(error) => panic!("receipt append benchmark failed: {error}"),
        },
    );
}

criterion_group!(benches, bench);
criterion_main!(benches);
