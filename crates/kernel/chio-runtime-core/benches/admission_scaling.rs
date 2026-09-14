//! Admission latency as a function of receipt-lineage depth.
//!
//! The lineage walk is the one part of admission that is linear in what the
//! request presents, and the only term in the decision whose cost is not a
//! constant. This sweep times one `ChioKernel::evaluate_tool_call` per
//! invocation through the real runtime admission hook, once per depth, with
//! request setup outside the timed window. Every depth gets its own kernel, its
//! own store and its own SQLite receipt file, so nothing but the bundle differs
//! between them.
//!
//! Two windows are timed per call. The first is the receiver-side lineage work
//! on its own: resolving the bundle the request names from the receiver's own
//! store, comparing the digest the store recorded for it against the one the
//! request cites, and walking every edge. The second is the whole admitted call
//! that includes it. The first is where the linear term lives; the second says
//! how much of an admission it is.
//!
//! Each timed invocation is written out individually rather than summarized
//! here: the distribution, its percentiles and its intervals are the reader's to
//! compute from the samples, not this target's to assert.
//!
//! The depth is a property of the bundle the RECEIVER holds. A request names the
//! bundle by id and digest and cannot supply one, so the curve measures what a
//! deep lineage costs the receiver that accepted it, not what a peer can impose
//! inside one request.
//!
//! Environment:
//!
//! * `CHIO_ADMISSION_SCALING_DEPTHS` - depths to sweep, comma separated.
//!   Default `1,2,4,8,16,32`.
//! * `CHIO_ADMISSION_SCALING_ITERATIONS` - timed invocations per depth.
//!   Default 200.
//! * `CHIO_ADMISSION_SCALING_WARMUP` - untimed invocations per depth before the
//!   timed ones. Default 20.
//! * `CHIO_PAPER_SAMPLES_DIR` - where the samples go. Without it the sweep runs
//!   and prints a summary but writes nothing.
//!
//! The target carries its own entry point when it is built as a
//! `harness = false` bench and runs under libtest's otherwise. The sweep is the
//! same function either way.

#[path = "fixtures/admission_scaling_fixture.rs"]
mod admission_scaling_fixture;

use std::fs;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use admission_scaling_fixture::{AdmissionScalingFixture, CallOutcome};
use tempfile::TempDir;

type BoxError = Box<dyn std::error::Error>;

/// Depths swept when the environment does not name others. Doubling covers a
/// wide enough range for the shape of the curve to be read off the points
/// rather than assumed from two of them.
const DEFAULT_DEPTHS: &[usize] = &[1, 2, 4, 8, 16, 32];
const DEFAULT_ITERATIONS: usize = 200;
const DEFAULT_WARMUP: usize = 20;

/// One depth's measurement: the whole admitted call, and the lineage work
/// inside it on its own.
struct DepthResult {
    depth: usize,
    lineage_bundle_bytes: usize,
    call_nanos: Vec<u64>,
    lineage_nanos: Vec<u64>,
}

fn median_micros(samples: &[u64]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let mut ordered = samples.to_vec();
    ordered.sort_unstable();
    let middle = ordered.len() / 2;
    if ordered.len() % 2 == 1 {
        ordered[middle] as f64 / 1_000.0
    } else {
        (ordered[middle - 1] as f64 + ordered[middle] as f64) / 2_000.0
    }
}

/// The depths this run sweeps. A malformed override fails the run rather than
/// silently falling back to the default, which would report a sweep nobody asked
/// for under the name of one somebody did.
fn depths() -> Result<Vec<usize>, BoxError> {
    let Some(raw) = std::env::var_os("CHIO_ADMISSION_SCALING_DEPTHS") else {
        return Ok(DEFAULT_DEPTHS.to_vec());
    };
    let raw = raw
        .into_string()
        .map_err(|_| "CHIO_ADMISSION_SCALING_DEPTHS is not valid UTF-8")?;
    let mut depths = Vec::new();
    for field in raw.split(',') {
        let field = field.trim();
        if field.is_empty() {
            continue;
        }
        let depth: usize = field.parse().map_err(|error| {
            format!("CHIO_ADMISSION_SCALING_DEPTHS field {field} is not a depth: {error}")
        })?;
        if depth == 0 {
            return Err(
                "CHIO_ADMISSION_SCALING_DEPTHS names depth 0; a lineage bundle needs at least one statement"
                    .into(),
            );
        }
        depths.push(depth);
    }
    if depths.is_empty() {
        return Err("CHIO_ADMISSION_SCALING_DEPTHS named no depth".into());
    }
    Ok(depths)
}

fn count(variable: &str, default: usize, minimum: usize) -> Result<usize, BoxError> {
    let Some(raw) = std::env::var_os(variable) else {
        return Ok(default);
    };
    let raw = raw
        .into_string()
        .map_err(|_| format!("{variable} is not valid UTF-8"))?;
    let value: usize = raw
        .trim()
        .parse()
        .map_err(|error| format!("{variable} is not a whole number: {error}"))?;
    if value < minimum {
        return Err(format!("{variable} must be at least {minimum}").into());
    }
    Ok(value)
}

fn as_nanos(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
}

/// Stands a fixture up at one depth and returns it with the directory its
/// receipt store lives in, which must outlive it.
fn fixture_at(depth: usize) -> Result<(TempDir, AdmissionScalingFixture), BoxError> {
    let directory = TempDir::new().map_err(|error| {
        format!("failed to create a receipt directory for depth {depth}: {error}")
    })?;
    let fixture = AdmissionScalingFixture::new(&directory.path().join("receipts.sqlite3"), depth)
        .map_err(|error| {
        format!("failed to build the depth-{depth} scaling fixture: {error}")
    })?;
    Ok((directory, fixture))
}

/// Times `iterations` admitted calls at one depth, after `warmup` untimed ones.
///
/// The fixture registers fresh evidence for every call, so no call reuses a
/// continuation or a lease and each one takes the whole admitted path. A call
/// that is not admitted stops the sweep: a curve that silently includes a denial
/// is measuring the denial path.
fn measure_depth(depth: usize, warmup: usize, iterations: usize) -> Result<DepthResult, BoxError> {
    let (_directory, fixture) = fixture_at(depth)?;
    if fixture.lineage_depth() != depth {
        return Err(format!(
            "the fixture built for depth {depth} reports depth {}",
            fixture.lineage_depth()
        )
        .into());
    }
    let mut call_nanos = Vec::with_capacity(iterations);
    let mut lineage_nanos = Vec::with_capacity(iterations);
    for index in 0..warmup + iterations {
        let request = fixture.prepare_request()?;
        let (bundle_id, bundle_sha256) = lineage_bundle_citation(&request)?;

        // The lineage work on its own, before the call that includes it: the
        // resolution, the digest comparison and the walk, with nothing else in
        // the window.
        let started = Instant::now();
        let binding = fixture.verify_lineage_once(&bundle_id, &bundle_sha256)?;
        let lineage_elapsed = started.elapsed();
        if binding.is_empty() {
            return Err(format!("depth {depth} produced no lineage binding").into());
        }

        let started = Instant::now();
        let outcome = fixture.evaluate_once(&request)?;
        let call_elapsed = started.elapsed();
        match outcome {
            CallOutcome::Admitted => {}
            CallOutcome::Denied { failure_code } => {
                return Err(
                    format!("depth {depth} was denied at call {index}: {failure_code}").into(),
                )
            }
        }
        if index >= warmup {
            call_nanos.push(as_nanos(call_elapsed));
            lineage_nanos.push(as_nanos(lineage_elapsed));
        }
    }
    if fixture.tool_invocations() != fixture.calls() {
        return Err(format!(
            "depth {depth} dispatched {} times over {} admitted calls",
            fixture.tool_invocations(),
            fixture.calls()
        )
        .into());
    }
    Ok(DepthResult {
        depth,
        lineage_bundle_bytes: fixture.lineage_bundle_bytes(),
        call_nanos,
        lineage_nanos,
    })
}

/// The lineage bundle id the request cites. Read back out of the request rather
/// than recomputed, so the isolated measurement resolves the same object the
/// call that follows it resolves.
fn lineage_bundle_citation(
    request: &chio_kernel::ToolCallRequest,
) -> Result<(String, String), BoxError> {
    let citation = request
        .governed_intent
        .as_ref()
        .and_then(|intent| intent.context.as_ref())
        .map(|context| &context["chioTreaty"]["receiptLineageBundle"])
        .ok_or("the prepared request carries no governed intent")?;
    let id = citation["id"]
        .as_str()
        .ok_or("the prepared request cites no lineage bundle")?;
    let sha256 = citation["sha256"]
        .as_str()
        .ok_or("the prepared request cites a lineage bundle without a digest")?;
    Ok((id.to_string(), sha256.to_string()))
}

fn write_samples(directory: &Path, results: &[DepthResult]) -> Result<(), BoxError> {
    fs::create_dir_all(directory)?;
    let mut manifest = BufWriter::new(fs::File::create(
        directory.join("admission_scaling_depths.csv"),
    )?);
    writeln!(manifest, "depth,lineage_bundle_bytes,samples,samples_file")?;
    for result in results {
        let name = format!("admission_lineage_depth_{}", result.depth);
        writeln!(
            manifest,
            "{},{},{},{name}.csv",
            result.depth,
            result.lineage_bundle_bytes,
            result.call_nanos.len()
        )?;
        let mut samples = BufWriter::new(fs::File::create(directory.join(format!("{name}.csv")))?);
        writeln!(samples, "invocation,call_elapsed_ns,lineage_elapsed_ns")?;
        for (index, (call_ns, lineage_ns)) in result
            .call_nanos
            .iter()
            .zip(&result.lineage_nanos)
            .enumerate()
        {
            writeln!(samples, "{index},{call_ns},{lineage_ns}")?;
        }
        samples.flush()?;
    }
    manifest.flush()?;
    Ok(())
}

/// The whole sweep: every depth, in the order given, each on its own kernel.
fn sweep() -> Result<Vec<DepthResult>, BoxError> {
    let depths = depths()?;
    let iterations = count("CHIO_ADMISSION_SCALING_ITERATIONS", DEFAULT_ITERATIONS, 2)?;
    let warmup = count("CHIO_ADMISSION_SCALING_WARMUP", DEFAULT_WARMUP, 0)?;
    let mut results = Vec::with_capacity(depths.len());
    for depth in depths {
        let result = measure_depth(depth, warmup, iterations)?;
        println!(
            "depth {:>3}: {:>5} samples, bundle {:>7} bytes, call median {:>10.3} us, \
             lineage median {:>8.3} us",
            result.depth,
            result.call_nanos.len(),
            result.lineage_bundle_bytes,
            median_micros(&result.call_nanos),
            median_micros(&result.lineage_nanos)
        );
        results.push(result);
    }
    if let Some(directory) = std::env::var_os("CHIO_PAPER_SAMPLES_DIR") {
        write_samples(&PathBuf::from(directory), &results)?;
    }
    Ok(results)
}

#[cfg(not(test))]
fn main() {
    if let Err(error) = sweep() {
        eprintln!("admission scaling sweep failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod default_harness {
    //! Under the default test harness the sweep is the test. It reads the same
    //! environment as the standalone entry point, so one invocation of
    //! `cargo test --bench admission_scaling` is a full measurement.

    use super::sweep;

    #[test]
    fn lineage_depth_sweep() {
        if let Err(error) = sweep() {
            panic!("admission scaling sweep failed: {error}");
        }
    }
}
