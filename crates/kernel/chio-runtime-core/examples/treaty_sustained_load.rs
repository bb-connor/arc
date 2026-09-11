//! Admitted treaty calls back to back against a fresh SQLite receipt store.
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
//! and the in-process bilateral co-signature. The loop also carries each
//! call's origin-side setup (a fresh continuation, lineage, invocation, and
//! signed DSSE envelope), so calls per second is wall-clock throughput of the
//! whole exchange. The program exits nonzero when any call is denied or when
//! the tool server did not run exactly once per call.

#[path = "../benches/fixtures/treaty_admission_allow_fixture.rs"]
mod treaty_admission_allow_fixture;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use treaty_admission_allow_fixture::{CallOutcome, TreatyPredispatchAllowFixture};

const USAGE: &str = "usage: treaty_sustained_load --seconds <N> --out <path.json>";

struct Options {
    seconds: u64,
    out: PathBuf,
}

struct Report {
    seconds: u64,
    calls: u64,
    calls_per_second: f64,
    dispatch_count: u64,
    denials: u64,
    receipt_store_bytes_before: u64,
    receipt_store_bytes_after: u64,
}

fn parse_options(mut args: impl Iterator<Item = OsString>) -> Result<Options, String> {
    let mut seconds = None;
    let mut out = None;
    while let Some(flag) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("{} needs a value", flag.to_string_lossy()))?;
        match flag.to_str() {
            Some("--seconds") => {
                let parsed = value
                    .to_str()
                    .and_then(|value| value.parse::<u64>().ok())
                    .filter(|value| *value > 0)
                    .ok_or_else(|| "--seconds needs a positive integer".to_string())?;
                seconds = Some(parsed);
            }
            Some("--out") => out = Some(PathBuf::from(value)),
            _ => return Err(format!("unknown flag {}", flag.to_string_lossy())),
        }
    }
    Ok(Options {
        seconds: seconds.ok_or_else(|| "--seconds is required".to_string())?,
        out: out.ok_or_else(|| "--out is required".to_string())?,
    })
}

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

fn run(options: &Options) -> Result<Report, Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("receipts.sqlite3");
    let fixture = TreatyPredispatchAllowFixture::new(&database)?;
    // Measured after the fixture's single smoke call, so growth counts only the timed loop.
    let receipt_store_bytes_before = receipt_store_bytes(&database);
    let calls_before = fixture.calls();
    let dispatches_before = fixture.tool_invocations();

    let mut denials = 0_u64;
    let started = Instant::now();
    let deadline = started + Duration::from_secs(options.seconds);
    while Instant::now() < deadline {
        let request = fixture.prepare_request()?;
        match fixture.evaluate_once(&request)? {
            CallOutcome::Admitted => {}
            CallOutcome::Denied { failure_code } => {
                denials += 1;
                eprintln!(
                    "call {} denied before dispatch: {failure_code}",
                    fixture.calls() - calls_before
                );
            }
        }
    }
    let elapsed = started.elapsed();
    let calls = fixture.calls() - calls_before;

    Ok(Report {
        seconds: options.seconds,
        calls,
        calls_per_second: calls as f64 / elapsed.as_secs_f64(),
        dispatch_count: fixture.tool_invocations() - dispatches_before,
        denials,
        receipt_store_bytes_before,
        receipt_store_bytes_after: receipt_store_bytes(&database),
    })
}

fn write_report(path: &Path, report: &Report) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::json!({
        "seconds": report.seconds,
        "calls": report.calls,
        "calls_per_second": report.calls_per_second,
        "dispatch_count": report.dispatch_count,
        "denials": report.denials,
        "receipt_store_bytes_before": report.receipt_store_bytes_before,
        "receipt_store_bytes_after": report.receipt_store_bytes_after,
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
    eprintln!(
        "{} calls in {} s ({:.1} calls/s), {} dispatches, {} denials, receipt store {} -> {} bytes",
        report.calls,
        report.seconds,
        report.calls_per_second,
        report.dispatch_count,
        report.denials,
        report.receipt_store_bytes_before,
        report.receipt_store_bytes_after
    );
    if report.denials != 0 || report.dispatch_count != report.calls {
        eprintln!("sustained treaty load did not admit and dispatch every call exactly once");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
