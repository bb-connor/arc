//! Receiver-owned cross-boundary admission over a verified treaty intersection.
//!
//! `treaty_predispatch_deny` and `treaty_predispatch_allow` time one
//! `ChioKernel::evaluate_tool_call` per invocation through the real runtime
//! admission hook, with request setup outside the timed window. When
//! `CHIO_PAPER_SAMPLES_DIR` is set, every measured invocation's latency is
//! written to `<dir>/<bench_name>.csv` next to Criterion's own estimates.

#[path = "fixtures/treaty_admission_allow_fixture.rs"]
mod treaty_admission_allow_fixture;
#[path = "fixtures/treaty_admission_fixture.rs"]
mod treaty_admission_fixture;

use std::cell::RefCell;
use std::fs;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use chio_core_types::crypto::Keypair;
use chio_runtime_core::{
    compute_ladder_intersection, evaluate_cross_boundary_admission,
    governance_ladder_manifest_sha256, ladder_intersection_sha256, CrossBoundaryAdmissionInput,
    CrossBoundaryEvidenceRef, GovernanceLadderActionClass, GovernanceLadderManifest, TreatyScope,
    CHIO_GOVERNANCE_LADDER_MANIFEST_SCHEMA, CHIO_TREATY_SCOPE_SCHEMA,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tempfile::tempdir;
use treaty_admission_allow_fixture::{CallOutcome, TreatyPredispatchAllowFixture};
use treaty_admission_fixture::TreatyPredispatchDenyFixture;

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

fn action() -> GovernanceLadderActionClass {
    GovernanceLadderActionClass {
        action_class_id: "workflow.cross_kernel.read_refund_case".to_string(),
        mode: "receipt_backed".to_string(),
        destructive: false,
        consistency_model: "totally-ordered".to_string(),
        co_sign: "bilateral_required".to_string(),
        co_sign_quorum: None,
        evidence_required: vec![
            "receipt_lineage".to_string(),
            "bilateral_invocation".to_string(),
        ],
        aliases: Vec::new(),
    }
}

fn manifest(kernel_id: &str) -> GovernanceLadderManifest {
    GovernanceLadderManifest {
        schema: CHIO_GOVERNANCE_LADDER_MANIFEST_SCHEMA.to_string(),
        manifest_id: format!("ladder-{kernel_id}"),
        kernel_id: kernel_id.to_string(),
        issuer: kernel_id.to_string(),
        key_id: format!("key-{kernel_id}"),
        issued_at_unix_ms: 1_766_000_000_000,
        expires_at_unix_ms: 1_900_000_000_000,
        destructive_floor: "receipt_backed".to_string(),
        default_unknown_mode: "deny".to_string(),
        action_classes: vec![action()],
    }
}

pub fn bench(c: &mut Criterion) {
    // Denial: the hook resolves the six treaty artifacts from the in-memory
    // store, checks the continuation, lineage, and invocation bindings, decodes
    // the DSSE statement, and denies on the unanimous-deny policy summary
    // before any signature verification; the kernel then writes the signed
    // denial receipt to SQLite.
    let treaty_deny_fixture = match TreatyPredispatchDenyFixture::new() {
        Ok(fixture) => fixture,
        Err(error) => panic!("failed to build real treaty admission hook fixture: {error}"),
    };
    bench_per_invocation(
        c,
        "treaty_predispatch_deny",
        || match treaty_deny_fixture.prepare_request() {
            Ok(request) => request,
            Err(error) => panic!("failed to prepare treaty admission benchmark request: {error}"),
        },
        |request| {
            assert!(
                black_box(treaty_deny_fixture.evaluate_once(request)),
                "real treaty admission hook did not return the expected policy denial"
            );
        },
    );

    // Admission: the same resolution and binding checks, both Ed25519
    // verifications on the DSSE envelope, the cross-boundary admission report,
    // continuation and lease consumption, pre-dispatch revalidation, dispatch to
    // the counting tool server, the signed allow receipt in SQLite, and the
    // in-process bilateral co-signature. Same stores as the denial fixture.
    let receipt_directory = match tempdir() {
        Ok(directory) => directory,
        Err(error) => panic!("failed to create allow benchmark receipt directory: {error}"),
    };
    let treaty_allow_fixture = match TreatyPredispatchAllowFixture::new(
        &receipt_directory.path().join("receipts.sqlite3"),
    ) {
        Ok(fixture) => fixture,
        Err(error) => panic!("failed to build real treaty admission allow fixture: {error}"),
    };
    bench_per_invocation(
        c,
        "treaty_predispatch_allow",
        || match treaty_allow_fixture.prepare_request() {
            Ok(request) => request,
            Err(error) => panic!("failed to prepare treaty allow benchmark request: {error}"),
        },
        |request| match treaty_allow_fixture.evaluate_once(request) {
            Ok(CallOutcome::Admitted) => {}
            Ok(CallOutcome::Denied { failure_code }) => {
                panic!("real treaty admission hook denied the allow fixture: {failure_code}")
            }
            Err(error) => panic!("real treaty admission allow benchmark failed: {error}"),
        },
    );
    assert_eq!(
        treaty_allow_fixture.tool_invocations(),
        treaty_allow_fixture.calls(),
        "every admitted call must dispatch exactly once"
    );

    let manifests = vec![
        manifest("did:chio:buyer-kernel"),
        manifest("did:chio:vendor-a"),
    ];
    let manifest_hashes = manifests
        .iter()
        .map(
            |manifest| match governance_ladder_manifest_sha256(manifest) {
                Ok(hash) => hash,
                Err(error) => panic!("failed to hash admission benchmark manifest: {error}"),
            },
        )
        .collect::<Vec<_>>();
    let scope = TreatyScope {
        schema: CHIO_TREATY_SCOPE_SCHEMA.to_string(),
        treaty_id: "treaty-buyer-vendor".to_string(),
        participant_kernel_ids: vec![
            "did:chio:buyer-kernel".to_string(),
            "did:chio:vendor-a".to_string(),
        ],
        participant_public_keys: vec![
            Keypair::from_seed(&[11_u8; 32]).public_key(),
            Keypair::from_seed(&[12_u8; 32]).public_key(),
        ],
        ladder_manifest_sha256s: manifest_hashes,
        allowed_action_classes: vec!["workflow.cross_kernel.read_refund_case".to_string()],
        issued_at_unix_ms: 1_766_000_000_000,
        expires_at_unix_ms: 1_900_000_000_000,
        revocation_epoch_sha256: "c".repeat(64),
        trust_bundle_sha256: "b".repeat(64),
    };
    let intersection = match compute_ladder_intersection(&scope, &manifests, 1_766_000_001_000) {
        Ok(intersection) => intersection,
        Err(error) => panic!("failed to build admission benchmark intersection: {error}"),
    };
    let intersection_sha256 = match ladder_intersection_sha256(&intersection) {
        Ok(hash) => hash,
        Err(error) => panic!("failed to hash admission benchmark intersection: {error}"),
    };
    let evidence = vec![
        CrossBoundaryEvidenceRef {
            evidence_class: "receipt_lineage".to_string(),
            artifact_sha256: "d".repeat(64),
            verified: true,
        },
        CrossBoundaryEvidenceRef {
            evidence_class: "bilateral_invocation".to_string(),
            artifact_sha256: "e".repeat(64),
            verified: true,
        },
    ];

    c.bench_function("cross_boundary_admission_allow", |b| {
        b.iter(|| {
            let report = match evaluate_cross_boundary_admission(CrossBoundaryAdmissionInput {
                treaty_scope: black_box(&scope),
                ladder_intersection: black_box(&intersection),
                expected_ladder_intersection_sha256: Some(intersection_sha256.clone()),
                action_class_id: "workflow.cross_kernel.read_refund_case",
                present_evidence: vec![
                    "receipt_lineage".to_string(),
                    "bilateral_invocation".to_string(),
                ],
                verified_evidence: evidence.clone(),
                now_unix_ms: 1_766_000_001_000,
            }) {
                Ok(report) => report,
                Err(error) => panic!("cross-boundary admission benchmark failed: {error}"),
            };
            assert!(
                black_box(report.accepted),
                "cross-boundary admission benchmark rejected its fixture"
            );
        });
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
