//! Export actual supervised worker effects, then reject re-signed semantic substitutions.
#![cfg(target_os = "linux")]

use std::path::Path;
use std::process::{Command, Output};

use chio_core::{
    crypto::{canonical_json_bytes, sha256_hex},
    receipt::{body::ChioReceipt, decision::ToolCallAction},
};
use serde_json::{json, Value};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn process(args: &[&str]) -> Result<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_chio"))
        .arg("process")
        .args(args)
        .output()?)
}

fn success(output: Output) -> Result<Value> {
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}

#[test]
fn completed_run_binds_actual_worker_results_and_rejects_semantic_substitutions() -> Result {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let directory = tempfile::tempdir()?;
    let root = directory.path().canonicalize()?;
    let output = Command::new("python3")
        .args(["-c", "import sys; from pathlib import Path; import swarm; swarm.exercise(sys.argv[1], Path(sys.argv[2]), supervisor_only=True)"])
        .arg(env!("CARGO_BIN_EXE_chio"))
        .arg(&root)
        .env("PYTHONPATH", std::env::join_paths([
            repository.join("sdks/python/chio-process/src"),
            repository.join("crates/products/chio-cli/tests/process_host"),
        ])?)
        .output()?;
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let state = root.join("state");
    let plan = state.join("reference-run-plan.json");
    let artifact = root.join("completed.json");
    let summary = success(process(&[
        "attest-run",
        "--state",
        state.to_str().ok_or("state path")?,
        "--plan",
        plan.to_str().ok_or("plan path")?,
        "--out",
        artifact.to_str().ok_or("artifact path")?,
    ])?)?;
    let runtime = summary["runtime_id"].as_str().ok_or("runtime ID")?;
    let key = state.join("authority.db.kernel.pub");
    let verify = |path: &Path, runtime: &str| -> Result<Output> {
        process(&[
            "verify-run",
            "--artifact",
            path.to_str().ok_or("artifact path")?,
            "--trusted-kernel-pubkey",
            key.to_str().ok_or("key path")?,
            "--runtime-id",
            runtime,
        ])
    };
    let report = success(verify(&artifact, runtime)?)?;
    assert_eq!(report["verified_workers"], json!(["alice", "bob"]));
    assert_eq!(report["captured_invocations"], 2);
    assert_eq!(report["m5_acceptance_complete"], false);
    assert!(!verify(&artifact, "another-runtime")?.status.success());
    let original: ChioReceipt = serde_json::from_slice(&std::fs::read(&artifact)?)?;
    let signer = chio_control_plane::load_existing_authority_keypair(
        &state.join("authority.db.kernel.seed"),
    )?;
    assert_eq!(signer.public_key(), original.kernel_key);
    let cases = [
        (
            "/host_record/config/limits/max_calls",
            json!(9999),
            "host record differs",
        ),
        (
            "/aggregate/captured_invocations",
            json!(0),
            "aggregate usage",
        ),
        (
            "/aggregate/reserved_invocations",
            json!(1),
            "aggregate usage",
        ),
        (
            "/aggregate/owner_id",
            json!("another-owner"),
            "aggregate usage",
        ),
        (
            "/runner/workers/0/state",
            json!("running"),
            "worker did not complete",
        ),
        (
            "/runner/plan/workers/0/input/arguments",
            json!({"substituted": true}),
            "runner input differs",
        ),
        (
            "/results/alice/context/process_id",
            json!("bob"),
            "invocation context differs",
        ),
        (
            "/results/alice/response/output",
            json!({"kind":"value", "value":"forged"}),
            "output content hash",
        ),
    ];
    for (index, (pointer, replacement, reason)) in cases.into_iter().enumerate() {
        let mut body = original.body();
        *body
            .action
            .parameters
            .pointer_mut(pointer)
            .ok_or("missing mutation target")? = replacement;
        let value = body.action.parameters.clone();
        body.action = ToolCallAction::from_parameters(value.clone())?;
        body.content_hash = sha256_hex(&canonical_json_bytes(&value)?);
        body.id.clear();
        let signed = ChioReceipt::sign(body, &signer)?;
        assert!(signed.verify_signature()?);
        let path = root.join(format!("substitution-{index}.json"));
        std::fs::write(&path, canonical_json_bytes(&signed)?)?;
        let denied = verify(&path, runtime)?;
        assert!(!denied.status.success(), "accepted {pointer}");
        assert!(
            String::from_utf8_lossy(&denied.stderr).contains(reason),
            "{pointer}: {}",
            String::from_utf8_lossy(&denied.stderr)
        );
    }
    // Unsigned payload edits also fail at the signature boundary.
    let mut altered: Value = serde_json::to_value(&original)?;
    altered["action"]["parameters"]["runtime_id"] = json!("tampered");
    let path = root.join("broken-signature.json");
    std::fs::write(&path, serde_json::to_vec(&altered)?)?;
    assert!(!verify(&path, runtime)?.status.success());
    Ok(())
}
