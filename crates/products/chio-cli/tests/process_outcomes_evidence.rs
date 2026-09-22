//! Join actual worker completion, multiple issued graphs and captured family use.
#![cfg(target_os = "linux")]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

use chio_core::{
    crypto::{canonical_json_bytes, sha256_hex},
    receipt::{body::ChioReceipt, decision::ToolCallAction},
};
use serde_json::{json, Value};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

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
fn supervised_outcomes_bind_multiple_graphs_and_authoritative_family_usage() -> Result {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let directory = tempfile::tempdir()?;
    let root = directory.path().canonicalize()?;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
    success(Command::new("python3")
        .args(["-c", "import sys; from pathlib import Path; import swarm_outcomes; swarm_outcomes.exercise(sys.argv[1],Path(sys.argv[2]))"])
        .arg(env!("CARGO_BIN_EXE_chio")).arg(&root)
        .env("PYTHONPATH", std::env::join_paths([
            repository.join("sdks/python/chio-process/src"),
            repository.join("crates/products/chio-cli/tests/process_host"),
        ])?).output()?)?;
    let state = root.join("state");
    let artifact = root.join("outcomes.json");
    let summary = success(
        Command::new(env!("CARGO_BIN_EXE_chio"))
            .args(["process", "attest-outcomes", "--state"])
            .arg(&state)
            .arg("--plan")
            .arg(state.join("outcomes-run-plan.json"))
            .arg("--out")
            .arg(&artifact)
            .output()?,
    )?;
    let runtime = summary["runtime_id"].as_str().ok_or("runtime")?;
    let key = state.join("authority.db.kernel.pub");
    let verify = |path: &Path, runtime: &str| -> Result<Output> {
        Ok(Command::new(env!("CARGO_BIN_EXE_chio"))
            .args(["process", "verify-outcomes", "--artifact"])
            .arg(path)
            .arg("--trusted-kernel-pubkey")
            .arg(&key)
            .arg("--runtime-id")
            .arg(runtime)
            .output()?)
    };
    let report = success(verify(&artifact, runtime)?)?;
    assert_eq!(report["graphs"], 2);
    assert_eq!(report["workers"], 4);
    assert_eq!(report["captured_invocations"], 2);
    assert_eq!(report["m5_acceptance_complete"], false);
    assert_eq!(report["artifact_schema"], "chio.process.worker-outcomes.v3");
    assert_eq!(report["native_launches"], json!({}));
    assert!(!verify(&artifact, "another-runtime")?.status.success());
    let original: ChioReceipt = serde_json::from_slice(&std::fs::read(&artifact)?)?;
    let signer = chio_control_plane::load_existing_authority_keypair(
        &state.join("authority.db.kernel.seed"),
    )?;
    let params = &original.action.parameters;
    let mut states: Vec<_> = params["calls"]
        .as_object()
        .ok_or("calls")?
        .values()
        .map(|call| {
            call["action"]["parameters"]["operation"]["state"]
                .as_str()
                .ok_or("state")
        })
        .collect::<std::result::Result<_, _>>()?;
    states.sort();
    assert_eq!(
        states,
        [
            "compensated_before_dispatch",
            "compensated_before_dispatch",
            "completed",
            "completed"
        ]
    );
    let cases = [
        ("/aggregate/captured_invocations", json!(0)),
        ("/aggregate/captured_invocations", json!(3)),
        ("/aggregate/max_invocations", json!(99)),
        ("/aggregate/reserved_invocations", json!(1)),
        ("/aggregate/owner_id", json!("another-owner")),
        ("/runner/workers/0/state", json!("running")),
        ("/runner/workers/0/attempts", json!(0)),
        (
            "/runner/plan/workers/0/input/arguments",
            json!({"different":true}),
        ),
        (
            "/runner/plan/workers/0/input/request_id",
            json!("another-request"),
        ),
        ("/authorities", json!([params["authorities"][0]])),
        ("/authorities/1", params["authorities"][0].clone()),
        ("/calls/alice", params["calls"]["bob"].clone()),
        ("/observed_at_unix_ms", json!(1)),
        ("/schema", json!("chio.process.worker-outcomes.v9")),
    ];
    for (index, (pointer, replacement)) in cases.into_iter().enumerate() {
        let mut body = original.body();
        *body
            .action
            .parameters
            .pointer_mut(pointer)
            .ok_or("mutation target")? = replacement;
        let parameters = body.action.parameters.clone();
        body.action = ToolCallAction::from_parameters(parameters.clone())?;
        body.content_hash = sha256_hex(&canonical_json_bytes(&parameters)?);
        body.id.clear();
        let signed = ChioReceipt::sign(body, &signer)?;
        assert!(signed.verify_signature()?);
        let path = root.join(format!("substitution-{index}.json"));
        std::fs::write(&path, canonical_json_bytes(&signed)?)?;
        assert!(
            !verify(&path, runtime)?.status.success(),
            "accepted {pointer}"
        );
    }
    Ok(())
}
