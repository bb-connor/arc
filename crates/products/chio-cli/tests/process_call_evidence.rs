//! Observe real allowed and compensated calls without changing their outcome.
#![cfg(target_os = "linux")]

use std::path::Path;
use std::process::{Command, Output};

use chio_core::{
    crypto::{canonical_json_bytes, sha256_hex, Keypair},
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
fn retained_calls_bind_real_outcomes_and_reject_resigned_substitutions() -> Result {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let directory = tempfile::tempdir()?;
    let root = directory.path().canonicalize()?;
    let output = Command::new("python3")
        .args(["-c", "import sys,json; from pathlib import Path; import swarm_shared_family; print(json.dumps(swarm_shared_family.exercise(sys.argv[1],Path(sys.argv[2]))))"])
        .arg(env!("CARGO_BIN_EXE_chio")).arg(&root)
        .env("PYTHONPATH", std::env::join_paths([
            repository.join("sdks/python/chio-process/src"),
            repository.join("crates/products/chio-cli/tests/process_host"),
        ])?).output()?;
    let fixture = success(output)?;
    let runtime = fixture["bootstrap"]["action"]["parameters"]["runtime_id"]
        .as_str()
        .ok_or("runtime")?;
    let state = root.join("state");
    let key = state.join("authority.db.kernel.pub");
    let signer = chio_control_plane::load_existing_authority_keypair(
        &state.join("authority.db.kernel.seed"),
    )?;
    let verify = |artifact: &Path, runtime: &str, folder: &Path, key: &Path| -> Result<Output> {
        Ok(Command::new(env!("CARGO_BIN_EXE_chio"))
            .args(["process", "verify-call", "--artifact"])
            .arg(artifact)
            .arg("--trusted-kernel-pubkey")
            .arg(key)
            .arg("--runtime-id")
            .arg(runtime)
            .arg("--request")
            .arg(folder.join("request.json"))
            .arg("--context")
            .arg(folder.join("context.json"))
            .output()?)
    };
    let wrong_key = root.join("wrong-key.pub");
    std::fs::write(&wrong_key, Keypair::generate().public_key().to_hex())?;
    let mut counts = [0; 2];
    for name in ["alice", "bob", "carol", "dave"] {
        let folder = root.join(name);
        let artifact = folder.join("observed.json");
        success(
            Command::new(env!("CARGO_BIN_EXE_chio"))
                .args(["process", "attest-call", "--state"])
                .arg(&state)
                .arg("--request")
                .arg(folder.join("request.json"))
                .arg("--context")
                .arg(folder.join("context.json"))
                .arg("--response")
                .arg(folder.join("response.json"))
                .arg("--out")
                .arg(&artifact)
                .output()?,
        )?;
        let report = success(verify(&artifact, runtime, &folder, &key)?)?;
        assert_eq!(report["m5_acceptance_complete"], false);
        let original: ChioReceipt = serde_json::from_slice(&std::fs::read(&artifact)?)?;
        let state = original.action.parameters["operation"]["state"]
            .as_str()
            .ok_or("operation state")?;
        match state {
            "completed" => counts[0] += 1,
            "compensated_before_dispatch" => counts[1] += 1,
            _ => return Err(format!("unexpected operation state: {state}").into()),
        }
        assert!(!verify(&artifact, "another-runtime", &folder, &key)?
            .status
            .success());
        assert!(!verify(&artifact, runtime, &folder, &wrong_key)?
            .status
            .success());
        let other = if name == "alice" {
            root.join("bob")
        } else {
            root.join("alice")
        };
        assert!(!verify(&artifact, runtime, &other, &key)?.status.success());
        let mut cases = vec![
            ("/runtime_id", json!("another-runtime")),
            ("/request/arguments", json!({"substituted": true})),
            ("/context/process_id", json!("another-worker")),
            (
                "/operation/binding/capability_id",
                json!("another-capability"),
            ),
            ("/operation/dispatch_state", json!("not_committed")),
            ("/operation/state", json!("awaiting_caller_report")),
        ];
        if state == "completed" {
            cases.extend([
                ("/operation/version", json!(999)),
                ("/operation", Value::Null),
                ("/operation/terminal_replay", Value::Null),
                ("/operation/dispatch_commit", Value::Null),
                ("/operation/history", json!([])),
                (
                    "/operation/history/0/history/disposition",
                    json!("released_before_dispatch"),
                ),
                (
                    "/operation/history/0/claim/intent/expectationId",
                    json!("another-generation"),
                ),
            ]);
        }
        for (index, (pointer, value)) in cases.into_iter().enumerate() {
            let mut body = original.body();
            *body
                .action
                .parameters
                .pointer_mut(pointer)
                .ok_or("mutation target")? = value;
            let parameters = body.action.parameters.clone();
            body.action = ToolCallAction::from_parameters(parameters.clone())?;
            body.content_hash = sha256_hex(&canonical_json_bytes(&parameters)?);
            body.id.clear();
            let signed = ChioReceipt::sign(body, &signer)?;
            assert!(signed.verify_signature()?);
            let path = folder.join(format!("substitution-{index}.json"));
            std::fs::write(&path, canonical_json_bytes(&signed)?)?;
            let rejected = verify(&path, runtime, &folder, &key)?;
            assert!(!rejected.status.success(), "accepted {name} {pointer}");
        }
        let mut unsigned = serde_json::to_value(&original)?;
        unsigned["action"]["parameters"]["operation"]["private_request"] = json!({});
        let path = folder.join("unsigned-change.json");
        std::fs::write(&path, serde_json::to_vec(&unsigned)?)?;
        assert!(!verify(&path, runtime, &folder, &key)?.status.success());
    }
    assert_eq!(counts, [2, 2]);
    Ok(())
}
