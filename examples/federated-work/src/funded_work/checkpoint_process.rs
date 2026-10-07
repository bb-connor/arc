//! Owned local-chain reproduction of the portable operator artifact boundary.
use super::{checkpoint_files as files, checkpoint_operator as operator, evidence, native::Native};
use crate::common::{digest, Result};
use serde_json::{json, Value};
use std::{fs, path::Path, process::Command, sync::Arc};

fn command(args: &[&std::ffi::OsStr]) -> Result<Value> {
    let output = Command::new(std::env::current_exe()?).args(args).output()?;
    if !output.status.success() {
        return Err(format!(
            "checkpoint participant failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

pub fn run(root: &Path, mode: &str) -> Result<Value> {
    if !["pay", "reject"].contains(&mode) {
        return Err("checkpoint lifecycle supports pay or reject".into());
    }
    let state = root.join("provider");
    let separate = root.join("operator");
    let f = super::smoke::setup(&state)?;
    fs::create_dir(&separate)?;
    // Fixture-only provisioning transfers keys before execution. These processes
    // remain under the same test owner, not independent administrations.
    for role in ["checkpoint", "status"] {
        fs::rename(state.join(role), separate.join(role))?;
    }
    let enrollment = root.join("enrollment.json");
    files::write(
        &enrollment,
        &operator::Enrollment {
            schema: operator::ENROLLMENT_SCHEMA.into(),
            authority_uuid: f.native.policy.authority_uuid.clone(),
            context: f.native.policy.finding_context.clone(),
        },
    )?;
    command(&[
        "experimental-checkpoint-init".as_ref(),
        separate.as_os_str(),
        enrollment.as_os_str(),
    ])?;
    f.chain
        .request(json!({"method":"pin-verifier","key":f.native.policy.verifier_key.to_hex()}))?;
    let first = f.native.execute(&f.agreement, &f.request)?;
    drop(f.native);
    let request = root.join("request.json");
    command(&[
        "experimental-checkpoint-export".as_ref(),
        state.as_os_str(),
        f.request.request_id.as_ref(),
        request.as_os_str(),
    ])?;
    let response = root.join("response.json");
    command(&[
        "experimental-checkpoint-sign".as_ref(),
        separate.as_os_str(),
        request.as_os_str(),
        response.as_os_str(),
    ])?;
    for role in ["checkpoint", "status"] {
        fs::remove_file(separate.join(role).join("key.seed"))?;
    }
    let repeated = root.join("response-replay.json");
    command(&[
        "experimental-checkpoint-sign".as_ref(),
        separate.as_os_str(),
        request.as_os_str(),
        repeated.as_os_str(),
    ])?;
    if fs::read(&response)? != fs::read(&repeated)? {
        return Err("operator restart changed original response".into());
    }
    command(&[
        "experimental-checkpoint-import".as_ref(),
        state.as_os_str(),
        f.request.request_id.as_ref(),
        response.as_os_str(),
    ])?;
    let native = Native::open(&state, f.chain.clone())?;
    let original = native.evidence(&f.request)?;
    let checkpoint: super::Checkpoint = Arc::new(|_| Ok(()));
    let progress =
        super::lifecycle::progress(&state, &native, &f.request, mode, &checkpoint, &|phase| {
            f.chain.request(
                json!({"method":"advance","allocation":f.funding["allocationId"],"phase":phase}),
            )?;
            Ok(())
        })?;
    let allocation = &original.binding.allocation_id;
    let submission: evidence::Submission = native
        .journal
        .retained(allocation, "submission")?
        .ok_or("submission missing")?;
    let decision: super::verification::Decision = native
        .journal
        .retained(allocation, "decision")?
        .ok_or("decision missing")?;
    let output: Value = evidence::decode(&native.journal.blob(&submission.body.output_sha256)?)?;
    files::write(
        &root.join("witness.json"),
        &json!({
            "agreement":f.agreement, "submission":submission, "context":native.policy.finding_context,
            "bundle":original.execution, "output":output,
        }),
    )?;
    files::write(
        &root.join("pins.json"),
        &json!({
            "buyer":native.policy.buyer_key, "provider":native.policy.provider_key,
            "verifier":native.policy.verifier_key, "authorityUuid":native.policy.authority_uuid,
            "allocationId":f.funding["allocationId"],
        }),
    )?;
    drop(native);
    let recovered = Native::open(&state, f.chain.clone())?;
    let replay = recovered.execute(&f.agreement, &f.request)?;
    let chain = f
        .chain
        .request(json!({"method":"summary","allocation":f.funding["allocationId"]}))?;
    Ok(
        json!({"first":first,"verification":progress,"replay":replay,"chain":chain,
        "responseReplayWithoutKeys":true,"providerHasNoCheckpointKeys":!state.join("checkpoint").exists() && !state.join("status").exists(),
        "operatorProcesses":3,"providerHandoffProcesses":2,"independentAdministration":false,
        "bundleSha256":digest(&evidence::read::<super::execution_evidence::Bundle>(&response)?)?,
        "evaluatedAt":decision.body.finding_assessment.evaluated_at}),
    )
}
