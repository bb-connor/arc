//! Actual SIGKILL recovery while the separately owned private chain survives.
use super::{
    agreement::SignedAgreement,
    lifecycle,
    native::Native,
    process::{counts, Server, SocketSource},
    smoke::{setup, Scenario},
};
use crate::common::{self, Result};
use serde_json::{json, Value};
use std::{
    os::unix::process::ExitStatusExt,
    path::Path,
    process::{Command, Stdio},
    sync::Arc,
};

const POINTS: &[&str] = &[
    "after-submission",
    "claim-after-prepare",
    "claim-after-broadcast",
    "after-claim",
    "after-decision",
    "decision-after-prepare",
    "decision-after-broadcast",
    "after-recorded-decision",
    "pay-after-prepare",
    "pay-after-broadcast",
    "pay-after-observation",
    "refund-after-prepare",
    "refund-after-broadcast",
    "refund-after-observation",
    "before-native-acknowledgement",
];

fn validate(mode: &str, fault: &str) -> Result<()> {
    if !["pay", "reject", "absent", "unavailable"].contains(&mode)
        || (fault != "resume" && !POINTS.contains(&fault))
    {
        return Err("unsupported lifecycle process-loss scenario".into());
    }
    Ok(())
}

pub fn worker(state: &Path, socket: &Path, mode: &str, fault: &str) -> Result<Value> {
    validate(mode, fault)?;
    let source = Arc::new(SocketSource(socket.to_owned()));
    let native = Native::open(state, source.clone())?;
    let request: chio_kernel::ToolCallRequest =
        super::evidence::read(state.join("original-request.json"))?;
    let fault = fault.to_owned();
    let checkpoint: super::Checkpoint = Arc::new(move |point| {
        if point == fault {
            common::crash()
        } else {
            Ok(())
        }
    });
    let entry = native
        .journal
        .by_request(&request.request_id)?
        .ok_or("original worker entry missing")?;
    lifecycle::progress(state, &native, &request, mode, &checkpoint, &|phase| {
        source.request(&json!({"method":"advance","allocation":entry.allocation,"phase":phase}))?;
        Ok(())
    })
}

pub fn run(state: &Path, mode: &str, fault: &str) -> Result<Value> {
    let expire_decision = mode.ends_with("-expired");
    let mode = mode.strip_suffix("-expired").unwrap_or(mode);
    validate(mode, fault)?;
    let Scenario {
        chain,
        native,
        agreement,
        request,
        funding,
    } = setup(state)?;
    chain.request(json!({"method":"pin-verifier","key":native.policy.verifier_key.to_hex()}))?;
    let first = native.execute(&agreement, &request)?;
    std::fs::write(
        state.join("original-agreement.json"),
        chio_core_types::canonical_json_bytes(&agreement)?,
    )?;
    std::fs::write(
        state.join("original-request.json"),
        chio_core_types::canonical_json_bytes(&request)?,
    )?;
    drop(native);
    let allocation = funding["allocationId"]
        .as_str()
        .ok_or("allocation missing")?
        .to_owned();
    let socket = state.join("observer.sock");
    let mut server = Server::start(&socket, allocation.clone(), chain.clone())?;
    let child = Command::new(std::env::current_exe()?)
        .arg("experimental-funded-lifecycle-worker")
        .arg(state)
        .arg(&socket)
        .arg(mode)
        .arg(fault)
        .stdin(Stdio::null())
        .output()?;
    if child.status.signal() != Some(9) {
        return Err(format!(
            "lifecycle worker did not hit SIGKILL checkpoint: {:?}: {}",
            child.status,
            String::from_utf8_lossy(&child.stderr)
        )
        .into());
    }
    let before = counts(state)?;
    if expire_decision {
        chain.request(json!({"method":"advance","allocation":allocation,"phase":"refund"}))?;
    }
    let agreement: SignedAgreement = super::evidence::read(state.join("original-agreement.json"))?;
    let resumed = Command::new(std::env::current_exe()?)
        .arg("experimental-funded-lifecycle-worker")
        .arg(state)
        .arg(&socket)
        .arg(mode)
        .arg("resume")
        .stdin(Stdio::null())
        .output()?;
    server.finish()?;
    if !resumed.status.success() {
        return Err(format!(
            "restarted lifecycle worker failed: {}",
            String::from_utf8_lossy(&resumed.stderr)
        )
        .into());
    }
    let recovered: Value = serde_json::from_slice(&resumed.stdout)?;
    let native = Native::open(state, chain.clone())?;
    let replay = native.execute(&agreement, &request)?;
    let again = native.execute(&agreement, &request)?;
    if replay["operationId"] != again["operationId"]
        || replay["holdId"] != again["holdId"]
        || replay["executions"] != again["executions"]
    {
        return Err("settlement recovery changed native identity or executed twice".into());
    }
    let chain = chain.request(json!({"method":"summary","allocation":allocation}))?;
    Ok(
        json!({"checkpoint":fault,"killedSignal":9,"first":first,"before":before,"after":counts(state)?,"verification":recovered,"replay":replay,"chain":chain}),
    )
}

pub fn admission_loss(state: &Path, unknown_execution: bool) -> Result<Value> {
    let Scenario {
        chain,
        native,
        agreement,
        request,
        funding,
    } = setup(state)?;
    let allocation = funding["allocationId"]
        .as_str()
        .ok_or("allocation missing")?
        .to_owned();
    std::fs::write(
        state.join("original-agreement.json"),
        chio_core_types::canonical_json_bytes(&agreement)?,
    )?;
    std::fs::write(
        state.join("original-request.json"),
        chio_core_types::canonical_json_bytes(&request)?,
    )?;
    drop(native);
    let fault = if unknown_execution {
        "after-tool"
    } else {
        "after-hold"
    };
    let socket = state.join("observer.sock");
    let mut server = Server::start(&socket, allocation.clone(), chain.clone())?;
    let child = Command::new(std::env::current_exe()?)
        .arg("experimental-funded-worker")
        .arg(state)
        .arg(&socket)
        .arg(fault)
        .stdin(Stdio::null())
        .output()?;
    server.finish()?;
    if child.status.signal() != Some(9) {
        return Err(format!(
            "native admission loss did not occur: {}",
            String::from_utf8_lossy(&child.stderr)
        )
        .into());
    }
    let before = counts(state)?;
    let native = Native::open(state, chain.clone())?;
    let first = native.report(&request)?;
    let checkpoint: super::Checkpoint = Arc::new(|_| Ok(()));
    let verification =
        lifecycle::progress(state, &native, &request, "absent", &checkpoint, &|phase| {
            chain.request(json!({"method":"advance","allocation":allocation,"phase":phase}))?;
            Ok(())
        })?;
    drop(native);
    let native = Native::open(state, chain.clone())?;
    let replay = native.execute(&agreement, &request)?;
    let summary = chain.request(json!({"method":"summary","allocation":allocation}))?;
    Ok(
        json!({"checkpoint":fault,"killedSignal":9,"first":first,"before":before,"after":counts(state)?,
        "verification":verification,"replay":replay,"chain":summary}),
    )
}
