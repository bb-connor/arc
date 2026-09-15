//! Real process-loss checkpoints around native contractual resolution.
use super::{
    capture_resolution,
    native::Native,
    process::{Server, SocketSource},
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
    "none",
    "after-resolution-retained",
    "after-resolution-accepted",
    "after-resolution-completed",
];

pub fn worker(state: &Path, socket: &Path, fault: &str) -> Result<Value> {
    if !POINTS.contains(&fault) {
        return Err("unsupported resolution checkpoint".into());
    }
    let source = Arc::new(SocketSource(socket.to_owned()));
    let native = Native::open_for_resolution(state, source.clone())?;
    let request = common::read(state.join("original-request.json"))?;
    let point = fault.to_owned();
    let checkpoint: super::Checkpoint = Arc::new(move |current| {
        if current == point {
            common::crash()
        } else {
            Ok(())
        }
    });
    let resolution = capture_resolution::resolve(state, &native, &request, &checkpoint)?;
    drop(native);
    let native = Native::open(state, source)?;
    let agreement = common::read(state.join("original-agreement.json"))?;
    let report = native.execute(&agreement, &request)?;
    Ok(
        json!({"resolution":resolution,"after":report,"financial":capture_resolution::financial(state,&native,&request)?}),
    )
}

fn successful(output: std::process::Output) -> Result<Value> {
    if !output.status.success() {
        return Err(format!(
            "resolution worker failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

pub fn run(state: &Path, mode: &str, fault: &str) -> Result<Value> {
    if !["reject", "absent", "unavailable", "preexpired"].contains(&mode)
        || !POINTS.contains(&fault)
    {
        return Err("unsupported contractual refund scenario".into());
    }
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
    chain.request(json!({"method":"pin-verifier","key":native.policy.verifier_key.to_hex()}))?;
    native.execute(&agreement, &request)?;
    let no_fault: super::Checkpoint = Arc::new(|_| Ok(()));
    if mode == "preexpired" {
        chain.request(json!({"method":"advance","allocation":allocation,"phase":"refund"}))?;
        chain.request(json!({"method":"expire","allocation":allocation}))?;
    }
    super::lifecycle::progress(state, &native, &request, mode, &no_fault, &|phase| {
        chain.request(json!({"method":"advance","allocation":allocation,"phase":phase}))?;
        Ok(())
    })?;
    let before = native.report(&request)?;
    let source_before = capture_resolution::original_sources(state, &native, &request)?;
    for (name, value) in [
        ("original-request.json", serde_json::to_value(&request)?),
        ("original-agreement.json", serde_json::to_value(&agreement)?),
    ] {
        std::fs::write(
            state.join(name),
            chio_core_types::canonical_json_bytes(&value)?,
        )?;
    }
    drop(native);
    let socket = state.join("observer.sock");
    let mut server = Server::start(&socket, allocation.clone(), chain.clone())?;
    let invoke = |fault: &str| -> Result<std::process::Output> {
        Ok(Command::new(std::env::current_exe()?)
            .arg("experimental-funded-resolution-worker")
            .arg(state)
            .arg(&socket)
            .arg(fault)
            .stdin(Stdio::null())
            .output()?)
    };
    let output = invoke(fault)?;
    let killed = if fault == "none" {
        None
    } else {
        if output.status.signal() != Some(9) {
            return Err(format!(
                "resolution checkpoint did not SIGKILL: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Some(9)
    };
    let completed = successful(if killed.is_some() {
        invoke("none")?
    } else {
        output
    })?;
    let replay = successful(invoke("none")?)?;
    if completed != replay {
        return Err("native waiver changed after successful replay".into());
    }
    server.finish()?;
    let native = Native::open(state, chain.clone())?;
    let source_after = capture_resolution::original_sources(state, &native, &request)?;
    if source_before != source_after {
        return Err("waiver changed original capture, outcome or consumed budget history".into());
    }
    Ok(
        json!({"before":before,"after":completed["after"],"financial":completed["financial"],"resolution":completed["resolution"],
        "killedSignal":killed,"sourceBefore":source_before,"sourceAfter":source_after,
        "chain":chain.request(json!({"method":"summary","allocation":allocation}))?}),
    )
}
