//! Bounded files and separately configured observation for verifier handoff.
use super::{
    checkpoint_files, evidence, native::Native, process::SocketSource, verification::Decision,
    verifier_handoff,
};
use crate::common::Result;
use std::{path::Path, sync::Arc};

pub fn export(
    state: &Path,
    request_id: &str,
    socket: &Path,
    output: &Path,
) -> Result<serde_json::Value> {
    let native = Native::open_for_checkpoint(state, Arc::new(SocketSource(socket.to_owned())))?;
    let entry = native
        .journal
        .by_request(request_id)?
        .ok_or("original funded request missing")?;
    let request = verifier_handoff::export(&native, &entry.request)?;
    checkpoint_files::write(output, &request)?;
    Ok(serde_json::json!({"requestSha256":crate::common::digest(&request)?}))
}

pub fn import(
    state: &Path,
    request_id: &str,
    socket: &Path,
    input: &Path,
) -> Result<serde_json::Value> {
    let decision: Decision = evidence::read(input)?;
    let native = Native::open_for_checkpoint(state, Arc::new(SocketSource(socket.to_owned())))?;
    let entry = native
        .journal
        .by_request(request_id)?
        .ok_or("original funded request missing")?;
    verifier_handoff::import(&native, &entry.request, &decision)?;
    Ok(serde_json::json!({"decisionSha256":crate::common::digest(&decision.body)?}))
}
