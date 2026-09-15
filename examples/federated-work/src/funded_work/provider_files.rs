//! Provider-only native request, execution and financial commands.
use super::{
    checkpoint_files as files, evidence,
    native::Native,
    process::SocketSource,
    settlement::{self, Action},
    work_consent as consent,
};
use crate::common::{self, Result};
use serde_json::{json, Value};
use std::{path::Path, sync::Arc};
fn open(state: &Path, socket: &Path) -> Result<Native> {
    Native::open_for_checkpoint(state, Arc::new(SocketSource(socket.to_owned())))
}
pub fn propose(state: &Path, intent: &Path, input: &Path, output: &Path) -> Result<Value> {
    let native = open(state, Path::new("/unavailable"))?;
    let input: String = evidence::read(input)?;
    let proposal = consent::propose(&native, &evidence::read(intent)?, &input)?;
    files::write(output, &proposal)?;
    Ok(json!({"proposalSha256":common::digest(&proposal)?}))
}
pub fn accept(state: &Path, intent: &Path, proposal: &Path, output: &Path) -> Result<Value> {
    let accepted = consent::accept(state, &evidence::read(intent)?, &evidence::read(proposal)?)?;
    files::write(output, &accepted)?;
    Ok(json!({"acceptanceSha256":common::digest(&accepted)?}))
}
pub fn execute(state: &Path, socket: &Path, acceptance: &Path) -> Result<Value> {
    let native = Native::open(state, Arc::new(SocketSource(socket.to_owned())))?;
    let (agreement, request) = consent::original(&native, &evidence::read(acceptance)?)?;
    native.execute(&agreement, &request)
}
pub fn output(state: &Path, id: &str, output: &Path) -> Result<Value> {
    let native = open(state, Path::new("/unavailable"))?;
    let entry = native
        .journal
        .by_request(id)?
        .ok_or("original request missing")?;
    let original = native.evidence(&entry.request)?;
    files::write(output, &original.output)?;
    Ok(json!({"outputSha256":common::digest(&original.output)?}))
}
pub fn submit(state: &Path, id: &str, socket: &Path, candidate: &Path) -> Result<Value> {
    let native = open(state, socket)?;
    let entry = native
        .journal
        .by_request(id)?
        .ok_or("original request missing")?;
    let original = native.evidence(&entry.request)?;
    let output: Value = evidence::read(candidate)?;
    let submission = match native
        .journal
        .retained::<super::evidence::Submission>(&entry.allocation, "submission")?
    {
        Some(value) => {
            if value.body.output_sha256 != common::digest(&output)? {
                return Err("submission retry changed original output".into());
            }
            value
        }
        None => {
            let value =
                evidence::submit(&original, &output, &common::key(state)?, &native.journal)?;
            native
                .journal
                .retain(&entry.allocation, "submission", &value)?;
            value
        }
    };
    let checkpoint: super::Checkpoint = Arc::new(|_| Ok(()));
    let claim = settlement::drive(
        &entry,
        Action::Submit,
        &native.policy,
        &native.journal,
        native.source.as_ref(),
        &checkpoint,
    )?;
    Ok(
        json!({"submissionSha256":common::digest(&submission)?,"claimTransactionHash":claim.transaction_hash}),
    )
}
pub fn settle(state: &Path, id: &str, socket: &Path) -> Result<Value> {
    let native = open(state, socket)?;
    let entry = native
        .journal
        .by_request(id)?
        .ok_or("original request missing")?;
    let decision: super::verification::Decision = native
        .journal
        .retained(&entry.allocation, "decision")?
        .ok_or("original imported decision missing")?;
    let checkpoint: super::Checkpoint = Arc::new(|_| Ok(()));
    settlement::drive(
        &entry,
        Action::Record,
        &native.policy,
        &native.journal,
        native.source.as_ref(),
        &checkpoint,
    )?;
    let action = if decision.body.accepted {
        Action::Pay
    } else {
        Action::Refund
    };
    let observed = settlement::drive(
        &entry,
        action,
        &native.policy,
        &native.journal,
        native.source.as_ref(),
        &checkpoint,
    )?;
    Ok(json!({"accepted":decision.body.accepted,"transactionHash":observed.transaction_hash}))
}
