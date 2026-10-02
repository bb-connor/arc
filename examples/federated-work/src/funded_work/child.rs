//! Signed parent/child dependency and execution through the child's own kernel.
use super::{
    agreement::SignedAgreement,
    evidence::{self, Signed},
    native::Native,
    observer::FundingSource,
};
use crate::common::{self, digest, Result};
use chio_core_types::PublicKey;
use chio_kernel::ToolCallRequest;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{path::Path, sync::Arc};

pub(super) type AdvanceClock = Arc<dyn Fn(&str) -> Result<()> + Send + Sync>;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Dependency {
    pub(super) schema: String,
    pub(super) parent_agreement: String,
    pub(super) child_agreement: String,
    pub(super) parent_request: String,
    pub(super) child_request: String,
    pub(super) parent_authority: String,
    pub(super) child_authority: String,
    pub(super) input_sha256: String,
}

pub(super) fn retain(
    state: &Path,
    parent: &super::smoke::Scenario,
    child: &super::smoke::Scenario,
) -> Result<()> {
    let input = parent.request.arguments["input"]
        .as_str()
        .ok_or("parent input missing")?;
    if child.request.arguments["input"].as_str() != Some(input)
        || child.native.policy.buyer_key != parent.native.policy.provider_key
        || child.native.policy.authority_uuid == parent.native.policy.authority_uuid
        || child.funding["allocationId"] == parent.funding["allocationId"]
    {
        return Err("subcontract must have separate funded authority for the same input".into());
    }
    let body = Dependency {
        schema: "chio.experimental.native-funded-dependency.v1".into(),
        parent_agreement: digest(&parent.agreement)?,
        child_agreement: digest(&child.agreement)?,
        parent_request: digest(&parent.request)?,
        child_request: digest(&child.request)?,
        parent_authority: parent.native.policy.authority_uuid.clone(),
        child_authority: child.native.policy.authority_uuid.clone(),
        input_sha256: chio_core_types::sha256_hex(input.as_bytes()),
    };
    write(
        &state.join("dependency.json"),
        &evidence::sign(body, &common::key(&state.join("parent"))?)?,
    )?;
    for (role, scenario) in [("parent", parent), ("child", child)] {
        write(
            &state.join(role).join("original-agreement.json"),
            &scenario.agreement,
        )?;
        write(
            &state.join(role).join("original-request.json"),
            &scenario.request,
        )?;
    }
    Ok(())
}

fn write(path: &Path, value: &impl Serialize) -> Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(&chio_core_types::canonical_json_bytes(value)?)?;
    file.sync_all()?;
    Ok(())
}

pub(super) fn verify_dependency(
    signed: &Signed<Dependency>,
    parent: &SignedAgreement,
    parent_request: &ToolCallRequest,
    child: &SignedAgreement,
    child_request: &ToolCallRequest,
    parent_key: &PublicKey,
) -> Result<()> {
    super::wire::dependency(signed)?;
    let b = &signed.body;
    if b.schema != "chio.experimental.native-funded-dependency.v1"
        || !parent_key.verify_strict(
            &chio_core_types::canonical_json_bytes(b)?,
            &signed.signature,
        )
        || b.parent_agreement != digest(parent)?
        || b.child_agreement != digest(child)?
        || b.parent_request != digest(parent_request)?
        || b.child_request != digest(child_request)?
        || b.parent_authority != parent.body.authority_uuid
        || b.child_authority != child.body.authority_uuid
        || b.parent_authority == b.child_authority
        || parent.body.provider_key != *parent_key
        || child.body.buyer_key != *parent_key
        || parent_request.arguments["input"] != child_request.arguments["input"]
        || b.input_sha256
            != chio_core_types::sha256_hex(
                parent_request.arguments["input"]
                    .as_str()
                    .ok_or("dependency input missing")?
                    .as_bytes(),
            )
    {
        return Err("signed native dependency differs from original authority or input".into());
    }
    Ok(())
}

pub(super) fn executor(
    state: &Path,
    source: Arc<dyn FundingSource>,
    advance: AdvanceClock,
) -> Result<super::tool::Subcontract> {
    let dependency: Signed<Dependency> =
        evidence::decode(&std::fs::read(state.join("dependency.json"))?)?;
    let parent: SignedAgreement =
        super::evidence::read(state.join("parent/original-agreement.json"))?;
    let parent_request = super::evidence::read(state.join("parent/original-request.json"))?;
    let child: SignedAgreement =
        super::evidence::read(state.join("child/original-agreement.json"))?;
    let request: ToolCallRequest =
        super::evidence::read(state.join("child/original-request.json"))?;
    verify_dependency(
        &dependency,
        &parent,
        &parent_request,
        &child,
        &request,
        &parent.body.provider_key,
    )?;
    let state = state.join("child");
    Ok(Arc::new(move |input| {
        if request.arguments["input"].as_str() != Some(input) {
            return Err("parent substituted the agreed subcontract input".into());
        }
        // The parent invokes this hook from its asynchronous tool dispatch.
        // Give the child's blocking kernel API its own executor thread. The
        // scoped join preserves errors and cannot leave detached child work.
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let native = Native::open(&state, source.clone())?;
                    native.execute(&child, &request)?;
                    let checkpoint: super::Checkpoint = Arc::new(|_| Ok(()));
                    let earned = super::lifecycle::progress(
                        &state,
                        &native,
                        &request,
                        "earn",
                        &checkpoint,
                        advance.as_ref(),
                    )?;
                    if earned["financial"] != "payable" {
                        return Err("child has not earned an observed payment claim".into());
                    }
                    Ok(native.evidence(&request)?.output)
                })
                .join()
                .map_err(|_| "child kernel worker panicked")?
        })
    }))
}

/// Collection consumes the original child artifacts and beneficiary authority.
/// It never reruns work, issues a decision, or loads a parent private key.
pub(super) fn collect(
    state: &Path,
    source: Arc<dyn FundingSource>,
    checkpoint: super::Checkpoint,
) -> Result<Value> {
    let native = Native::open(state, source.clone())?;
    let request: ToolCallRequest = super::evidence::read(state.join("original-request.json"))?;
    let entry = native
        .journal
        .by_request(&request.request_id)?
        .ok_or("original child entry missing")?;
    let observed = super::settlement::drive(
        &entry,
        super::settlement::Action::Pay,
        &native.policy,
        &native.journal,
        source.as_ref(),
        &checkpoint,
    )?;
    drop(native);
    let native = Native::open(state, source)?;
    let agreement = super::evidence::read(state.join("original-agreement.json"))?;
    let report = native.execute(&agreement, &request)?;
    if report["paymentState"] != "paid" || report["executions"] != 1 {
        return Err("child payout did not reconcile the original single execution".into());
    }
    Ok(json!({"replay":report,"transactionHash":observed.transaction_hash}))
}
