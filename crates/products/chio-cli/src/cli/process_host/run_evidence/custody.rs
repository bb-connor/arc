//! Signed readback of the existing operation-owned continuation ledger.

use std::collections::BTreeSet;

use chio_kernel::admission_operation::runtime_participant::{
    RuntimeParticipantClaimEvidenceV1, RuntimeParticipantClaimReferenceV1,
    RuntimeParticipantDisposition, RuntimeParticipantPhase, MAX_RUNTIME_PARTICIPANT_EPISODES,
};
use chio_kernel::admission_operation::{
    AdmissionOperationId, AdmissionOperationState, RuntimeReplayParticipantKind,
};

use super::*;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Observation {
    operation_id: AdmissionOperationId,
    request_id: String,
    capability_id: String,
    request_binding_sha256: String,
    state: AdmissionOperationState,
    terminal_receipt_id: String,
    history: Vec<RuntimeParticipantClaimEvidenceV1>,
}

fn replay(receipt: &ChioReceipt) -> Result<&Value, CliError> {
    receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata["chio_runtime"].get("operation_owned_replay"))
        .ok_or_else(|| error("missing operation-owned replay evidence"))
}

#[cfg(target_os = "linux")]
pub(super) fn export(
    host: &super::super::state::Host,
    receipt: &ChioReceipt,
    now: u64,
) -> Result<Observation, CliError> {
    use chio_kernel::admission_operation::AdmissionTerminalReplay;

    let reference: RuntimeParticipantClaimReferenceV1 =
        serde_json::from_value(replay(receipt)?["reference"].clone()).map_err(error)?;
    let (store, fence) = host
        .authority
        .local_runtime_participant()
        .ok_or_else(|| error("missing local continuation custody authority"))?;
    let (operation, history) = store
        .load_runtime_participant_evidence(reference.operation_id(), &fence, now)
        .map_err(error)?
        .ok_or_else(|| error("continuation custody operation is absent"))?;
    let Some(AdmissionTerminalReplay::Receipt { receipt_id, .. }) = operation.terminal_replay()
    else {
        return Err(error("custody operation has no completed receipt"));
    };
    require(
        operation.state() == AdmissionOperationState::Completed
            && operation.dispatch_commit().is_some()
            && receipt_id.as_str() == receipt.id,
        "custody operation did not complete this tool receipt",
    )?;
    let binding = operation.binding();
    Ok(Observation {
        operation_id: binding.operation_id().clone(),
        request_id: binding.request_id().as_str().into(),
        capability_id: binding.capability_id().as_str().into(),
        request_binding_sha256: binding.request_binding_hash().as_str().into(),
        state: operation.state(),
        terminal_receipt_id: receipt_id.as_str().into(),
        history,
    })
}

pub(super) fn verify(
    observation: &Observation,
    receipt: &ChioReceipt,
    token: &chio_swarm_authority::SwarmContinuationToken,
    runtime_id: &str,
    nonce: Option<&super::super::nonce_evidence::Evidence>,
) -> Result<(), CliError> {
    let owned = replay(receipt)?;
    let reference: RuntimeParticipantClaimReferenceV1 =
        serde_json::from_value(owned["reference"].clone()).map_err(error)?;
    require(
        observation.operation_id == *reference.operation_id()
            && observation.capability_id == receipt.capability_id
            && observation.terminal_receipt_id == receipt.id
            && observation.state == AdmissionOperationState::Completed
            && receipt
                .metadata
                .as_ref()
                .ok_or_else(|| error("missing receipt metadata"))?["receipt_context"]["request_id"]
                == observation.request_id,
        "continuation custody operation differs from completed call",
    )?;
    require(
        !observation.history.is_empty()
            && observation.history.len() <= MAX_RUNTIME_PARTICIPANT_EPISODES,
        "continuation custody history is absent or exceeds its bound",
    )?;
    let mut episodes = BTreeSet::new();
    let mut retained = None;
    for evidence in &observation.history {
        evidence.verify().map_err(error)?;
        let claim = &evidence.history;
        claim.intent.validate().map_err(error)?;
        require(
            claim.reference.operation_id() == &observation.operation_id
                && claim.reference.episode_id() == claim.intent.episode_id()
                && claim.intent.runtime_authority_id().as_str() == runtime_id
                && claim.intent.request_binding_hash().as_str()
                    == observation.request_binding_sha256
                && episodes.insert(claim.reference.episode_id().as_str()),
            "continuation custody history has substituted or duplicate episodes",
        )?;
        if claim.reference == reference {
            if let Some(nonce) = nonce {
                let original =
                    chio_kernel::admission_operation::AdmissionOperationV1::from_persisted(
                        evidence.operation.clone(),
                    )
                    .map_err(error)?;
                let current =
                    chio_kernel::admission_operation::AdmissionOperationV1::from_persisted(
                        nonce.operation.clone(),
                    )
                    .map_err(error)?;
                require(
                    original.binding() == current.binding()
                        && original.execution_nonce_issuance_digest()
                            == current.execution_nonce_issuance_digest(),
                    "execution nonce differs from original continuation commitment",
                )?;
            }
            require(
                claim.disposition == RuntimeParticipantDisposition::RetainedAfterDispatchCommit,
                "completed continuation custody is not retained",
            )?;
            retained = Some(claim);
        } else {
            require(
                claim.disposition == RuntimeParticipantDisposition::ReleasedBeforeDispatch,
                "another continuation episode remains live",
            )?;
        }
    }
    let claim = retained.ok_or_else(|| error("signed continuation custody reference is absent"))?;
    let resources = claim.intent.resources();
    require(
        claim.intent.phase() == RuntimeParticipantPhase::Dispatch
            && owned["plan_sha256"] == claim.intent.plan_digest().as_str()
            && owned["resources_sha256"] == hash(&resources)?
            && resources.len() == 1,
        "continuation custody prepared plan differs from signed receipt",
    )?;
    require(
        resources[0].kind() == RuntimeReplayParticipantKind::SwarmContinuation
            && resources[0].resource_id().as_str() == token.token_id
            && resources[0].artifact_digest().as_str() == hash(token)?,
        "continuation custody does not retain the issued single-use token",
    )
}
