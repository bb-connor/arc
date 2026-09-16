//! Signed readback of one call. It grants no authority and asserts no graph completion.

use std::{collections::BTreeSet, io::Read, path::Path};

use chio_core::{
    capability::token::CapabilityToken,
    crypto::{canonical_json_bytes, sha256_hex, PublicKey},
    receipt::{body::ChioReceipt, decision::Decision, kinds::*},
};
use chio_kernel::admission_operation::{
    runtime_participant::{
        RuntimeParticipantClaimEvidenceV1, RuntimeParticipantClaimReferenceV1,
        RuntimeParticipantDisposition, RuntimeParticipantPhase, MAX_RUNTIME_PARTICIPANT_EPISODES,
    },
    AdmissionDispatchCommitBindingV1, AdmissionDispatchState, AdmissionOperationBindingV1,
    AdmissionOperationKind, AdmissionOperationState, AdmissionReceiptMetadataV1,
    AdmissionTerminalReplay, PersistedAdmissionOperationBindingV1,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::state::error;
use crate::CliError;

#[cfg(target_os = "linux")]
#[path = "call_evidence/export.rs"]
mod exporting;
#[cfg(target_os = "linux")]
pub(super) use exporting::export;

const SCHEMA: &str = "chio.process.call-observation.v1";
const LIMIT: u64 = 32 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    schema: String,
    runtime_id: String,
    observed_at_unix_ms: u64,
    bootstrap: ChioReceipt,
    request: Value,
    context: Value,
    response: Value,
    operation: Option<Operation>,
}

/// Only public binding digests and the existing claim commitment preimages.
/// The private RetainedToolAdmissionRequestV1 is never serialized here.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Operation {
    binding: PersistedAdmissionOperationBindingV1,
    state: AdmissionOperationState,
    version: u64,
    dispatch_state: AdmissionDispatchState,
    dispatch_commit: Option<AdmissionDispatchCommitBindingV1>,
    terminal_replay: Option<AdmissionTerminalReplay>,
    history: Vec<RuntimeParticipantClaimEvidenceV1>,
}

fn require(condition: bool, message: &str) -> Result<(), CliError> {
    if condition {
        Ok(())
    } else {
        Err(error(message))
    }
}

fn hash<T: Serialize>(value: &T) -> Result<String, CliError> {
    canonical_json_bytes(value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(error)
}

fn text(path: &Path) -> Result<String, CliError> {
    let file = std::fs::File::open(path)?;
    require(
        file.metadata()?.is_file(),
        "call evidence input must be a regular file",
    )?;
    let mut text = String::new();
    file.take(LIMIT + 1).read_to_string(&mut text)?;
    require(
        text.len() as u64 <= LIMIT,
        "call evidence input exceeds 32 MiB",
    )?;
    Ok(text)
}

fn receipt(receipt: &ChioReceipt, key: &PublicKey) -> Result<(), CliError> {
    crate::receipt_verify::verify_original_receipt(
        &serde_json::to_string(receipt).map_err(error)?,
        key,
    )?;
    Ok(())
}

fn observation(value: &ChioReceipt, tool: &str) -> Result<(), CliError> {
    require(
        value.receipt_kind == ReceiptKind::TraceObservation
            && value.boundary_class == BoundaryClass::DetectOnly
            && value.observation_outcome == Some(ObservationOutcome::Observed)
            && value.tool_origin == ToolOrigin::ChioInternal
            && value.trust_level == TrustLevel::Verified
            && value.decision.is_none()
            && value.tool_server == "chio-process-host"
            && value.tool_name == tool
            && value.content_hash == hash(&value.action.parameters)?,
        "invalid call observation role or content",
    )
}

fn verify(
    signed: &ChioReceipt,
    evidence: &Evidence,
    key: &PublicKey,
    runtime: &str,
) -> Result<(), CliError> {
    receipt(signed, key)?;
    observation(signed, "attest_retained_call")?;
    require(
        !runtime.is_empty()
            && evidence.runtime_id == runtime
            && evidence.schema == SCHEMA
            && signed.action.parameters == serde_json::to_value(evidence).map_err(error)?,
        "call schema, runtime pin or signed payload differs",
    )?;
    receipt(&evidence.bootstrap, key)?;
    observation(&evidence.bootstrap, "provision_swarm")?;
    require(
        evidence.bootstrap.action.parameters["runtime_id"] == runtime
            && evidence.context["runtime_id"] == runtime
            && evidence.observed_at_unix_ms > 0
            && evidence.observed_at_unix_ms < (1_u64 << 53)
            && signed.timestamp == evidence.observed_at_unix_ms / 1000
            && signed.timestamp >= evidence.bootstrap.timestamp
            && signed.policy_hash == evidence.bootstrap.policy_hash
            && signed.capability_id == evidence.bootstrap.capability_id,
        "call observation differs from original provisioning",
    )?;
    let process = evidence.context["process_id"]
        .as_str()
        .ok_or_else(|| error("missing process"))?;
    let cap: CapabilityToken = serde_json::from_value(
        evidence.bootstrap.action.parameters["capabilities"][process].clone(),
    )
    .map_err(error)?;
    require(
        evidence.context["capability_id"] == cap.id,
        "call capability differs from provisioning",
    )?;
    let call = crate::process_response_verify::verify_values(
        &evidence.request,
        &evidence.context,
        &evidence.response,
        key,
    )?;
    require(
        call.timestamp >= evidence.bootstrap.timestamp && call.timestamp <= signed.timestamp,
        "call receipt is outside observation interval",
    )?;
    verify_operation(
        evidence.operation.as_ref(),
        &call,
        &cap,
        runtime,
        evidence.observed_at_unix_ms,
    )
}

fn verify_operation(
    operation: Option<&Operation>,
    call: &ChioReceipt,
    cap: &CapabilityToken,
    runtime: &str,
    observed_at: u64,
) -> Result<(), CliError> {
    let metadata = call
        .metadata
        .as_ref()
        .ok_or_else(|| error("missing call metadata"))?;
    let projection = metadata
        .get("admission_operation")
        .map(|value| {
            serde_json::from_value::<AdmissionReceiptMetadataV1>(value.clone()).map_err(error)
        })
        .transpose()?;
    let owned = &metadata["chio_runtime"]["operation_owned_replay"];
    let Some(operation) = operation else {
        return require(
            projection.is_none()
                && owned.is_null()
                && matches!(call.decision, Some(Decision::Deny { .. })),
            "call without retained operation must be an ordinary denial without custody claims",
        );
    };
    let binding =
        AdmissionOperationBindingV1::from_persisted(operation.binding.clone()).map_err(error)?;
    require(
        binding.kind() == AdmissionOperationKind::ToolDispatch
            && operation.dispatch_state == AdmissionDispatchState::Terminal
            && binding.request_id().as_str() == metadata["receipt_context"]["request_id"]
            && binding.capability_id().as_str() == call.capability_id
            && operation.binding.authorization_capability_hash.as_str() == hash(cap)?
            && binding.action_parameter_hash().as_str() == call.action.parameter_hash
            && binding.policy_hash().as_str() == call.policy_hash
            && operation.version > 0
            && operation.version < (1_u64 << 53),
        "retained operation differs from call binding",
    )?;
    if let Some(projection) = &projection {
        require(
            projection.operation_id == *binding.operation_id()
                && projection.request_id == *binding.request_id()
                && projection.request_namespace_digest == *binding.request_namespace_digest()
                && projection.request_binding_hash == *binding.request_binding_hash()
                && projection.projected_state == operation.state
                && projection.projected_dispatch_state == operation.dispatch_state
                && projection.projected_operation_version == operation.version
                && projection.retained_dispatch_commit == operation.dispatch_commit
                && projection.trusted_time_unix_ms <= observed_at,
            "operation readback differs from original signed admission projection",
        )?;
    }
    let committed = match operation.state {
        AdmissionOperationState::Completed => {
            require(
                projection.is_some()
                    && call.decision == Some(Decision::Allow)
                    && matches!(&operation.terminal_replay, Some(AdmissionTerminalReplay::Receipt { receipt_id, .. }) if receipt_id.as_str() == call.id),
                "completed operation lacks its actual terminal receipt",
            )?;
            true
        }
        AdmissionOperationState::OutcomeUnknownAfterDispatch => {
            require(
                projection.is_some()
                    && matches!(
                        operation.terminal_replay,
                        Some(AdmissionTerminalReplay::Incident { .. })
                    )
                    && matches!(&call.decision, Some(Decision::Deny { guard, .. }) if guard == "kernel")
                    && projection.as_ref().is_some_and(|value| {
                        value.tool_outcome_id.is_none() && value.tool_outcome_version.is_none()
                    })
                    && owned.is_null(),
                "unknown operation must retain uncertainty without a terminal result",
            )?;
            true
        }
        AdmissionOperationState::CompensatedBeforeDispatch => {
            require(
                matches!(call.decision, Some(Decision::Deny { .. }))
                    && owned.is_null()
                    && matches!(
                        operation.terminal_replay,
                        Some(
                            AdmissionTerminalReplay::Receipt { .. }
                                | AdmissionTerminalReplay::Incident { .. }
                        )
                    ),
                "compensated operation must be denied without retained dispatch custody",
            )?;
            false
        }
        _ => {
            return Err(error(
                "call observation requires completed, compensated or retained-unknown state",
            ))
        }
    };
    require(
        operation.dispatch_commit.is_some() == committed,
        "operation dispatch commitment contradicts its observed outcome",
    )?;
    if let Some(commit) = &operation.dispatch_commit {
        require(
            commit.committed_version <= operation.version,
            "dispatch commitment follows observed operation version",
        )?;
    }
    require(
        operation.history.len() <= MAX_RUNTIME_PARTICIPANT_EPISODES,
        "continuation history exceeds its bound",
    )?;
    let reference = if owned.is_null() {
        None
    } else {
        Some(
            serde_json::from_value::<RuntimeParticipantClaimReferenceV1>(
                owned["reference"].clone(),
            )
            .map_err(error)?,
        )
    };
    let mut episodes = BTreeSet::new();
    let mut retained = 0;
    // Recovery signs the historical dispatch projection and a refusal to retry.
    // There was no completed tool receipt carrying a runtime claim reference.
    // Custody in this case is explicitly the exporter's signed store readback.
    let unknown = operation.state == AdmissionOperationState::OutcomeUnknownAfterDispatch;
    for evidence in &operation.history {
        evidence.verify().map_err(error)?;
        let claim = &evidence.history;
        require(
            evidence.operation.binding == operation.binding
                && claim.reference.operation_id() == binding.operation_id()
                && claim.intent.runtime_authority_id().as_str() == runtime
                && claim.intent.request_binding_hash() == binding.request_binding_hash()
                && episodes.insert(claim.reference.episode_id().as_str()),
            "substituted or duplicate continuation episode",
        )?;
        let receipt_reference = Some(&claim.reference) == reference.as_ref();
        let retained_unknown = unknown
            && claim.disposition == RuntimeParticipantDisposition::RetainedAfterDispatchCommit;
        if receipt_reference || retained_unknown {
            require(
                committed
                    && claim.disposition
                        == RuntimeParticipantDisposition::RetainedAfterDispatchCommit
                    && claim.intent.phase() == RuntimeParticipantPhase::Dispatch,
                "retained continuation contradicts dispatch custody",
            )?;
            if receipt_reference {
                require(
                    owned["plan_sha256"] == claim.intent.plan_digest().as_str()
                        && owned["resources_sha256"] == hash(&claim.intent.resources())?,
                    "retained continuation differs from original signed receipt",
                )?;
            }
            retained += 1;
        } else {
            require(
                claim.disposition == RuntimeParticipantDisposition::ReleasedBeforeDispatch,
                "unreferenced continuation episode remains live",
            )?;
        }
    }
    require(
        if committed {
            (reference.is_some() || unknown) && retained == 1
        } else {
            reference.is_none() && retained == 0
        },
        "call continuation custody is missing or contradicts dispatch",
    )
}

pub(super) fn verify_file(
    path: &Path,
    key: &Path,
    runtime: &str,
    request: &Path,
    context: &Path,
) -> Result<(), CliError> {
    let key = crate::load_trusted_kernel_pubkey(key).map_err(error)?;
    let signed = crate::receipt_verify::verify_original_receipt(&text(path)?, &key)?;
    let evidence: Evidence =
        serde_json::from_value(signed.action.parameters.clone()).map_err(error)?;
    let expected_request: Value = crate::process_response_verify::read_document(request)?;
    let expected_context: Value = crate::process_response_verify::read_document(context)?;
    require(
        evidence.request == expected_request && evidence.context == expected_context,
        "call differs from independently retained request or context",
    )?;
    verify(&signed, &evidence, &key, runtime)?;
    println!(
        "{}",
        json!({"schema": "chio.process.call-verification.v1", "runtime_id": runtime,
        "process_id": evidence.context["process_id"], "request_id": evidence.response["request_id"],
        "observed_operation_state": evidence.operation.as_ref().map(|operation| operation.state),
        "custody_binding": match evidence.operation.as_ref().map(|operation| operation.state) {
            Some(AdmissionOperationState::Completed) => "original_call_commitment_and_signed_store_readback",
            Some(_) => "signed_store_readback",
            None => "no_custody_claim",
        },
        "checks": ["signer_pin", "runtime_pin", "original_request", "issued_capability", "worker_response", "retained_operation", "continuation_custody"],
        "unchecked": ["task_authority", "aggregate_usage", "confinement", "physical_effects", "execution_nonces", "graph_completion", "scenario_matrix"],
        "m5_acceptance_complete": false})
    );
    Ok(())
}
