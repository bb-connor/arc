//! Verify a broker completion inside the original process-call observation.

use super::*;
use chio_secret_broker::kernel_admission::NativeBrokerCompletionEvidence;
use chio_secret_broker::protocol::{BrokerExecuteRequest, BrokerExecuteResponse};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Evidence {
    host_record: super::super::state::Record,
    capture: NativeBrokerCompletionEvidence,
    confinement: crate::mcp_cli::NativeLaunchEvidence,
}

fn response(value: &Value) -> Result<BrokerExecuteResponse, CliError> {
    require(
        value["verdict"] == "allow" && value["output"]["kind"] == "value",
        "broker observation requires a completed value response",
    )?;
    serde_json::from_value(value["output"]["value"].clone()).map_err(error)
}

pub(super) fn verify(
    evidence: &Evidence,
    call_evidence: &super::Evidence,
    call: &ChioReceipt,
    parent: &CapabilityToken,
    trusted: &super::super::state::Config,
) -> Result<(), CliError> {
    trusted.validate()?;
    let config = trusted
        .native_broker
        .as_ref()
        .ok_or_else(|| error("trusted host configuration has no broker route"))?;
    require(
        hash(&evidence.host_record.config)? == hash(trusted)?
            && call_evidence.bootstrap.action.parameters["record_sha256"]
                == hash(&evidence.host_record)?,
        "broker host configuration differs from external pins or provisioning",
    )?;
    let operation = call_evidence
        .operation
        .as_ref()
        .ok_or_else(|| error("missing broker operation"))?;
    let binding =
        AdmissionOperationBindingV1::from_persisted(operation.binding.clone()).map_err(error)?;
    let execute: BrokerExecuteRequest =
        serde_json::from_value(call_evidence.request["arguments"].clone()).map_err(error)?;
    let completed = response(&call_evidence.response)?;
    let committed = operation
        .dispatch_commit
        .as_ref()
        .ok_or_else(|| error("missing original broker dispatch"))?;
    require(
        operation.state == AdmissionOperationState::Completed
            && execute.capability.body.parent_capability_id == parent.id
            && execute.capability.body.subject == parent.subject
            && execute.proof.body.authority_key == parent.subject
            && call.tool_server == config.quota.server_id
            && call.tool_name == config.quota.tool_name
            && execute.capability.body.provider_adapter_id == config.quota.provider_adapter_id
            && execute.capability.body.provider_adapter_version
                == config.quota.provider_adapter_version
            && evidence.capture.registration.revocation_authority_domain
                == config.revocation_authority_domain
            && completed.evidence.leader_epoch == committed.store_fence.owner_epoch,
        "broker completion differs from original process, provider or authority",
    )?;
    // Proof issuance is authenticated historical time. Current capability
    // expiry must not prevent verification of a completed original call.
    let issued = execute.proof.body.issued_at_unix_seconds;
    require(
        issued >= parent.issued_at
            && issued < parent.expires_at
            && issued <= completed.receipt.body.issued_at_unix_seconds,
        "broker proof time is outside parent authority or follows completion",
    )?;
    chio_secret_broker::capability::verify_capability(
        &execute.capability,
        &config.quota.issuer,
        &config.quota.audience,
        issued,
        true,
    )
    .map_err(error)?;
    chio_secret_broker::proof::verify_request_proof(
        &execute.proof,
        &execute.capability,
        &execute.request,
        issued,
        0,
    )
    .map_err(error)?;
    evidence
        .capture
        .verify(
            &binding,
            &execute,
            &completed,
            &config.broker_identity,
            call_evidence.observed_at_unix_ms,
        )
        .map_err(error)?;
    require(
        evidence.capture.invocation_quotas.iter().any(|quota| {
            matches!(
                quota.profile.as_str(),
                "chio.aggregate-capability-invocation.v1" | "chio.aggregate-family-invocation.v1"
            )
        }),
        "broker completion has no original aggregate quota participant",
    )?;

    let reference = &call
        .metadata
        .as_ref()
        .ok_or_else(|| error("missing call metadata"))?["native_launch"];
    require(
        reference["receipt_id"] == evidence.confinement.enforcement.id
            && reference["receipt_sha256"] == hash(&evidence.confinement.enforcement)?,
        "broker cage receipt differs from the original call's prepared connection",
    )?;
    let server = &trusted.servers[0];
    let signer = PublicKey::from_hex(
        server
            .launch_policy_signer
            .as_deref()
            .ok_or_else(|| error("missing external launch signer"))?,
    )
    .map_err(error)?;
    let window = crate::mcp_cli::verify_broker_native_launch_evidence(
        &evidence.confinement,
        &server.id,
        &signer,
    )?;
    require(
        window.target_argv == server.command
            && evidence.host_record.manifests.len() == 1
            && hash(&window.manifest)? == hash(&evidence.host_record.manifests[0])?
            && window.tools.contains(&call.tool_name)
            && completed.receipt.body.issued_at_unix_seconds >= window.started_at_unix_ms / 1000
            && completed.receipt.body.issued_at_unix_seconds <= window.exited_at_unix_ms / 1000
            && window.exited_at_unix_ms <= call_evidence.observed_at_unix_ms,
        "broker response is outside its original confined tool lifetime or manifest",
    )?;
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn export(
    host: &super::super::state::Host,
    call: &ChioReceipt,
    value: &Value,
    operation: &Operation,
    now: u64,
) -> Result<Evidence, CliError> {
    let completed = response(value)?;
    let capture = super::super::native_broker::completion_evidence(
        host,
        &operation.binding.operation_id,
        &completed,
        now,
    )?;
    let reference = &call
        .metadata
        .as_ref()
        .ok_or_else(|| error("missing original broker launch reference"))?["native_launch"];
    let id = reference["receipt_id"]
        .as_str()
        .ok_or_else(|| error("missing original broker launch ID"))?;
    let server = host
        .record
        .config
        .servers
        .first()
        .ok_or_else(|| error("missing broker route"))?;
    let signer = PublicKey::from_hex(
        server
            .launch_policy_signer
            .as_deref()
            .ok_or_else(|| error("missing broker launch signer"))?,
    )
    .map_err(error)?;
    let mut launches = crate::mcp_cli::export_broker_native_launch_evidence(
        server
            .launch_policy
            .as_deref()
            .ok_or_else(|| error("missing broker launch policy"))?,
        &server.id,
        &signer,
        &BTreeSet::from([id.to_string()]),
    )?;
    let confinement = launches
        .remove(id)
        .ok_or_else(|| error("missing original broker confinement"))?;
    Ok(Evidence {
        host_record: host.record.clone(),
        capture,
        confinement,
    })
}
