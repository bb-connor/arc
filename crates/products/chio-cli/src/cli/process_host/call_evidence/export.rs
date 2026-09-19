use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::receipt::decision::ToolCallAction;
use chio_kernel::admission_operation::{AdmissionIdentifier, AdmissionOperationStore};

use super::super::state::{read_json, write_secret, Host};
use super::*;

pub(crate) fn export(
    state: &Path,
    request: &Path,
    context: &Path,
    response: &Path,
    output: &Path,
) -> Result<(), CliError> {
    let request: Value = crate::process_response_verify::read_document(request)?;
    let context: Value = crate::process_response_verify::read_document(context)?;
    let response: Value = crate::process_response_verify::read_document(response)?;
    let host = Host::open(state, false)?;
    let now = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(error)?
            .as_millis(),
    )
    .map_err(error)?;
    let signed = observe(&host, request, context, response, now)?;
    let bytes = canonical_json_bytes(&signed).map_err(error)?;
    require(bytes.len() as u64 <= LIMIT, "call evidence exceeds 32 MiB")?;
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let directory = chio_control_plane::prepare_private_directory(parent)?;
    write_secret(
        &directory,
        output
            .file_name()
            .ok_or_else(|| error("artifact needs a file name"))?,
        &bytes,
    )?;
    println!(
        "{}",
        json!({"artifact": output, "receipt_id": signed.id, "request_id": signed.action.parameters["response"]["request_id"], "m5_acceptance_complete": false})
    );
    Ok(())
}

/// Read the same anchored state under the caller's existing stopped-host lease.
pub(super) fn observe(
    host: &Host,
    request: Value,
    context: Value,
    response: Value,
    now: u64,
) -> Result<ChioReceipt, CliError> {
    let key = host.kernel.public_key();
    let call = crate::process_response_verify::verify_values(&request, &context, &response, &key)?;
    require(
        context["runtime_id"] == host.runtime.runtime_id(),
        "call belongs to another runtime",
    )?;
    let process = context["process_id"]
        .as_str()
        .ok_or_else(|| error("missing process"))?;
    let cap = host.runtime.process(process).map_err(error)?.capability;
    let bootstrap: ChioReceipt =
        read_json(&host.lease.directory.path().join("swarm-bootstrap.json"))?;
    require(
        bootstrap.action.parameters["capabilities"][process]
            == serde_json::to_value(&cap).map_err(error)?,
        "issued capability differs from provisioning",
    )?;
    let request_id = AdmissionIdentifier::try_new(
        "request_id",
        response["request_id"]
            .as_str()
            .ok_or_else(|| error("missing request ID"))?,
    )
    .map_err(error)?;
    let (store, fence) = host
        .authority
        .local_runtime_participant()
        .ok_or_else(|| error("missing local custody authority"))?;
    let retained = store
        .load_unambiguous_retained_tool_request(&request_id, &fence, now)
        .map_err(error)?;
    let operation = if let Some((operation, private_request)) = retained {
        // Validate through the anchored private store. Never export these request bytes.
        private_request
            .validate_binding(operation.binding())
            .map_err(error)?;
        let original = private_request.request_for_revalidation();
        private_request
            .validate_request_material(original)
            .map_err(error)?;
        require(
            original.request_id == request_id.as_str()
                && hash(&original.capability)? == hash(&cap)?
                && original.server_id == request["server_id"]
                && original.tool_name == request["tool_name"]
                && original.arguments == request["arguments"],
            "private retained request differs from caller evidence",
        )?;
        let intent_hash = original
            .governed_intent
            .as_ref()
            .map(|intent| intent.binding_hash())
            .transpose()
            .map_err(error)?;
        require(
            call.metadata
                .as_ref()
                .ok_or_else(|| error("missing call metadata"))?["governed_transaction"]
                ["intent_hash"]
                == serde_json::to_value(intent_hash).map_err(error)?,
            "governed intent differs from retained request",
        )?;
        let (current, history) = store
            .load_runtime_participant_evidence(operation.binding().operation_id(), &fence, now)
            .map_err(error)?
            .ok_or_else(|| error("retained operation disappeared"))?;
        require(
            current.to_persisted() == operation.to_persisted(),
            "operation changed during observation",
        )?;
        Some(Operation {
            binding: operation.binding().to_persisted(),
            state: operation.state(),
            version: operation.version(),
            dispatch_state: operation.dispatch_state(),
            dispatch_commit: operation.dispatch_commit().cloned(),
            terminal_replay: operation.terminal_replay().cloned(),
            history,
        })
    } else {
        None
    };
    let evidence = Evidence {
        schema: SCHEMA.into(),
        runtime_id: host.runtime.runtime_id().into(),
        observed_at_unix_ms: now,
        bootstrap,
        request,
        context,
        response,
        operation,
    };
    let parameters = serde_json::to_value(&evidence).map_err(error)?;
    let mut body = evidence.bootstrap.body();
    body.id.clear();
    body.timestamp = now / 1000;
    body.tool_name = "attest_retained_call".into();
    body.action = ToolCallAction::from_parameters(parameters.clone()).map_err(error)?;
    body.content_hash = hash(&parameters)?;
    let signed = ChioReceipt::sign(body, &host.authority.kernel_keypair()).map_err(error)?;
    verify(&signed, &evidence, &key, host.runtime.runtime_id())?;
    Ok(signed)
}
