use super::*;
use chio_core_types::capability::governance::GovernedTransactionIntent;
use chio_core_types::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core_types::receipt::decision::ToolCallAction;
use chio_core_types::receipt::kinds::{
    BoundaryClass, ObservationOutcome, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
};
use chio_runtime_core::{
    runtime_admission_bundle_sha256, RuntimeAdmissionBundle, RuntimeRequestBinding,
    CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA,
};
use chio_swarm_authority::SwarmAuthorityBundle;
use serde_json::json;

pub(super) fn bootstrap(
    runtime: &ProcessRuntime,
    record: &Record,
    issuer: &Keypair,
    now: u64,
    role: &str,
) -> Result<ChioReceipt, CliError> {
    let mut capabilities = BTreeMap::new();
    for id in
        std::iter::once("root").chain(record.config.children.iter().map(|child| child.id.as_str()))
    {
        capabilities.insert(id, runtime.process(id).map_err(error)?.capability);
    }
    let parameters = json!({"runtime_id": runtime.runtime_id(), "capabilities": capabilities, "record_sha256": hash(record)?});
    // This observes completed provisioning, not a tool effect or future task.
    ChioReceipt::sign(
        ChioReceiptBody {
            id: String::new(),
            timestamp: now / 1000,
            capability_id: capabilities["root"].id.clone(),
            tool_server: "chio-process-host".into(),
            tool_name: role.into(),
            action: ToolCallAction::from_parameters(parameters.clone()).map_err(error)?,
            decision: None,
            receipt_kind: ReceiptKind::TraceObservation,
            boundary_class: BoundaryClass::DetectOnly,
            observation_outcome: Some(ObservationOutcome::Observed),
            tool_origin: ToolOrigin::ChioInternal,
            redaction_mode: RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: hash(&parameters)?,
            policy_hash: record.runtime_policy_hash.clone(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: TrustLevel::Verified,
            tenant_id: None,
            kernel_key: issuer.public_key(),
            bbs_projection_version: None,
        },
        issuer,
    )
    .map_err(error)
}

pub(super) fn prepare(
    plan: &Graph,
    swarm: &SwarmAuthorityBundle,
    runtime: &ProcessRuntime,
    record: &Record,
    profile: &RuntimeAdmissionProfile,
    source: &SqliteRuntimeOrchestrationStore,
) -> Result<Vec<Value>, CliError> {
    let mut calls = Vec::new();
    for (index, call) in plan.calls.iter().enumerate() {
        let request = runtime
            .tool_request(
                &call.process,
                &call.operation_key,
                &call.server_id,
                &call.tool_name,
                call.arguments.clone(),
            )
            .map_err(error)?;
        let admission = RuntimeAdmissionBundle {
            schema: CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA.into(),
            admission_id: format!("admission-{}-{}", plan.graph_id, call.process),
            binding: RuntimeRequestBinding::from_tool_call_request(
                &request,
                &profile.local_kernel_id,
            )
            .map_err(error)?,
            workflow_id: plan.graph_id.clone(),
            workflow_grant_id: request.capability.id.clone(),
            step_index: index as u64,
            destructive: false,
            lease_id: None,
            governance_receipt_id: None,
            trust_bundle_sha256: hash(&record.manifests)?,
            verification_context_sha256: hash(record)?,
        };
        let token = &swarm.continuation_tokens[index];
        let route = &swarm.route_plan_receipts[index];
        let witness = &swarm.witness_chains[index];
        let context = json!({
            "chioAdmission": {"admissionId": admission.admission_id, "bundleSha256": runtime_admission_bundle_sha256(&admission).map_err(error)?},
            "chioSwarm": {
                "taskGraph": {"id": swarm.task_graph.graph_id, "sha256": hash(&swarm.task_graph)?},
                "continuationToken": {"id": token.token_id, "sha256": hash(token)?},
                "routePlanReceipt": {"id": route.route_plan_id, "sha256": hash(route)?},
                "delegationWitness": {"id": witness.chain_id, "sha256": hash(witness)?},
                "revocationEpoch": {"id": swarm.revocation_epoch.epoch_id, "sha256": hash(&swarm.revocation_epoch)?},
                "budgetPool": {"id": swarm.budget_pool.pool_id, "sha256": hash(&swarm.budget_pool)?}
            }
        });
        let intent = GovernedTransactionIntent {
            id: format!("intent-{}-{}", plan.graph_id, call.process),
            server_id: call.server_id.clone(),
            tool_name: call.tool_name.clone(),
            purpose: "Execute the initialized process task".into(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: Some(context),
            body: Default::default(),
        };
        source.insert_bundle(admission).map_err(error)?;
        calls.push(json!({"process": call.process, "operation_key": call.operation_key, "server_id": call.server_id, "tool_name": call.tool_name, "arguments": call.arguments, "governed_intent": intent, "request_id": request.request_id, "capability_sha256": hash(&request.capability)?}));
    }
    Ok(calls)
}
