//! One stopped-host observation of issued graphs, worker outcomes and accounting.

use std::collections::BTreeMap;

use chio_core::capability::aggregate_invocation::{
    verify_aggregate_invocation_budget, AggregateInvocationScope,
};
use chio_kernel::admission_operation::RuntimeReplayParticipantKind;
use chio_swarm_authority::{
    verify_swarm_authority_for_admission, SwarmAuthorityBundle, SwarmContinuationMode,
};

use super::*;

#[cfg(target_os = "linux")]
#[path = "outcomes_export.rs"]
mod exporting;
#[cfg(target_os = "linux")]
pub(crate) use exporting::export;

const OUTCOMES_SCHEMA: &str = "chio.process.worker-outcomes.v1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Outcomes {
    schema: String,
    runtime_id: String,
    observed_at_unix_ms: u64,
    bootstrap: ChioReceipt,
    host_record: super::super::state::Record,
    authorities: Vec<SwarmAuthorityBundle>,
    runner: Value,
    aggregate: Usage,
    calls: BTreeMap<String, ChioReceipt>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Usage {
    owner_id: String,
    max_invocations: u32,
    reserved_invocations: u32,
    captured_invocations: u32,
}

fn verify_outcomes(
    signed: &ChioReceipt,
    run: &Outcomes,
    key: &PublicKey,
    runtime: &str,
) -> Result<(), CliError> {
    receipt(signed, key)?;
    observation(signed, "attest_worker_outcomes")?;
    receipt(&run.bootstrap, key)?;
    observation(&run.bootstrap, "provision_swarm")?;
    require(
        !runtime.is_empty()
            && run.schema == OUTCOMES_SCHEMA
            && run.runtime_id == runtime
            && run.bootstrap.action.parameters["runtime_id"] == runtime
            && signed.action.parameters == serde_json::to_value(run).map_err(error)?
            && signed.timestamp == run.observed_at_unix_ms / 1000
            && run.observed_at_unix_ms > 0
            && run.observed_at_unix_ms < (1_u64 << 53)
            && signed.timestamp >= run.bootstrap.timestamp
            && signed.policy_hash == run.bootstrap.policy_hash
            && signed.capability_id == run.bootstrap.capability_id
            && run.bootstrap.action.parameters["record_sha256"] == hash(&run.host_record)?
            && run.host_record.runtime_policy_hash == signed.policy_hash,
        "outcome observation differs from pinned provisioning",
    )?;
    super::super::state::require_abi(&run.host_record.abi, "worker outcomes")?;
    let caps: BTreeMap<String, CapabilityToken> =
        serde_json::from_value(run.bootstrap.action.parameters["capabilities"].clone())
            .map_err(error)?;
    let root = caps
        .get("root")
        .ok_or_else(|| error("missing root capability"))?;
    let family = verify_aggregate_invocation_budget(root, std::slice::from_ref(key), None)
        .map_err(error)?
        .ok_or_else(|| error("missing family budget"))?;
    require(
        family.scope == AggregateInvocationScope::DelegationFamily
            && root.id == signed.capability_id
            && (2..=32).contains(&run.calls.len())
            && !run.calls.contains_key("root")
            && caps.keys().map(String::as_str).collect::<BTreeSet<_>>()
                == run
                    .calls
                    .keys()
                    .map(String::as_str)
                    .chain(["root"])
                    .collect()
            && !run.authorities.is_empty()
            && run.authorities.len() <= run.calls.len(),
        "outcome capability or graph inventory differs",
    )?;
    let mut graph_ids = BTreeSet::new();
    let mut workers = BTreeMap::new();
    for bundle in &run.authorities {
        verify_swarm_authority_for_admission(bundle, std::slice::from_ref(key)).map_err(error)?;
        let graph = &bundle.task_graph;
        require(
            graph_ids.insert(graph.graph_id.as_str())
                && graph.root_transaction_ref == run.bootstrap.id
                && graph.planner_subject == root.subject.to_hex()
                && graph.max_depth == 1
                && !graph.multi_hop_witness_chains
                && bundle.join_receipts.is_empty()
                && bundle.terminal_receipts.is_empty()
                && bundle.now_unix_ms / 1000 == run.bootstrap.timestamp
                && bundle.budget_pool.total_units == u64::from(family.max_invocations),
            "outcomes require the original issued direct-child graph authority",
        )?;
        let mut nodes = BTreeSet::new();
        for node in &graph.nodes {
            let cap = caps
                .get(&node.task_id)
                .ok_or_else(|| error("unknown graph task"))?;
            require(
                nodes.insert(node.task_id.as_str())
                    && node.scope_hash == hash(&cap.scope)?
                    && cap.issued_at <= run.bootstrap.timestamp
                    && cap.expires_at > run.bootstrap.timestamp,
                "graph differs from issued task capability",
            )?;
            if node.task_id == "root" {
                require(
                    node.parent_task_id.is_none() && node.depth == 0,
                    "invalid graph root",
                )?;
            } else {
                require(
                    node.parent_task_id.as_deref() == Some("root")
                        && node.depth == 1
                        && workers.insert(node.task_id.as_str(), bundle).is_none(),
                    "task is duplicated across graphs or has a different parent",
                )?;
                let child =
                    verify_aggregate_invocation_budget(cap, std::slice::from_ref(key), Some(root))
                        .map_err(error)?
                        .ok_or_else(|| error("missing child family budget"))?;
                require(child == family, "worker has a different aggregate family")?;
            }
        }
        require(
            nodes.contains("root") && bundle.witness_chains.len() + 1 == nodes.len(),
            "graph witness inventory differs",
        )?;
        for witness in &bundle.witness_chains {
            let child = caps
                .get(&witness.child_task_id)
                .ok_or_else(|| error("unknown witness child"))?;
            require(
                witness.parent_task_id == "root"
                    && nodes.contains(witness.child_task_id.as_str())
                    && witness.hops.len() == 1,
                "invalid task witness",
            )?;
            let hop = &witness.hops[0];
            require(
                hop.parent_capability_digest == hash(root)?
                    && hop.child_capability_digest == hash(child)?
                    && hop.parent_scope_hash == hash(&root.scope)?
                    && hop.child_scope_hash == hash(&child.scope)?,
                "task witness substitutes issued capabilities",
            )?;
        }
    }
    require(
        workers.keys().copied().collect::<BTreeSet<_>>()
            == run.calls.keys().map(String::as_str).collect(),
        "issued graph and observed worker set differ",
    )?;
    let planned = run.runner["plan"]["workers"]
        .as_array()
        .ok_or_else(|| error("missing planned workers"))?;
    let completed = run.runner["workers"]
        .as_array()
        .ok_or_else(|| error("missing completed workers"))?;
    require(
        run.runner["plan"]["schema"] == "chio.process.run.v1"
            && run.runner["plan"]["templates"]
                .as_array()
                .is_none_or(Vec::is_empty)
            && planned.len() == workers.len()
            && completed.len() == workers.len(),
        "runner inventory differs from issued workers",
    )?;
    let mut committed = 0;
    let mut requests = BTreeSet::new();
    for (process, signed_call) in &run.calls {
        let evidence: Evidence =
            serde_json::from_value(signed_call.action.parameters.clone()).map_err(error)?;
        super::verify(signed_call, &evidence, key, runtime)?;
        let cap = &caps[process];
        require(
            hash(&evidence.bootstrap)? == hash(&run.bootstrap)?
                && evidence.observed_at_unix_ms == run.observed_at_unix_ms
                && evidence.context
                    == json!({"runtime_id": runtime, "process_id": process, "capability_id": cap.id})
                && requests.insert(
                    evidence.response["request_id"]
                        .as_str()
                        .ok_or_else(|| error("missing request ID"))?
                        .to_owned(),
                ),
            "call is substituted, duplicated or from another observation",
        )?;
        let call = crate::process_response_verify::verify_values(
            &evidence.request,
            &evidence.context,
            &evidence.response,
            key,
        )?;
        task_authority(&evidence, &call, workers[process.as_str()], cap, runtime)?;
        let plan: Vec<_> = planned
            .iter()
            .filter(|item| item["process"] == *process)
            .collect();
        let done: Vec<_> = completed
            .iter()
            .filter(|item| item["process"] == *process)
            .collect();
        require(
            plan.len() == 1 && done.len() == 1,
            "duplicate or missing runner worker",
        )?;
        require(
            done[0]["state"] == "completed" && done[0]["attempts"].as_u64().is_some_and(|n| n > 0),
            "worker has not finished an actual attempt",
        )?;
        let input = &plan[0]["input"];
        for field in ["operation_key", "server_id", "tool_name", "arguments"] {
            require(
                input[field] == evidence.request[field],
                "runner invocation differs from observed call",
            )?;
        }
        require(
            input["process"] == *process
                && input["request_id"] == evidence.response["request_id"]
                && input["capability_sha256"] == hash(cap)?,
            "runner task identity differs",
        )?;
        if evidence
            .operation
            .as_ref()
            .is_some_and(|op| op.dispatch_commit.is_some())
        {
            committed += 1;
        }
    }
    require(
        run.aggregate.owner_id == family.owner_id
            && run.aggregate.max_invocations == family.max_invocations
            && run.aggregate.reserved_invocations == 0
            && run.aggregate.captured_invocations == committed
            && committed <= family.max_invocations,
        "authoritative family usage differs from retained dispatches",
    )
}

fn task_authority(
    evidence: &Evidence,
    call: &ChioReceipt,
    bundle: &SwarmAuthorityBundle,
    cap: &CapabilityToken,
    runtime: &str,
) -> Result<(), CliError> {
    let process = evidence.context["process_id"]
        .as_str()
        .ok_or_else(|| error("missing process"))?;
    let tokens: Vec<_> = bundle
        .continuation_tokens
        .iter()
        .filter(|t| t.child_task_id == process)
        .collect();
    require(tokens.len() == 1, "missing or duplicate task continuation")?;
    let token = tokens[0];
    require(
        token.mode == SwarmContinuationMode::SingleUse
            && token.session_anchor_ref == runtime
            && token.parent_receipt_ids == [evidence.bootstrap.id.clone()]
            && token.join_receipt_id.is_none(),
        "task continuation differs from issued fan-out authority",
    )?;
    if let Some(operation) = &evidence.operation {
        for history in &operation.history {
            let resources = history.history.intent.resources();
            require(
                resources.len() == 1
                    && resources[0].kind() == RuntimeReplayParticipantKind::SwarmContinuation
                    && resources[0].resource_id().as_str() == token.token_id
                    && resources[0].artifact_digest().as_str() == hash(token)?,
                "retained continuation differs from issued task authority",
            )?;
        }
    }
    let metadata = call
        .metadata
        .as_ref()
        .ok_or_else(|| error("missing call metadata"))?;
    let binding = &metadata["chio_runtime"]["verified_swarm_request_binding"];
    if binding.is_null() {
        return require(
            matches!(call.decision, Some(Decision::Deny { .. })),
            "completed or interrupted call lacks its admitted task binding",
        );
    }
    let route = bundle
        .route_plan_receipts
        .iter()
        .find(|r| r.route_plan_id == token.route_plan_receipt_id)
        .ok_or_else(|| error("missing task route"))?;
    let witness = bundle
        .witness_chains
        .iter()
        .find(|w| Some(&w.chain_id) == token.witness_chain_ref.as_ref())
        .ok_or_else(|| error("missing task witness"))?;
    let reference = |id: &str, value: Value| -> Result<Value, CliError> {
        Ok(json!({"evidence_id": id, "artifact_sha256": hash(&value)?}))
    };
    let refs = json!({
        "task_graph": reference(&bundle.task_graph.graph_id, serde_json::to_value(&bundle.task_graph).map_err(error)?)?,
        "continuation_token": reference(&token.token_id, serde_json::to_value(token).map_err(error)?)?,
        "route_plan_receipt": reference(&route.route_plan_id, serde_json::to_value(route).map_err(error)?)?,
        "delegation_witness": reference(&witness.chain_id, serde_json::to_value(witness).map_err(error)?)?,
        "revocation_epoch": reference(&bundle.revocation_epoch.epoch_id, serde_json::to_value(&bundle.revocation_epoch).map_err(error)?)?,
        "budget_pool": reference(&bundle.budget_pool.pool_id, serde_json::to_value(&bundle.budget_pool).map_err(error)?)?,
    });
    require(
        binding["graph_id"] == bundle.task_graph.graph_id
            && binding["task_id"] == process
            && binding["capability_sha256"] == hash(cap)?
            && binding["scope_sha256"] == hash(&cap.scope)?
            && binding["evidence_refs_sha256"] == hash(&refs)?
            && metadata["route"]
                == json!({"bridge": route.bridge_id, "protocolTarget": route.protocol_target, "selectedRoute": route.selected_route}),
        "admitted task binding differs from issued authority",
    )
}

pub(crate) fn verify_file(path: &Path, key: &Path, runtime: &str) -> Result<(), CliError> {
    let key = crate::load_trusted_kernel_pubkey(key).map_err(error)?;
    let signed = crate::receipt_verify::verify_original_receipt(&text(path)?, &key)?;
    let run: Outcomes = serde_json::from_value(signed.action.parameters.clone()).map_err(error)?;
    verify_outcomes(&signed, &run, &key, runtime)?;
    println!(
        "{}",
        json!({
        "schema": "chio.process.worker-outcomes-verification.v1", "runtime_id": runtime,
        "graphs": run.authorities.len(), "workers": run.calls.len(),
        "captured_invocations": run.aggregate.captured_invocations,
        "observed_operations": run.calls.iter().map(|(process, call)|
            (process, call.action.parameters["operation"]["state"].clone())
        ).collect::<BTreeMap<_, _>>(),
            "checks": ["signer_pin", "runtime_pin", "issued_task_authority", "worker_completion", "call_outcomes", "continuation_custody", "aggregate_usage"],
            "unchecked": ["confinement", "physical_effects", "execution_nonces", "scenario_matrix"],
            "m5_acceptance_complete": false,
        })
    );
    Ok(())
}
