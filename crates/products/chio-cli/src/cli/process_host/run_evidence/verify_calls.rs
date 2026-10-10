use chio_core::receipt::decision::Decision;
use chio_swarm_authority::SwarmContinuationMode;

use super::*;

pub(super) fn verify(
    evidence: &Evidence,
    caps: &BTreeMap<String, CapabilityToken>,
    key: &PublicKey,
) -> Result<BTreeMap<String, String>, CliError> {
    let bundle = &evidence.authority;
    let workers = evidence.runner["plan"]["workers"]
        .as_array()
        .ok_or_else(|| error("missing runner plan workers"))?;
    let snapshots = evidence.runner["workers"]
        .as_array()
        .ok_or_else(|| error("missing runner completion snapshot"))?;
    require(
        evidence.runner["plan"]["schema"] == "chio.process.run.v1"
            && evidence.runner["plan"]["templates"]
                .as_array()
                .is_none_or(Vec::is_empty)
            && workers.len() == evidence.results.len()
            && snapshots.len() == evidence.results.len(),
        "runner plan or snapshot inventory differs",
    )?;
    let mut parents = BTreeMap::new();
    let mut receipt_ids = BTreeSet::new();
    let mut nonce_ids = BTreeSet::new();
    for (process, call) in &evidence.results {
        let cap = &caps[process];
        require(
            call.context
                == json!({"runtime_id": evidence.runtime_id, "process_id": process, "capability_id": cap.id}),
            "worker invocation context differs",
        )?;
        let receipt = crate::process_response_verify::verify_values(
            &call.request,
            &call.context,
            &call.response,
            key,
        )?;
        if evidence.schema == SCHEMA {
            let id = super::super::super::nonce_evidence::verify(
                call.nonce.as_ref(),
                &receipt,
                &call.response,
                cap,
                key,
                bundle.now_unix_ms,
            )?
            .ok_or_else(|| error("missing completed execution nonce"))?;
            require(
                nonce_ids.insert(id),
                "execution nonce reused across workers",
            )?;
            call.receipt_log
                .as_ref()
                .ok_or_else(|| error("missing receipt log inclusion"))?
                .verify(&receipt, key, bundle.now_unix_ms)?;
        } else {
            require(
                call.nonce.is_none() && call.receipt_log.is_none(),
                "legacy run carries unsupported nonce or log claims",
            )?;
        }
        require(
            receipt.decision == Some(Decision::Allow)
                && receipt.timestamp >= evidence.bootstrap.timestamp
                && receipt.timestamp <= bundle.now_unix_ms / 1000,
            "joined tool result is not a completed allowed effect in this run",
        )?;
        require(
            receipt_ids.insert(receipt.id.clone()),
            "tool receipt reused for multiple workers",
        )?;
        let binding = receipt
            .metadata
            .as_ref()
            .ok_or_else(|| error("missing governed receipt metadata"))?["chio_runtime"]
            ["verified_swarm_request_binding"]
            .clone();
        require(
            binding["graph_id"] == bundle.task_graph.graph_id
                && binding["task_id"] == *process
                && binding["capability_sha256"] == hash(cap)?
                && binding["scope_sha256"] == hash(&cap.scope)?,
            "tool receipt is not bound to the issued task capability",
        )?;
        let token = bundle
            .continuation_tokens
            .iter()
            .find(|token| token.child_task_id == *process)
            .ok_or_else(|| error("missing task continuation"))?;
        let route = bundle
            .route_plan_receipts
            .iter()
            .find(|route| route.route_plan_id == token.route_plan_receipt_id)
            .ok_or_else(|| error("missing task route"))?;
        super::super::custody::verify(
            &call.custody,
            &receipt,
            token,
            &evidence.runtime_id,
            call.nonce.as_ref(),
        )?;
        require(
            receipt
                .metadata
                .as_ref()
                .ok_or_else(|| error("missing route metadata"))?["route"]
                == json!({"bridge": route.bridge_id, "protocolTarget": route.protocol_target, "selectedRoute": route.selected_route}),
            "tool receipt route differs from signed task route",
        )?;
        let witness = bundle
            .witness_chains
            .iter()
            .find(|witness| Some(&witness.chain_id) == token.witness_chain_ref.as_ref())
            .ok_or_else(|| error("missing task witness"))?;
        require(
            token.mode == SwarmContinuationMode::SingleUse
                && token.session_anchor_ref == evidence.runtime_id
                && token.parent_receipt_ids == [evidence.bootstrap.id.clone()]
                && token.join_receipt_id.is_none(),
            "continuation is not the issued single-use fan-out authority",
        )?;
        let refs = json!({
            "task_graph": reference(&bundle.task_graph.graph_id, &bundle.task_graph)?,
            "continuation_token": reference(&token.token_id, token)?,
            "route_plan_receipt": reference(&route.route_plan_id, route)?,
            "delegation_witness": reference(&witness.chain_id, witness)?,
            "revocation_epoch": reference(&bundle.revocation_epoch.epoch_id, &bundle.revocation_epoch)?,
            "budget_pool": reference(&bundle.budget_pool.pool_id, &bundle.budget_pool)?,
        });
        require(
            binding["evidence_refs_sha256"] == hash(&refs)?,
            "tool receipt authority references differ",
        )?;
        let planned: Vec<_> = workers
            .iter()
            .filter(|worker| worker["process"] == *process)
            .collect();
        let completed: Vec<_> = snapshots
            .iter()
            .filter(|worker| worker["process"] == *process)
            .collect();
        require(
            planned.len() == 1 && completed.len() == 1,
            "missing or duplicate runner worker",
        )?;
        require(
            completed[0]["state"] == "completed"
                && completed[0]["attempts"]
                    .as_u64()
                    .is_some_and(|attempts| attempts > 0),
            "worker did not complete an actual attempt",
        )?;
        let input = &planned[0]["input"];
        for field in ["operation_key", "server_id", "tool_name", "arguments"] {
            require(
                input[field] == call.request[field],
                "runner input differs from actual invocation",
            )?;
        }
        require(
            input["process"] == *process
                && input["request_id"] == call.response["request_id"]
                && input["capability_sha256"] == hash(cap)?,
            "runner input identity differs",
        )?;
        parents.insert(process.clone(), receipt.id);
    }
    Ok(parents)
}

fn reference<T: Serialize>(id: &str, value: &T) -> Result<Value, CliError> {
    Ok(json!({"evidence_id": id, "artifact_sha256": hash(value)?}))
}
