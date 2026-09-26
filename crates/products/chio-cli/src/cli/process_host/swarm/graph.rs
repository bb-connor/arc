//! Construct live authority from the issued process identities. No future
//! result or terminal receipt is fabricated to make admission succeed.
use super::*;
use chio_core_types::capability::attenuation::{compute_attenuation_witness, scope_hash};
use chio_swarm_authority::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn build(
    plan: &Graph,
    runtime: &ProcessRuntime,
    record: &Record,
    routes: &BTreeMap<String, Route>,
    issuer: &Keypair,
    bootstrap_id: &str,
    now: u64,
    expires: u64,
    max_invocations: u32,
) -> Result<SwarmAuthorityBundle, CliError> {
    if plan.calls.len() as u64 > u64::from(max_invocations) {
        return Err(error(
            "planned allocations exceed the signed aggregate invocation budget",
        ));
    }
    let root = runtime.process("root").map_err(error)?;
    let parent_hash = scope_hash(&root.capability.scope).map_err(error)?;
    let issuer_id = format!("did:chio:{}", issuer.public_key().to_hex());
    let pool_id = format!("pool-{}", plan.graph_id);
    let epoch_id = format!("epoch-{}", plan.graph_id);
    let mut nodes = vec![SwarmGraphNode {
        task_id: "root".into(),
        parent_task_id: None,
        route_plan_ref: None,
        continuation_token_ref: None,
        budget_allocation_ref: None,
        scope_hash: parent_hash.clone(),
        depth: 0,
    }];
    let mut edges = Vec::new();
    for call in &plan.calls {
        let child = runtime.process(&call.process).map_err(error)?;
        if child.parent_id.as_deref() != Some("root")
            || child.capability.aggregate_invocation_budget
                != root.capability.aggregate_invocation_budget
        {
            return Err(error(
                "planned process is not a direct member of the issued budget family",
            ));
        }
        let request = runtime
            .tool_request(
                &call.process,
                &call.operation_key,
                &call.server_id,
                &call.tool_name,
                call.arguments.clone(),
            )
            .map_err(error)?;
        if !record.manifests.iter().any(|server| {
            server.server_id == call.server_id
                && server.tools.iter().any(|tool| tool.name == call.tool_name)
        }) {
            return Err(error(
                "planned tool is absent from the registered manifests",
            ));
        }
        let allowed = child.capability.scope.grants.iter().any(|grant| {
            (grant.server_id == call.server_id || grant.server_id == "*")
                && (grant.tool_name == call.tool_name || grant.tool_name == "*")
                && grant
                    .operations
                    .contains(&chio_core_types::capability::scope::Operation::Invoke)
        });
        if !allowed || request.capability.id != child.capability.id {
            return Err(error("planned tool exceeds issued child scope"));
        }
        nodes.push(SwarmGraphNode {
            task_id: call.process.clone(),
            parent_task_id: Some("root".into()),
            route_plan_ref: Some(format!("route-{}", call.process)),
            continuation_token_ref: Some(format!("continue-{}", call.process)),
            budget_allocation_ref: Some(format!("allocation-{}", call.process)),
            scope_hash: scope_hash(&child.capability.scope).map_err(error)?,
            depth: 1,
        });
        edges.push(SwarmGraphEdge {
            from_task_id: "root".into(),
            to_task_id: call.process.clone(),
            edge_type: "delegates".into(),
        });
    }
    let mut task_graph = SwarmTaskGraph {
        schema: CHIO_SWARM_TASK_GRAPH_SCHEMA.into(),
        graph_id: plan.graph_id.clone(),
        root_transaction_ref: bootstrap_id.into(),
        planner_subject: root.capability.subject.to_hex(),
        issuer: issuer_id.clone(),
        signature: String::new(),
        created_at_unix_ms: now,
        expires_at_unix_ms: expires,
        max_depth: 1,
        max_fanout: plan.calls.len() as u32,
        multi_hop_witness_chains: false,
        nodes,
        edges,
        joins: vec![SwarmGraphJoin {
            join_id: format!("join-{}", plan.graph_id),
            parent_task_ids: plan.calls.iter().map(|call| call.process.clone()).collect(),
            next_task_id: "root".into(),
        }],
        budget_pool_ref: pool_id.clone(),
        revocation_epoch_ref: epoch_id.clone(),
        route_plan_refs: plan
            .calls
            .iter()
            .map(|call| format!("route-{}", call.process))
            .collect(),
    };
    task_graph.signature = sign_swarm_task_graph(&task_graph, issuer).map_err(error)?;
    let graph_sha256 = hash(&task_graph)?;
    let epoch_root = hash(&serde_json::json!({"revokedSubjects": [], "revokedTaskIds": []}))?;
    let mut witness_chains = Vec::new();
    let mut continuation_tokens = Vec::new();
    let mut route_plan_receipts = Vec::new();
    let mut allocations = Vec::new();
    for call in &plan.calls {
        let child = runtime.process(&call.process).map_err(error)?;
        let mut chain = SwarmDelegationWitnessChain {
            schema: CHIO_SWARM_DELEGATION_WITNESS_CHAIN_SCHEMA.into(),
            chain_id: format!("witness-{}", call.process),
            graph_id: plan.graph_id.clone(),
            parent_task_id: "root".into(),
            child_task_id: call.process.clone(),
            hops: vec![SwarmDelegationWitnessHop {
                parent_capability_digest: hash(&root.capability)?,
                child_capability_digest: hash(&child.capability)?,
                parent_scope_hash: parent_hash.clone(),
                child_scope_hash: scope_hash(&child.capability.scope).map_err(error)?,
                attenuation_rule_id: "rule-subset-tool-invocation".into(),
                scope_subset_proof: compute_attenuation_witness(
                    &root.capability.scope,
                    &child.capability.scope,
                )
                .map_err(error)?,
                expires_at_unix_ms: expires,
                issuer: issuer_id.clone(),
                policy_digest: record.runtime_policy_hash.clone(),
                witness_signature: String::new(),
            }],
        };
        chain.hops[0].witness_signature =
            sign_swarm_delegation_witness_hop(&chain, &chain.hops[0], issuer).map_err(error)?;
        let route = routes
            .get(&call.server_id)
            .ok_or_else(|| error("planned server has no host route"))?;
        let mut routed = SwarmRoutePlanReceipt {
            schema: CHIO_SWARM_ROUTE_PLAN_RECEIPT_SCHEMA.into(),
            route_plan_id: format!("route-{}", call.process),
            graph_id: plan.graph_id.clone(),
            task_id: call.process.clone(),
            selected_route: route.selected_route.clone(),
            candidate_set_digest: hash(&record.manifests)?,
            registry_snapshot_hash: hash(&record.manifests)?,
            bridge_id: route.bridge.clone(),
            protocol_target: route.protocol_target.clone(),
            egress_contract_id: format!("{}:manifest:{}", route.bridge, route.manifest_sha256),
            egress_constraints: vec!["deny-private-network".into()],
            attenuation_decision: "accepted".into(),
            policy_digest: record.runtime_policy_hash.clone(),
            expires_at_unix_ms: expires,
            issuer: issuer_id.clone(),
            signature: String::new(),
        };
        routed.signature = sign_swarm_route_plan_receipt(&routed, issuer).map_err(error)?;
        let allocation_id = format!("allocation-{}", call.process);
        let mut token = SwarmContinuationToken {
            schema: CHIO_SWARM_CONTINUATION_TOKEN_SCHEMA.into(),
            token_id: format!("continue-{}", call.process),
            graph_id: plan.graph_id.clone(),
            child_task_id: call.process.clone(),
            parent_task_id: Some("root".into()),
            join_receipt_id: None,
            parent_receipt_ids: vec![bootstrap_id.into()],
            graph_sha256: graph_sha256.clone(),
            route_plan_receipt_id: routed.route_plan_id.clone(),
            budget_allocation_id: allocation_id.clone(),
            witness_chain_ref: Some(chain.chain_id.clone()),
            witness_chain_sha256: Some(hash(&chain)?),
            revocation_epoch_ref: epoch_id.clone(),
            revocation_epoch_root_hash: epoch_root.clone(),
            session_anchor_ref: runtime.runtime_id().into(),
            nonce: uuid::Uuid::new_v4().to_string(),
            mode: SwarmContinuationMode::SingleUse,
            issued_at_unix_ms: now,
            expires_at_unix_ms: expires,
            issuer: issuer_id.clone(),
            signature: String::new(),
        };
        token.signature = sign_swarm_continuation_token(&token, issuer).map_err(error)?;
        allocations.push(SwarmBudgetAllocation {
            allocation_id,
            task_id: call.process.clone(),
            dimension_id: "tool_calls".into(),
            state: SwarmBudgetAllocationState::Active,
            max_units: 1,
            reserved_units: 0,
            active_units: 1,
            consumed_units: 0,
            released_units: 0,
            reversed_units: 0,
        });
        witness_chains.push(chain);
        continuation_tokens.push(token);
        route_plan_receipts.push(routed);
    }
    let mut revocation_epoch = SwarmRevocationEpoch {
        schema: CHIO_SWARM_REVOCATION_EPOCH_SCHEMA.into(),
        epoch_id,
        root_hash: epoch_root,
        issued_at_unix_ms: now,
        valid_until_unix_ms: expires,
        revoked_subjects: Vec::new(),
        revoked_task_ids: Vec::new(),
        issuer: issuer_id,
        signature: String::new(),
    };
    revocation_epoch.signature =
        sign_swarm_revocation_epoch(&revocation_epoch, issuer).map_err(error)?;
    Ok(SwarmAuthorityBundle {
        task_graph,
        witness_chains,
        continuation_tokens,
        route_plan_receipts,
        revocation_epoch,
        budget_pool: SwarmBudgetPool {
            schema: CHIO_SWARM_BUDGET_POOL_SCHEMA.into(),
            pool_id,
            graph_id: plan.graph_id.clone(),
            currency: "tool_calls".into(),
            total_units: u64::from(max_invocations),
            allocations,
        },
        join_receipts: Vec::new(),
        terminal_receipts: Vec::new(),
        now_unix_ms: now,
    })
}
