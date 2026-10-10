use super::*;

pub(super) fn resign(swarm: &mut SwarmAuthorityBundle) -> TestResult {
    let key = swarm_witness_keypair();
    swarm.task_graph.signature = sign_swarm_task_graph(&swarm.task_graph, &key)?;
    for chain in &mut swarm.witness_chains {
        for index in 0..chain.hops.len() {
            chain.hops[index].witness_signature =
                sign_swarm_delegation_witness_hop(chain, &chain.hops[index], &key)?;
        }
    }
    for token in &mut swarm.continuation_tokens {
        token.graph_sha256 = canonical_test_hash(&swarm.task_graph)?;
        if let Some(chain_id) = token.witness_chain_ref.as_deref() {
            let chain = swarm
                .witness_chains
                .iter()
                .find(|chain| chain.chain_id == chain_id)
                .ok_or_else(|| io::Error::other("missing continuation chain"))?;
            token.witness_chain_sha256 = Some(canonical_test_hash(chain)?);
        }
        token.signature = sign_swarm_continuation_token(token, &key)?;
    }
    Ok(())
}

pub(super) fn multihop_bundle() -> TestResult<SwarmAuthorityBundle> {
    let mut swarm = runtime_swarm_bundle(false)?;
    swarm.task_graph.multi_hop_witness_chains = true;
    let chain = &mut swarm.witness_chains[0];
    let intermediate_scope = runtime_swarm_scope(2);
    let intermediate_digest = sha256_hex(b"intermediate capability");
    let mut first = chain.hops[0].clone();
    first.child_scope_hash = scope_hash(&intermediate_scope)?;
    first.child_capability_digest = intermediate_digest.clone();
    first.scope_subset_proof =
        compute_attenuation_witness(&runtime_swarm_scope(3), &intermediate_scope)?;
    let mut last = chain.hops[0].clone();
    last.parent_scope_hash = scope_hash(&intermediate_scope)?;
    last.parent_capability_digest = intermediate_digest;
    last.scope_subset_proof =
        compute_attenuation_witness(&intermediate_scope, &runtime_swarm_scope(1))?;
    chain.hops = vec![first, last];
    resign(&mut swarm)?;
    Ok(swarm)
}

pub(super) fn join_bundle() -> TestResult<SwarmAuthorityBundle> {
    let mut swarm = runtime_swarm_bundle(false)?;
    let root = &mut swarm.task_graph.nodes[0];
    root.route_plan_ref = Some("route-root".to_string());
    root.continuation_token_ref = Some("continuation-root".to_string());
    root.budget_allocation_ref = Some("budget-root".to_string());
    swarm
        .task_graph
        .route_plan_refs
        .push("route-root".to_string());
    swarm.route_plan_receipts.insert(
        0,
        runtime_swarm_route_plan_receipt(
            "route-root",
            "task-root",
            "mcp",
            "mcp://provider-runtime",
            b"root-route",
        )?,
    );
    let mut allocation = swarm.budget_pool.allocations[0].clone();
    allocation.allocation_id = "budget-root".to_string();
    allocation.task_id = "task-root".to_string();
    swarm.budget_pool.allocations.push(allocation);
    let terminal = &mut swarm.terminal_receipts[0];
    terminal
        .route_plan_receipt_ids
        .push("route-root".to_string());
    terminal.budget_rollups[0].active_units += 1_000;
    terminal.budget_rollups[0].total_units += 1_000;
    terminal.signature = sign_swarm_terminal_graph_receipt(terminal, &swarm_witness_keypair())?;
    let mut token = swarm.continuation_tokens[0].clone();
    token.token_id = "continuation-root".to_string();
    token.child_task_id = "task-root".to_string();
    token.parent_task_id = None;
    token.join_receipt_id = Some(swarm.join_receipts[0].join_id.clone());
    token.parent_receipt_ids = swarm.join_receipts[0].actual_parent_receipt_ids.clone();
    token.route_plan_receipt_id = "route-root".to_string();
    token.budget_allocation_id = "budget-root".to_string();
    token.witness_chain_ref = None;
    token.witness_chain_sha256 = None;
    token.nonce = "nonce-root-join".to_string();
    swarm.continuation_tokens.insert(0, token);
    resign(&mut swarm)?;
    Ok(swarm)
}
