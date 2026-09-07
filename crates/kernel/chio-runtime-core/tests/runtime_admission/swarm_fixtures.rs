use super::*;

pub(super) fn runtime_swarm_continuation(
    token_id: &str,
    child_task_id: &str,
    route_plan_receipt_id: &str,
    budget_allocation_id: &str,
    graph_sha256: &str,
    revocation_epoch_root_hash: &str,
    stale: bool,
) -> Result<SwarmContinuationToken, Box<dyn std::error::Error>> {
    let mut token = SwarmContinuationToken {
        schema: CHIO_SWARM_CONTINUATION_TOKEN_SCHEMA.to_string(),
        token_id: token_id.to_string(),
        graph_id: "swarm-graph-runtime".to_string(),
        child_task_id: child_task_id.to_string(),
        parent_task_id: Some("task-root".to_string()),
        join_receipt_id: None,
        parent_receipt_ids: vec!["receipt-root".to_string()],
        graph_sha256: graph_sha256.to_string(),
        route_plan_receipt_id: route_plan_receipt_id.to_string(),
        budget_allocation_id: budget_allocation_id.to_string(),
        witness_chain_ref: None,
        witness_chain_sha256: None,
        revocation_epoch_ref: "revocation-epoch-runtime".to_string(),
        revocation_epoch_root_hash: revocation_epoch_root_hash.to_string(),
        session_anchor_ref: "session-anchor-runtime".to_string(),
        nonce: format!("nonce-{child_task_id}"),
        mode: SwarmContinuationMode::SingleUse,
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: if stale {
            1_800_000_000_999
        } else {
            1_800_003_600_000
        },
        issuer: swarm_witness_issuer(),
        signature: String::new(),
    };
    token.signature = sign_swarm_continuation_token(&token, &swarm_witness_keypair())?;
    Ok(token)
}

pub(super) fn runtime_swarm_witness_chain(
    chain_id: &str,
    child_task_id: &str,
    parent_scope_hash: &str,
    child_scope_hash: &str,
    scope_subset_proof: chio_core_types::capability::attenuation::AttenuationWitness,
) -> Result<SwarmDelegationWitnessChain, Box<dyn std::error::Error>> {
    let mut chain = SwarmDelegationWitnessChain {
        schema: CHIO_SWARM_DELEGATION_WITNESS_CHAIN_SCHEMA.to_string(),
        chain_id: chain_id.to_string(),
        graph_id: "swarm-graph-runtime".to_string(),
        parent_task_id: "task-root".to_string(),
        child_task_id: child_task_id.to_string(),
        hops: vec![SwarmDelegationWitnessHop {
            parent_capability_digest: sha256_hex(b"parent-capability"),
            child_capability_digest: sha256_hex(child_task_id.as_bytes()),
            parent_scope_hash: parent_scope_hash.to_string(),
            child_scope_hash: child_scope_hash.to_string(),
            attenuation_rule_id: "rule-subset-tool-invocation".to_string(),
            scope_subset_proof,
            expires_at_unix_ms: 1_800_003_600_000,
            issuer: swarm_witness_issuer(),
            policy_digest: sha256_hex(b"swarm-policy"),
            witness_signature: String::new(),
        }],
    };
    chain.hops[0].witness_signature =
        sign_swarm_delegation_witness_hop(&chain, &chain.hops[0], &swarm_witness_keypair())?;
    Ok(chain)
}

pub(super) fn runtime_swarm_scope(max_invocations: u32) -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: "vendor-ledger".to_string(),
            tool_name: "close_account".to_string(),
            operations: vec![Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: Some(max_invocations),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    }
}

pub(super) fn swarm_witness_keypair() -> Keypair {
    Keypair::from_seed(&[31u8; 32])
}

pub(super) fn trusted_swarm_witness_keys() -> Vec<PublicKey> {
    vec![swarm_witness_keypair().public_key()]
}

pub(super) fn swarm_witness_issuer() -> String {
    format!("did:chio:{}", swarm_witness_keypair().public_key().to_hex())
}

pub(super) fn runtime_swarm_join_parent_set_hash(
    chain_id: &str,
    receipt_ids: &[&str],
) -> Result<String, Box<dyn std::error::Error>> {
    let mut sorted_receipt_ids = receipt_ids.to_vec();
    sorted_receipt_ids.sort();
    let body = serde_json::json!({
        "chainId": chain_id,
        "parentReceiptIds": sorted_receipt_ids,
    });
    Ok(sha256_hex(&canonical_json_bytes(&body)?))
}

pub(super) fn runtime_swarm_route_plan_receipt(
    route_plan_id: &str,
    task_id: &str,
    bridge_id: &str,
    protocol_target: &str,
    candidate_seed: &[u8],
) -> Result<SwarmRoutePlanReceipt, Box<dyn std::error::Error>> {
    let mut receipt = SwarmRoutePlanReceipt {
        schema: CHIO_SWARM_ROUTE_PLAN_RECEIPT_SCHEMA.to_string(),
        route_plan_id: route_plan_id.to_string(),
        graph_id: "swarm-graph-runtime".to_string(),
        task_id: task_id.to_string(),
        selected_route: format!("{bridge_id}:{task_id}"),
        candidate_set_digest: sha256_hex(candidate_seed),
        registry_snapshot_hash: sha256_hex(b"runtime-swarm-registry"),
        bridge_id: bridge_id.to_string(),
        protocol_target: protocol_target.to_string(),
        egress_contract_id: format!("{bridge_id}:egress-contract-{task_id}"),
        egress_constraints: vec!["deny-private-network".to_string()],
        attenuation_decision: "accepted".to_string(),
        policy_digest: sha256_hex(b"swarm-route-policy"),
        expires_at_unix_ms: 1_800_003_600_000,
        issuer: swarm_witness_issuer(),
        signature: String::new(),
    };
    receipt.signature = sign_swarm_route_plan_receipt(&receipt, &swarm_witness_keypair())?;
    Ok(receipt)
}

pub(super) fn runtime_swarm_terminal_graph_receipt(
) -> Result<SwarmTerminalGraphReceipt, Box<dyn std::error::Error>> {
    let mut receipt = SwarmTerminalGraphReceipt {
        schema: CHIO_SWARM_TERMINAL_GRAPH_RECEIPT_SCHEMA.to_string(),
        receipt_id: "terminal-swarm-runtime".to_string(),
        graph_id: "swarm-graph-runtime".to_string(),
        chain_id: "swarm-chain-swarm-graph-runtime".to_string(),
        terminal_task_ids: vec!["task-root".to_string()],
        completed_task_ids: vec![
            "task-root".to_string(),
            "task-child-a".to_string(),
            "task-child-b".to_string(),
        ],
        join_receipt_ids: vec!["join-child-results".to_string()],
        route_plan_receipt_ids: vec!["route-child-a".to_string(), "route-child-b".to_string()],
        budget_pool_id: "budget-pool-runtime".to_string(),
        budget_rollups: vec![SwarmTerminalBudgetRollup {
            dimension_id: "usd_minor".to_string(),
            reserved_units: 0,
            active_units: 2_000,
            consumed_units: 0,
            released_units: 0,
            reversed_units: 0,
            total_units: 2_000,
        }],
        revocation_epoch_ref: "revocation-epoch-runtime".to_string(),
        result_digest: sha256_hex(b"joined-child-results"),
        completed_at_unix_ms: 1_800_000_000_500,
        issuer: swarm_witness_issuer(),
        signature: String::new(),
    };
    receipt.signature = sign_swarm_terminal_graph_receipt(&receipt, &swarm_witness_keypair())?;
    Ok(receipt)
}

pub(super) fn canonical_test_hash<T: serde::Serialize>(
    value: &T,
) -> Result<String, Box<dyn std::error::Error>> {
    Ok(sha256_hex(&canonical_json_bytes(value)?))
}

pub(super) fn runtime_swarm_revocation_root(
    revoked_subjects: &[&str],
    revoked_task_ids: &[&str],
) -> Result<String, Box<dyn std::error::Error>> {
    let mut revoked_subjects = revoked_subjects.to_vec();
    let mut revoked_task_ids = revoked_task_ids.to_vec();
    revoked_subjects.sort_unstable();
    revoked_task_ids.sort_unstable();
    canonical_test_hash(&serde_json::json!({
        "revokedSubjects": revoked_subjects,
        "revokedTaskIds": revoked_task_ids,
    }))
}
