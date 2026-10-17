#![allow(dead_code)]

use chio_core::capability::attenuation::{compute_attenuation_witness, scope_hash};
use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core::crypto::{canonical_json_bytes, sha256_hex, Keypair, PublicKey};
use chio_swarm_authority::{
    sign_swarm_continuation_token, sign_swarm_delegation_witness_hop, sign_swarm_join_receipt,
    sign_swarm_revocation_epoch, sign_swarm_route_plan_receipt, sign_swarm_task_graph,
    sign_swarm_terminal_graph_receipt, SwarmAuthorityBundle, SwarmBudgetAllocation,
    SwarmBudgetAllocationState, SwarmBudgetPool, SwarmContinuationMode, SwarmContinuationToken,
    SwarmDelegationWitnessChain, SwarmDelegationWitnessHop, SwarmGraphEdge, SwarmGraphJoin,
    SwarmGraphNode, SwarmJoinParentReceipt, SwarmJoinReceipt, SwarmRevocationEpoch,
    SwarmRoutePlanReceipt, SwarmTaskGraph, SwarmTerminalBudgetRollup, SwarmTerminalGraphReceipt,
    CHIO_SWARM_BUDGET_POOL_SCHEMA, CHIO_SWARM_CONTINUATION_TOKEN_SCHEMA,
    CHIO_SWARM_DELEGATION_WITNESS_CHAIN_SCHEMA, CHIO_SWARM_JOIN_RECEIPT_SCHEMA,
    CHIO_SWARM_REVOCATION_EPOCH_SCHEMA, CHIO_SWARM_ROUTE_PLAN_RECEIPT_SCHEMA,
    CHIO_SWARM_TASK_GRAPH_SCHEMA, CHIO_SWARM_TERMINAL_GRAPH_RECEIPT_SCHEMA,
};
use std::collections::BTreeMap;
use std::error::Error;

pub const NOW_UNIX_MS: u64 = 1_800_000_001_000;

pub fn versions() -> Result<(SwarmAuthorityBundle, SwarmAuthorityBundle), Box<dyn Error>> {
    let mut next = sample_swarm_bundle()?;
    next.join_receipts.clear();
    next.terminal_receipts.clear();
    let mut prior = next.clone();
    prior
        .task_graph
        .nodes
        .retain(|n| n.task_id != "task-child-b");
    prior
        .task_graph
        .edges
        .retain(|e| e.to_task_id != "task-child-b");
    prior.task_graph.joins.clear();
    prior
        .task_graph
        .route_plan_refs
        .retain(|r| r != "route-child-b");
    prior
        .route_plan_receipts
        .retain(|r| r.task_id != "task-child-b");
    prior
        .continuation_tokens
        .retain(|t| t.child_task_id != "task-child-b");
    prior
        .witness_chains
        .retain(|w| w.child_task_id != "task-child-b");
    prior
        .budget_pool
        .allocations
        .retain(|a| a.task_id != "task-child-b");
    refresh_continuation_graph_digests(&mut prior)?;
    Ok((prior, next))
}

pub fn sample_swarm_bundle() -> Result<SwarmAuthorityBundle, Box<dyn Error>> {
    let parent_scope = scope_for("commerce", "reserve_budget", 3);
    let child_scope = scope_for("commerce", "reserve_budget", 1);
    let parent_scope_hash = scope_hash(&parent_scope)?;
    let child_scope_hash = scope_hash(&child_scope)?;
    let witness = compute_attenuation_witness(&parent_scope, &child_scope)?;

    let mut task_graph = SwarmTaskGraph {
        schema: CHIO_SWARM_TASK_GRAPH_SCHEMA.to_string(),
        graph_id: "swarm-graph-proof-valid".to_string(),
        root_transaction_ref: "passport-swarm-valid".to_string(),
        planner_subject: "did:chio:planner".to_string(),
        issuer: witness_issuer(),
        signature: String::new(),
        created_at_unix_ms: NOW_UNIX_MS - 1_000,
        expires_at_unix_ms: NOW_UNIX_MS + 60_000,
        max_depth: 2,
        max_fanout: 2,
        multi_hop_witness_chains: false,
        nodes: vec![
            SwarmGraphNode {
                task_id: "task-root".to_string(),
                parent_task_id: None,
                route_plan_ref: None,
                continuation_token_ref: None,
                budget_allocation_ref: None,
                scope_hash: parent_scope_hash.clone(),
                depth: 0,
            },
            SwarmGraphNode {
                task_id: "task-child-a".to_string(),
                parent_task_id: Some("task-root".to_string()),
                route_plan_ref: Some("route-child-a".to_string()),
                continuation_token_ref: Some("continuation-child-a".to_string()),
                budget_allocation_ref: Some("budget-child-a".to_string()),
                scope_hash: child_scope_hash.clone(),
                depth: 1,
            },
            SwarmGraphNode {
                task_id: "task-child-b".to_string(),
                parent_task_id: Some("task-root".to_string()),
                route_plan_ref: Some("route-child-b".to_string()),
                continuation_token_ref: Some("continuation-child-b".to_string()),
                budget_allocation_ref: Some("budget-child-b".to_string()),
                scope_hash: child_scope_hash.clone(),
                depth: 1,
            },
        ],
        edges: vec![
            SwarmGraphEdge {
                from_task_id: "task-root".to_string(),
                to_task_id: "task-child-a".to_string(),
                edge_type: "delegates".to_string(),
            },
            SwarmGraphEdge {
                from_task_id: "task-root".to_string(),
                to_task_id: "task-child-b".to_string(),
                edge_type: "delegates".to_string(),
            },
        ],
        joins: vec![SwarmGraphJoin {
            join_id: "join-child-results".to_string(),
            parent_task_ids: vec!["task-child-a".to_string(), "task-child-b".to_string()],
            next_task_id: "task-root".to_string(),
        }],
        budget_pool_ref: "budget-pool-swarm-valid".to_string(),
        revocation_epoch_ref: "revocation-epoch-swarm-valid".to_string(),
        route_plan_refs: vec!["route-child-a".to_string(), "route-child-b".to_string()],
    };
    sign_task_graph(&mut task_graph)?;
    let graph_sha256 = canonical_hash(&task_graph)?;
    let empty_revoked_subjects = Vec::<String>::new();
    let empty_revoked_task_ids = Vec::<String>::new();
    let revocation_epoch_root_hash =
        revocation_epoch_root_hash(&empty_revoked_subjects, &empty_revoked_task_ids)?;

    let witness_chains = vec![
        witness_chain(
            "witness-child-a",
            "task-root",
            "task-child-a",
            &parent_scope_hash,
            &child_scope_hash,
            witness.clone(),
        )?,
        witness_chain(
            "witness-child-b",
            "task-root",
            "task-child-b",
            &parent_scope_hash,
            &child_scope_hash,
            witness,
        )?,
    ];
    let continuation_tokens = vec![
        continuation_token(
            "continuation-child-a",
            "task-child-a",
            "route-child-a",
            &graph_sha256,
            &revocation_epoch_root_hash,
            Some(&witness_chains[0]),
        )?,
        continuation_token(
            "continuation-child-b",
            "task-child-b",
            "route-child-b",
            &graph_sha256,
            &revocation_epoch_root_hash,
            Some(&witness_chains[1]),
        )?,
    ];
    task_graph.nodes[1].continuation_token_ref = Some(continuation_tokens[0].token_id.clone());
    task_graph.nodes[2].continuation_token_ref = Some(continuation_tokens[1].token_id.clone());

    let mut join_receipts = vec![SwarmJoinReceipt {
        schema: CHIO_SWARM_JOIN_RECEIPT_SCHEMA.to_string(),
        join_id: "join-child-results".to_string(),
        graph_id: "swarm-graph-proof-valid".to_string(),
        chain_id: "swarm-chain-proof-valid".to_string(),
        parent_set_hash: join_parent_set_hash(
            "swarm-chain-proof-valid",
            &["receipt-child-a", "receipt-child-b"],
        )?,
        dag_ordinal: 2,
        hlc_unix_ms: NOW_UNIX_MS - 500,
        parent_task_receipts: vec![
            SwarmJoinParentReceipt {
                task_id: "task-child-a".to_string(),
                receipt_id: "receipt-child-a".to_string(),
            },
            SwarmJoinParentReceipt {
                task_id: "task-child-b".to_string(),
                receipt_id: "receipt-child-b".to_string(),
            },
        ],
        expected_parent_receipt_ids: vec![
            "receipt-child-a".to_string(),
            "receipt-child-b".to_string(),
        ],
        actual_parent_receipt_ids: vec![
            "receipt-child-a".to_string(),
            "receipt-child-b".to_string(),
        ],
        join_predicate: "all_success".to_string(),
        result_digest: sha256_hex(b"joined-child-results"),
        next_task_id: "task-root".to_string(),
        issuer: witness_issuer(),
        signature: String::new(),
    }];
    sign_join_receipt(&mut join_receipts[0])?;

    let mut bundle = SwarmAuthorityBundle {
        task_graph,
        continuation_tokens,
        witness_chains,
        join_receipts,
        route_plan_receipts: vec![
            route_plan_receipt("route-child-a", "task-child-a", "mcp", "mcp://provider-a")?,
            route_plan_receipt("route-child-b", "task-child-b", "a2a", "a2a://provider-b")?,
        ],
        budget_pool: SwarmBudgetPool {
            schema: CHIO_SWARM_BUDGET_POOL_SCHEMA.to_string(),
            pool_id: "budget-pool-swarm-valid".to_string(),
            graph_id: "swarm-graph-proof-valid".to_string(),
            currency: "USD".to_string(),
            total_units: 10_000,
            allocations: vec![
                SwarmBudgetAllocation {
                    allocation_id: "budget-child-a".to_string(),
                    task_id: "task-child-a".to_string(),
                    dimension_id: "usd_minor".to_string(),
                    state: SwarmBudgetAllocationState::Active,
                    max_units: 2_500,
                    reserved_units: 0,
                    active_units: 2_500,
                    consumed_units: 0,
                    released_units: 0,
                    reversed_units: 0,
                },
                SwarmBudgetAllocation {
                    allocation_id: "budget-child-b".to_string(),
                    task_id: "task-child-b".to_string(),
                    dimension_id: "usd_minor".to_string(),
                    state: SwarmBudgetAllocationState::Active,
                    max_units: 2_500,
                    reserved_units: 0,
                    active_units: 2_500,
                    consumed_units: 0,
                    released_units: 0,
                    reversed_units: 0,
                },
            ],
        },
        revocation_epoch: SwarmRevocationEpoch {
            schema: CHIO_SWARM_REVOCATION_EPOCH_SCHEMA.to_string(),
            epoch_id: "revocation-epoch-swarm-valid".to_string(),
            root_hash: revocation_epoch_root_hash,
            issued_at_unix_ms: NOW_UNIX_MS - 1_000,
            valid_until_unix_ms: NOW_UNIX_MS + 60_000,
            revoked_subjects: empty_revoked_subjects,
            revoked_task_ids: empty_revoked_task_ids,
            issuer: witness_issuer(),
            signature: String::new(),
        },
        terminal_receipts: vec![terminal_graph_receipt()?],
        now_unix_ms: NOW_UNIX_MS,
    };
    sign_revocation_epoch(&mut bundle.revocation_epoch)?;
    Ok(bundle)
}

pub fn root_only_swarm_bundle() -> Result<SwarmAuthorityBundle, Box<dyn Error>> {
    let root_scope_hash = scope_hash(&scope_for("commerce", "reserve_budget", 1))?;
    let mut task_graph = SwarmTaskGraph {
        schema: CHIO_SWARM_TASK_GRAPH_SCHEMA.to_string(),
        graph_id: "swarm-graph-root-only".to_string(),
        root_transaction_ref: "passport-swarm-root-only".to_string(),
        planner_subject: "did:chio:planner".to_string(),
        issuer: witness_issuer(),
        signature: String::new(),
        created_at_unix_ms: NOW_UNIX_MS - 1_000,
        expires_at_unix_ms: NOW_UNIX_MS + 60_000,
        max_depth: 1,
        max_fanout: 1,
        multi_hop_witness_chains: false,
        nodes: vec![SwarmGraphNode {
            task_id: "task-root".to_string(),
            parent_task_id: None,
            route_plan_ref: None,
            continuation_token_ref: None,
            budget_allocation_ref: None,
            scope_hash: root_scope_hash,
            depth: 0,
        }],
        edges: Vec::new(),
        joins: Vec::new(),
        budget_pool_ref: "budget-pool-swarm-root-only".to_string(),
        revocation_epoch_ref: "revocation-epoch-swarm-root-only".to_string(),
        route_plan_refs: Vec::new(),
    };
    sign_task_graph(&mut task_graph)?;
    let empty_revoked_subjects = Vec::<String>::new();
    let empty_revoked_task_ids = Vec::<String>::new();
    let revocation_epoch_root_hash =
        revocation_epoch_root_hash(&empty_revoked_subjects, &empty_revoked_task_ids)?;
    let mut bundle = SwarmAuthorityBundle {
        task_graph,
        continuation_tokens: Vec::new(),
        witness_chains: Vec::new(),
        join_receipts: Vec::new(),
        route_plan_receipts: Vec::new(),
        budget_pool: SwarmBudgetPool {
            schema: CHIO_SWARM_BUDGET_POOL_SCHEMA.to_string(),
            pool_id: "budget-pool-swarm-root-only".to_string(),
            graph_id: "swarm-graph-root-only".to_string(),
            currency: "USD".to_string(),
            total_units: 0,
            allocations: Vec::new(),
        },
        revocation_epoch: SwarmRevocationEpoch {
            schema: CHIO_SWARM_REVOCATION_EPOCH_SCHEMA.to_string(),
            epoch_id: "revocation-epoch-swarm-root-only".to_string(),
            root_hash: revocation_epoch_root_hash,
            issued_at_unix_ms: NOW_UNIX_MS - 1_000,
            valid_until_unix_ms: NOW_UNIX_MS + 60_000,
            revoked_subjects: empty_revoked_subjects,
            revoked_task_ids: empty_revoked_task_ids,
            issuer: witness_issuer(),
            signature: String::new(),
        },
        terminal_receipts: Vec::new(),
        now_unix_ms: NOW_UNIX_MS,
    };
    sign_revocation_epoch(&mut bundle.revocation_epoch)?;
    Ok(bundle)
}

pub fn continuation_token(
    token_id: &str,
    child_task_id: &str,
    route_plan_receipt_id: &str,
    graph_sha256: &str,
    revocation_epoch_root_hash: &str,
    witness_chain: Option<&SwarmDelegationWitnessChain>,
) -> Result<SwarmContinuationToken, Box<dyn Error>> {
    let witness_chain_ref = witness_chain.map(|chain| chain.chain_id.clone());
    let witness_chain_sha256 = witness_chain.map(canonical_hash).transpose()?;
    let mut token = SwarmContinuationToken {
        schema: CHIO_SWARM_CONTINUATION_TOKEN_SCHEMA.to_string(),
        token_id: token_id.to_string(),
        graph_id: "swarm-graph-proof-valid".to_string(),
        child_task_id: child_task_id.to_string(),
        parent_task_id: Some("task-root".to_string()),
        join_receipt_id: None,
        parent_receipt_ids: vec!["receipt-root".to_string()],
        graph_sha256: graph_sha256.to_string(),
        route_plan_receipt_id: route_plan_receipt_id.to_string(),
        budget_allocation_id: format!("budget-{}", child_task_id.trim_start_matches("task-")),
        witness_chain_ref,
        witness_chain_sha256,
        revocation_epoch_ref: "revocation-epoch-swarm-valid".to_string(),
        revocation_epoch_root_hash: revocation_epoch_root_hash.to_string(),
        session_anchor_ref: "session-anchor-swarm-valid".to_string(),
        nonce: format!("nonce-{child_task_id}"),
        mode: SwarmContinuationMode::SingleUse,
        issued_at_unix_ms: NOW_UNIX_MS - 1_000,
        expires_at_unix_ms: NOW_UNIX_MS + 60_000,
        issuer: witness_issuer(),
        signature: String::new(),
    };
    sign_continuation_token(&mut token)?;
    Ok(token)
}

pub fn sign_continuation_token(token: &mut SwarmContinuationToken) -> Result<(), Box<dyn Error>> {
    token.signature = sign_swarm_continuation_token(token, &witness_keypair())?;
    Ok(())
}

pub fn sign_task_graph(graph: &mut SwarmTaskGraph) -> Result<(), Box<dyn Error>> {
    graph.signature = sign_swarm_task_graph(graph, &witness_keypair())?;
    Ok(())
}

pub fn sign_join_receipt(receipt: &mut SwarmJoinReceipt) -> Result<(), Box<dyn Error>> {
    receipt.signature = sign_swarm_join_receipt(receipt, &witness_keypair())?;
    Ok(())
}

pub fn sign_route_plan_receipt(receipt: &mut SwarmRoutePlanReceipt) -> Result<(), Box<dyn Error>> {
    receipt.signature = sign_swarm_route_plan_receipt(receipt, &witness_keypair())?;
    Ok(())
}

pub fn sign_terminal_graph_receipt(
    receipt: &mut SwarmTerminalGraphReceipt,
) -> Result<(), Box<dyn Error>> {
    receipt.signature = sign_swarm_terminal_graph_receipt(receipt, &witness_keypair())?;
    Ok(())
}

pub fn sign_revocation_epoch(epoch: &mut SwarmRevocationEpoch) -> Result<(), Box<dyn Error>> {
    epoch.signature = sign_swarm_revocation_epoch(epoch, &witness_keypair())?;
    Ok(())
}

pub fn refresh_join_receipt_parent_set_hash(
    receipt: &mut SwarmJoinReceipt,
) -> Result<(), Box<dyn Error>> {
    let receipt_ids = receipt
        .actual_parent_receipt_ids
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    receipt.parent_set_hash = join_parent_set_hash(&receipt.chain_id, &receipt_ids)?;
    Ok(())
}

pub fn keep_first_join_parent_receipt(
    receipt: &mut SwarmJoinReceipt,
) -> Result<(), Box<dyn Error>> {
    receipt.actual_parent_receipt_ids.truncate(1);
    receipt.parent_task_receipts.truncate(1);
    refresh_join_receipt_parent_set_hash(receipt)
}

pub fn join_parent_set_hash(
    chain_id: &str,
    receipt_ids: &[&str],
) -> Result<String, Box<dyn Error>> {
    let mut sorted_receipt_ids = receipt_ids.to_vec();
    sorted_receipt_ids.sort();
    let body = serde_json::json!({
        "chainId": chain_id,
        "parentReceiptIds": sorted_receipt_ids,
    });
    Ok(sha256_hex(&canonical_json_bytes(&body)?))
}

pub fn witness_chain(
    chain_id: &str,
    parent_task_id: &str,
    child_task_id: &str,
    parent_scope_hash: &str,
    child_scope_hash: &str,
    scope_subset_proof: chio_core::capability::attenuation::AttenuationWitness,
) -> Result<SwarmDelegationWitnessChain, Box<dyn Error>> {
    let mut chain = SwarmDelegationWitnessChain {
        schema: CHIO_SWARM_DELEGATION_WITNESS_CHAIN_SCHEMA.to_string(),
        chain_id: chain_id.to_string(),
        graph_id: "swarm-graph-proof-valid".to_string(),
        parent_task_id: parent_task_id.to_string(),
        child_task_id: child_task_id.to_string(),
        hops: vec![SwarmDelegationWitnessHop {
            parent_capability_digest: sha256_hex(b"parent-capability"),
            child_capability_digest: sha256_hex(child_task_id.as_bytes()),
            parent_scope_hash: parent_scope_hash.to_string(),
            child_scope_hash: child_scope_hash.to_string(),
            attenuation_rule_id: "rule-subset-tool-invocation".to_string(),
            scope_subset_proof,
            expires_at_unix_ms: NOW_UNIX_MS + 60_000,
            issuer: witness_issuer(),
            policy_digest: sha256_hex(b"swarm-policy"),
            witness_signature: String::new(),
        }],
    };
    sign_witness_chain(&mut chain)?;
    Ok(chain)
}

pub fn set_child_a_multi_hop_witness(
    bundle: &mut SwarmAuthorityBundle,
) -> Result<(), Box<dyn Error>> {
    let parent_scope = scope_for("commerce", "reserve_budget", 3);
    let intermediate_scope = scope_for("commerce", "reserve_budget", 2);
    let child_scope = scope_for("commerce", "reserve_budget", 1);
    let parent_scope_hash = scope_hash(&parent_scope)?;
    let intermediate_scope_hash = scope_hash(&intermediate_scope)?;
    let child_scope_hash = scope_hash(&child_scope)?;

    bundle.witness_chains[0].hops = vec![
        SwarmDelegationWitnessHop {
            parent_capability_digest: sha256_hex(b"parent-capability"),
            child_capability_digest: sha256_hex(b"intermediate-capability"),
            parent_scope_hash: parent_scope_hash.clone(),
            child_scope_hash: intermediate_scope_hash.clone(),
            attenuation_rule_id: "rule-subset-tool-invocation".to_string(),
            scope_subset_proof: compute_attenuation_witness(&parent_scope, &intermediate_scope)?,
            expires_at_unix_ms: NOW_UNIX_MS + 60_000,
            issuer: witness_issuer(),
            policy_digest: sha256_hex(b"swarm-policy"),
            witness_signature: String::new(),
        },
        SwarmDelegationWitnessHop {
            parent_capability_digest: sha256_hex(b"intermediate-capability"),
            child_capability_digest: sha256_hex(b"task-child-a"),
            parent_scope_hash: intermediate_scope_hash,
            child_scope_hash,
            attenuation_rule_id: "rule-subset-tool-invocation".to_string(),
            scope_subset_proof: compute_attenuation_witness(&intermediate_scope, &child_scope)?,
            expires_at_unix_ms: NOW_UNIX_MS + 60_000,
            issuer: witness_issuer(),
            policy_digest: sha256_hex(b"swarm-policy"),
            witness_signature: String::new(),
        },
    ];
    sign_witness_chain(&mut bundle.witness_chains[0])?;
    Ok(())
}

pub fn sign_witness_chain(chain: &mut SwarmDelegationWitnessChain) -> Result<(), Box<dyn Error>> {
    let keypair = witness_keypair();
    for index in 0..chain.hops.len() {
        let signature = sign_swarm_delegation_witness_hop(chain, &chain.hops[index], &keypair)?;
        chain.hops[index].witness_signature = signature;
    }
    Ok(())
}

pub fn witness_keypair() -> Keypair {
    Keypair::from_seed(&[31u8; 32])
}

pub fn trusted_witness_keys() -> Vec<PublicKey> {
    vec![witness_keypair().public_key()]
}

pub fn witness_issuer() -> String {
    format!("did:chio:{}", witness_keypair().public_key().to_hex())
}

pub fn route_plan_receipt(
    route_plan_id: &str,
    task_id: &str,
    bridge_id: &str,
    protocol_target: &str,
) -> Result<SwarmRoutePlanReceipt, Box<dyn Error>> {
    let mut receipt = SwarmRoutePlanReceipt {
        schema: CHIO_SWARM_ROUTE_PLAN_RECEIPT_SCHEMA.to_string(),
        route_plan_id: route_plan_id.to_string(),
        graph_id: "swarm-graph-proof-valid".to_string(),
        task_id: task_id.to_string(),
        selected_route: format!("{bridge_id}:{task_id}"),
        candidate_set_digest: sha256_hex(format!("candidates-{task_id}").as_bytes()),
        registry_snapshot_hash: sha256_hex(b"registry-snapshot"),
        bridge_id: bridge_id.to_string(),
        protocol_target: protocol_target.to_string(),
        egress_contract_id: format!("{bridge_id}:egress-contract-{task_id}"),
        egress_constraints: vec!["deny-private-network".to_string()],
        attenuation_decision: "accepted".to_string(),
        policy_digest: sha256_hex(b"swarm-route-policy"),
        expires_at_unix_ms: NOW_UNIX_MS + 60_000,
        issuer: witness_issuer(),
        signature: String::new(),
    };
    sign_route_plan_receipt(&mut receipt)?;
    Ok(receipt)
}

pub fn terminal_graph_receipt() -> Result<SwarmTerminalGraphReceipt, Box<dyn Error>> {
    let mut receipt = SwarmTerminalGraphReceipt {
        schema: CHIO_SWARM_TERMINAL_GRAPH_RECEIPT_SCHEMA.to_string(),
        receipt_id: "terminal-swarm-proof-valid".to_string(),
        graph_id: "swarm-graph-proof-valid".to_string(),
        chain_id: "swarm-chain-proof-valid".to_string(),
        terminal_task_ids: vec!["task-root".to_string()],
        completed_task_ids: vec![
            "task-root".to_string(),
            "task-child-a".to_string(),
            "task-child-b".to_string(),
        ],
        join_receipt_ids: vec!["join-child-results".to_string()],
        route_plan_receipt_ids: vec!["route-child-a".to_string(), "route-child-b".to_string()],
        budget_pool_id: "budget-pool-swarm-valid".to_string(),
        budget_rollups: vec![SwarmTerminalBudgetRollup {
            dimension_id: "usd_minor".to_string(),
            reserved_units: 0,
            active_units: 5_000,
            consumed_units: 0,
            released_units: 0,
            reversed_units: 0,
            total_units: 5_000,
        }],
        revocation_epoch_ref: "revocation-epoch-swarm-valid".to_string(),
        result_digest: sha256_hex(b"joined-child-results"),
        completed_at_unix_ms: NOW_UNIX_MS,
        issuer: witness_issuer(),
        signature: String::new(),
    };
    sign_terminal_graph_receipt(&mut receipt)?;
    Ok(receipt)
}

pub fn scope_for(server_id: &str, tool_name: &str, max_invocations: u32) -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: server_id.to_string(),
            tool_name: tool_name.to_string(),
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

pub fn canonical_hash<T: serde::Serialize>(value: &T) -> Result<String, Box<dyn Error>> {
    Ok(sha256_hex(&canonical_json_bytes(value)?))
}

pub fn revocation_epoch_root_hash(
    revoked_subjects: &[String],
    revoked_task_ids: &[String],
) -> Result<String, Box<dyn Error>> {
    let mut subjects = revoked_subjects
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    subjects.sort_unstable();
    let mut task_ids = revoked_task_ids
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    task_ids.sort_unstable();
    canonical_hash(&serde_json::json!({
        "revokedSubjects": subjects,
        "revokedTaskIds": task_ids,
    }))
}

pub fn refresh_revocation_epoch_root(
    bundle: &mut SwarmAuthorityBundle,
) -> Result<(), Box<dyn Error>> {
    let root_hash = revocation_epoch_root_hash(
        &bundle.revocation_epoch.revoked_subjects,
        &bundle.revocation_epoch.revoked_task_ids,
    )?;
    bundle.revocation_epoch.root_hash = root_hash.clone();
    sign_revocation_epoch(&mut bundle.revocation_epoch)?;
    for token in &mut bundle.continuation_tokens {
        token.revocation_epoch_root_hash = root_hash.clone();
        sign_continuation_token(token)?;
    }
    Ok(())
}

pub fn refresh_continuation_graph_digests(
    bundle: &mut SwarmAuthorityBundle,
) -> Result<(), Box<dyn Error>> {
    sign_task_graph(&mut bundle.task_graph)?;
    let graph_sha256 = canonical_hash(&bundle.task_graph)?;
    let mut witness_bindings = BTreeMap::new();
    for chain in &bundle.witness_chains {
        witness_bindings.insert(
            (chain.parent_task_id.as_str(), chain.child_task_id.as_str()),
            (chain.chain_id.clone(), canonical_hash(chain)?),
        );
    }
    for token in &mut bundle.continuation_tokens {
        token.graph_sha256 = graph_sha256.clone();
        if let Some(parent_task_id) = token.parent_task_id.as_deref() {
            if let Some((chain_id, chain_sha256)) =
                witness_bindings.get(&(parent_task_id, token.child_task_id.as_str()))
            {
                token.witness_chain_ref = Some(chain_id.clone());
                token.witness_chain_sha256 = Some(chain_sha256.clone());
            }
        }
        sign_continuation_token(token)?;
    }
    Ok(())
}

/// `base` plus one additional grandchild task under `task-child-a`.
pub fn with_grandchild(
    base: &SwarmAuthorityBundle,
    suffix: &str,
) -> Result<SwarmAuthorityBundle, Box<dyn Error>> {
    let mut next = base.clone();
    let id = format!("task-grandchild-{suffix}");
    let route = format!("route-grandchild-{suffix}");
    let continuation = format!("continuation-grandchild-{suffix}");
    let budget = format!("budget-grandchild-{suffix}");
    let mut task = next.task_graph.nodes[1].clone();
    task.task_id = id.clone();
    task.parent_task_id = Some("task-child-a".into());
    task.route_plan_ref = Some(route.clone());
    task.continuation_token_ref = Some(continuation.clone());
    task.budget_allocation_ref = Some(budget.clone());
    task.depth = 2;
    next.task_graph.nodes.push(task);
    next.task_graph.edges.push(SwarmGraphEdge {
        from_task_id: "task-child-a".into(),
        to_task_id: id.clone(),
        edge_type: "delegates".into(),
    });
    next.task_graph.route_plan_refs.push(route.clone());
    next.route_plan_receipts.push(route_plan_receipt(
        &route,
        &id,
        "mcp",
        &format!("mcp://grandchild-{suffix}"),
    )?);
    let mut allocation = next.budget_pool.allocations[0].clone();
    allocation.allocation_id = budget.clone();
    allocation.task_id = id.clone();
    next.budget_pool.allocations.push(allocation);
    let scope = scope_for("commerce", "reserve_budget", 1);
    let digest = scope_hash(&scope)?;
    next.witness_chains.push(witness_chain(
        &format!("witness-grandchild-{suffix}"),
        "task-child-a",
        &id,
        &digest,
        &digest,
        compute_attenuation_witness(&scope, &scope)?,
    )?);
    let mut token = next.continuation_tokens[0].clone();
    token.token_id = continuation;
    token.child_task_id = id;
    token.parent_task_id = Some("task-child-a".into());
    token.parent_receipt_ids = vec!["receipt-child-a".into()];
    token.route_plan_receipt_id = route;
    token.budget_allocation_id = budget;
    token.nonce = format!("nonce-grandchild-{suffix}");
    next.continuation_tokens.push(token);
    refresh_continuation_graph_digests(&mut next)?;
    Ok(next)
}

/// `next` with a different nonce on the continuation for `task-child-b`,
/// so it is a second valid extension of the same parent.
pub fn competing_extension(
    next: &SwarmAuthorityBundle,
) -> Result<SwarmAuthorityBundle, Box<dyn Error>> {
    let mut rival = next.clone();
    for token in &mut rival.continuation_tokens {
        if token.child_task_id == "task-child-b" {
            token.nonce = "rival-nonce".into();
        }
    }
    refresh_continuation_graph_digests(&mut rival)?;
    Ok(rival)
}
