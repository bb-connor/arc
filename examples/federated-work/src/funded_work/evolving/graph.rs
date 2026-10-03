//! Build and extend the existing S1 artifacts. No alternate graph verifier.
use super::super::composition::Config;
use crate::common::{digest, Result};
use chio_core_types::{
    capability::{
        attenuation::{compute_attenuation_witness, scope_hash},
        token::CapabilityToken,
    },
    Keypair,
};
use chio_kernel::ToolCallRequest;
use chio_swarm_authority::*;
use serde_json::{json, Value};

pub(super) fn new(
    config: &Config,
    root: &CapabilityToken,
    witness: &Keypair,
) -> Result<SwarmAuthorityBundle> {
    let issuer = super::super::composition::kernel_id(&witness.public_key());
    let mut epoch = SwarmRevocationEpoch {
        schema: CHIO_SWARM_REVOCATION_EPOCH_SCHEMA.into(),
        epoch_id: format!("epoch-{}", config.program_id),
        root_hash: digest(&json!({"revokedSubjects":[],"revokedTaskIds":[]}))?,
        issued_at_unix_ms: config.profile.issued_at_unix_ms,
        valid_until_unix_ms: config.profile.expires_at_unix_ms,
        revoked_subjects: vec![],
        revoked_task_ids: vec![],
        issuer: issuer.clone(),
        signature: String::new(),
    };
    epoch.signature = sign_swarm_revocation_epoch(&epoch, witness)?;
    Ok(SwarmAuthorityBundle {
        task_graph: SwarmTaskGraph {
            schema: CHIO_SWARM_TASK_GRAPH_SCHEMA.into(),
            graph_id: config.program_id.clone(),
            root_transaction_ref: config.program_id.clone(),
            planner_subject: issuer.clone(),
            issuer,
            signature: String::new(),
            created_at_unix_ms: config.profile.issued_at_unix_ms,
            expires_at_unix_ms: config.profile.expires_at_unix_ms,
            max_depth: 1,
            max_fanout: 3,
            multi_hop_witness_chains: false,
            nodes: vec![SwarmGraphNode {
                task_id: "program".into(),
                parent_task_id: None,
                route_plan_ref: None,
                continuation_token_ref: None,
                budget_allocation_ref: None,
                scope_hash: scope_hash(&root.scope)?,
                depth: 0,
            }],
            edges: vec![],
            joins: vec![],
            budget_pool_ref: config.program_id.clone(),
            revocation_epoch_ref: epoch.epoch_id.clone(),
            route_plan_refs: vec![],
        },
        continuation_tokens: vec![],
        witness_chains: vec![],
        join_receipts: vec![],
        route_plan_receipts: vec![],
        budget_pool: SwarmBudgetPool {
            schema: CHIO_SWARM_BUDGET_POOL_SCHEMA.into(),
            pool_id: config.program_id.clone(),
            graph_id: config.program_id.clone(),
            currency: "XTS".into(),
            total_units: 300,
            allocations: vec![],
        },
        revocation_epoch: epoch,
        terminal_receipts: vec![],
        now_unix_ms: config.profile.issued_at_unix_ms,
    })
}

pub(super) fn add(
    bundle: &mut SwarmAuthorityBundle,
    request: &ToolCallRequest,
    allocation: String,
    root: &CapabilityToken,
    witness: &Keypair,
) -> Result<()> {
    let task = &request.request_id;
    let name = |prefix: &str| format!("{prefix}-{task}");
    let issuer = super::super::composition::kernel_id(&witness.public_key());
    let expires = request.capability.expires_at * 1000;
    let graph = &mut bundle.task_graph;
    graph.nodes.push(SwarmGraphNode {
        task_id: task.clone(),
        parent_task_id: Some("program".into()),
        route_plan_ref: Some(name("route")),
        continuation_token_ref: Some(name("continue")),
        budget_allocation_ref: Some(allocation.clone()),
        scope_hash: scope_hash(&request.capability.scope)?,
        depth: 1,
    });
    graph.edges.push(SwarmGraphEdge {
        from_task_id: "program".into(),
        to_task_id: task.clone(),
        edge_type: "delegates".into(),
    });
    graph.route_plan_refs.push(name("route"));
    let mut route = SwarmRoutePlanReceipt {
        schema: CHIO_SWARM_ROUTE_PLAN_RECEIPT_SCHEMA.into(),
        route_plan_id: name("route"),
        graph_id: graph.graph_id.clone(),
        task_id: task.clone(),
        selected_route: format!("native:{task}"),
        candidate_set_digest: digest(&request.capability.issuer)?,
        registry_snapshot_hash: digest(&"locally-enrolled-receivers")?,
        bridge_id: "native".into(),
        protocol_target: format!("native://{}", request.capability.issuer.to_hex()),
        egress_contract_id: format!("native:egress-{task}"),
        egress_constraints: vec!["deny-private-network".into()],
        attenuation_decision: "accepted".into(),
        policy_digest: digest(&"funded-review-policy")?,
        expires_at_unix_ms: expires,
        issuer: issuer.clone(),
        signature: String::new(),
    };
    route.signature = sign_swarm_route_plan_receipt(&route, witness)?;
    bundle.route_plan_receipts.push(route);
    let mut chain = SwarmDelegationWitnessChain {
        schema: CHIO_SWARM_DELEGATION_WITNESS_CHAIN_SCHEMA.into(),
        chain_id: name("witness"),
        graph_id: graph.graph_id.clone(),
        parent_task_id: "program".into(),
        child_task_id: task.clone(),
        hops: vec![SwarmDelegationWitnessHop {
            parent_capability_digest: digest(root)?,
            child_capability_digest: digest(&request.capability)?,
            parent_scope_hash: scope_hash(&root.scope)?,
            child_scope_hash: scope_hash(&request.capability.scope)?,
            attenuation_rule_id: "rule-subset-tool-invocation".into(),
            scope_subset_proof: compute_attenuation_witness(
                &root.scope,
                &request.capability.scope,
            )?,
            expires_at_unix_ms: expires,
            issuer: issuer.clone(),
            policy_digest: digest(&"funded-review-policy")?,
            witness_signature: String::new(),
        }],
    };
    chain.hops[0].witness_signature =
        sign_swarm_delegation_witness_hop(&chain, &chain.hops[0], witness)?;
    bundle.continuation_tokens.push(SwarmContinuationToken {
        schema: CHIO_SWARM_CONTINUATION_TOKEN_SCHEMA.into(),
        token_id: name("continue"),
        graph_id: graph.graph_id.clone(),
        child_task_id: task.clone(),
        parent_task_id: Some("program".into()),
        join_receipt_id: None,
        parent_receipt_ids: vec![format!("program-consent-{}", graph.graph_id)],
        graph_sha256: String::new(),
        route_plan_receipt_id: name("route"),
        budget_allocation_id: allocation.clone(),
        witness_chain_ref: Some(chain.chain_id.clone()),
        witness_chain_sha256: Some(digest(&chain)?),
        revocation_epoch_ref: bundle.revocation_epoch.epoch_id.clone(),
        revocation_epoch_root_hash: bundle.revocation_epoch.root_hash.clone(),
        session_anchor_ref: format!("session-{}", graph.graph_id),
        nonce: name("nonce"),
        mode: SwarmContinuationMode::SingleUse,
        issued_at_unix_ms: graph.created_at_unix_ms,
        expires_at_unix_ms: expires,
        issuer,
        signature: String::new(),
    });
    bundle.witness_chains.push(chain);
    bundle.budget_pool.allocations.push(SwarmBudgetAllocation {
        allocation_id: allocation,
        task_id: task.clone(),
        dimension_id: "xts_base_units".into(),
        state: SwarmBudgetAllocationState::Active,
        max_units: 100,
        reserved_units: 0,
        active_units: 100,
        consumed_units: 0,
        released_units: 0,
        reversed_units: 0,
    });
    graph.signature = sign_swarm_task_graph(graph, witness)?;
    for token in &mut bundle.continuation_tokens {
        token.graph_sha256 = digest(graph)?;
        token.signature = sign_swarm_continuation_token(token, witness)?;
    }
    Ok(())
}

pub(super) fn context(bundle: &SwarmAuthorityBundle, id: &str) -> Result<Value> {
    let token = bundle
        .continuation_tokens
        .iter()
        .find(|t| t.child_task_id == id)
        .ok_or("task continuation absent")?;
    let route = bundle
        .route_plan_receipts
        .iter()
        .find(|r| r.task_id == id)
        .ok_or("task route absent")?;
    let witness = bundle
        .witness_chains
        .iter()
        .find(|w| w.child_task_id == id)
        .ok_or("task witness absent")?;
    Ok(json!({
        "taskGraph":{"id":bundle.task_graph.graph_id,"sha256":digest(&bundle.task_graph)?},
        "continuationToken":{"id":token.token_id,"sha256":digest(token)?},
        "routePlanReceipt":{"id":route.route_plan_id,"sha256":digest(route)?},
        "delegationWitness":{"id":witness.chain_id,"sha256":digest(witness)?},
        "revocationEpoch":{"id":bundle.revocation_epoch.epoch_id,"sha256":digest(&bundle.revocation_epoch)?},
        "budgetPool":{"id":bundle.budget_pool.pool_id,"sha256":digest(&bundle.budget_pool)?}
    }))
}
