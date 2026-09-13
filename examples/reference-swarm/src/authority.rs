//! The swarm authority bundle for one run.
//!
//! The orchestrator delegates to a reader worker and a writer worker, each
//! holding a scope narrower than the orchestrator's, a route to its edge, an
//! allocation from one budget pool, and a continuation token bound to the
//! signed task graph. The bundle is verified before any worker starts and
//! again after the run, with the pool released and a terminal receipt.

use std::collections::BTreeMap;
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core_types::capability::attenuation::{compute_attenuation_witness, scope_hash};
use chio_core_types::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core_types::crypto::{canonical_json_bytes, sha256_hex, Keypair, PublicKey};
use chio_swarm_authority::{
    release_swarm_budget_fanin, reserve_swarm_budget_fanout, sign_swarm_continuation_token,
    sign_swarm_delegation_witness_hop, sign_swarm_join_receipt, sign_swarm_revocation_epoch,
    sign_swarm_route_plan_receipt, sign_swarm_task_graph, sign_swarm_terminal_graph_receipt,
    verify_swarm_authority_bundle, SwarmAuthorityBundle, SwarmAuthorityError,
    SwarmAuthorityVerifierReport, SwarmBudgetAllocation, SwarmBudgetAllocationState,
    SwarmBudgetFanInReleaseRequest, SwarmBudgetFanoutAllocationRequest,
    SwarmBudgetFanoutReservationRequest, SwarmBudgetPool, SwarmContinuationMode,
    SwarmContinuationToken, SwarmDelegationWitnessChain, SwarmDelegationWitnessHop, SwarmGraphEdge,
    SwarmGraphJoin, SwarmGraphNode, SwarmJoinParentReceipt, SwarmJoinReceipt, SwarmRevocationEpoch,
    SwarmRoutePlanReceipt, SwarmTaskGraph, SwarmTerminalBudgetRollup, SwarmTerminalGraphReceipt,
    CHIO_SWARM_BUDGET_POOL_SCHEMA, CHIO_SWARM_CONTINUATION_TOKEN_SCHEMA,
    CHIO_SWARM_DELEGATION_WITNESS_CHAIN_SCHEMA, CHIO_SWARM_JOIN_RECEIPT_SCHEMA,
    CHIO_SWARM_REVOCATION_EPOCH_SCHEMA, CHIO_SWARM_ROUTE_PLAN_RECEIPT_SCHEMA,
    CHIO_SWARM_TASK_GRAPH_SCHEMA, CHIO_SWARM_TERMINAL_GRAPH_RECEIPT_SCHEMA,
};

type Fallible<T> = Result<T, Box<dyn Error>>;

pub const ROOT_TASK: &str = "task-orchestrator";
/// Calls each worker may make: one budget unit per call.
pub const CALLS_PER_WORKER: u64 = 6;
const DIMENSION: &str = "tool_calls";
const VALIDITY_MS: u64 = 10 * 60 * 1000;

/// One worker: its task, the edge it is routed to and the tools it may call.
#[derive(Clone, Debug)]
pub struct WorkerGrant {
    pub task_id: String,
    pub server_id: String,
    pub tools: Vec<String>,
    pub route_target: String,
}

/// The verified delegation of one run.
pub struct SwarmPlan {
    pub run_id: String,
    pub bundle: SwarmAuthorityBundle,
    keypair: Keypair,
    parent_scope: ChioScope,
}

pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn grant(server_id: &str, tool: &str) -> ToolGrant {
    ToolGrant {
        server_id: server_id.to_string(),
        tool_name: tool.to_string(),
        operations: vec![Operation::Invoke],
        constraints: Vec::new(),
        max_invocations: Some(u32::try_from(CALLS_PER_WORKER).unwrap_or(u32::MAX)),
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    }
}

fn scope_of(workers: &[&WorkerGrant]) -> ChioScope {
    ChioScope {
        grants: workers
            .iter()
            .flat_map(|worker| {
                worker
                    .tools
                    .iter()
                    .map(|tool| grant(&worker.server_id, tool))
            })
            .collect(),
        ..ChioScope::default()
    }
}

fn canonical_hash<T: serde::Serialize>(value: &T) -> Fallible<String> {
    Ok(sha256_hex(&canonical_json_bytes(value)?))
}

fn revocation_epoch_root_hash(
    revoked_subjects: &[String],
    revoked_task_ids: &[String],
) -> Fallible<String> {
    let mut subjects: Vec<&str> = revoked_subjects.iter().map(String::as_str).collect();
    subjects.sort_unstable();
    let mut task_ids: Vec<&str> = revoked_task_ids.iter().map(String::as_str).collect();
    task_ids.sort_unstable();
    canonical_hash(&serde_json::json!({ "revokedSubjects": subjects, "revokedTaskIds": task_ids }))
}

fn short(task_id: &str) -> &str {
    task_id.trim_start_matches("task-")
}

/// Build and sign the bundle for `workers` under a fresh orchestrator key.
pub fn build_plan(run_id: &str, workers: &[WorkerGrant]) -> Fallible<SwarmPlan> {
    if workers.len() < 2 {
        return Err("a swarm needs at least two workers".into());
    }
    let keypair = Keypair::generate();
    let issuer = format!("did:chio:{}", keypair.public_key().to_hex());
    let now = now_unix_ms();
    let graph_id = format!("reference-swarm-{run_id}");
    let pool_id = format!("budget-pool-{run_id}");
    let epoch_id = format!("revocation-epoch-{run_id}");
    let chain_id = format!("swarm-chain-{run_id}");
    let parent_scope = scope_of(&workers.iter().collect::<Vec<_>>());
    let parent_hash = scope_hash(&parent_scope)?;

    let mut nodes = vec![SwarmGraphNode {
        task_id: ROOT_TASK.to_string(),
        parent_task_id: None,
        route_plan_ref: None,
        continuation_token_ref: None,
        budget_allocation_ref: None,
        scope_hash: parent_hash.clone(),
        depth: 0,
    }];
    let mut edges = Vec::new();
    let mut child_hashes = Vec::new();
    for worker in workers {
        let child_scope = scope_of(&[worker]);
        let child_hash = scope_hash(&child_scope)?;
        nodes.push(SwarmGraphNode {
            task_id: worker.task_id.clone(),
            parent_task_id: Some(ROOT_TASK.to_string()),
            route_plan_ref: Some(format!("route-{}", short(&worker.task_id))),
            continuation_token_ref: Some(format!("continuation-{}", short(&worker.task_id))),
            budget_allocation_ref: Some(format!("budget-{}", short(&worker.task_id))),
            scope_hash: child_hash.clone(),
            depth: 1,
        });
        edges.push(SwarmGraphEdge {
            from_task_id: ROOT_TASK.to_string(),
            to_task_id: worker.task_id.clone(),
            edge_type: "delegates".to_string(),
        });
        child_hashes.push((child_scope, child_hash));
    }
    let mut task_graph = SwarmTaskGraph {
        schema: CHIO_SWARM_TASK_GRAPH_SCHEMA.to_string(),
        graph_id: graph_id.clone(),
        root_transaction_ref: format!("run-{run_id}"),
        planner_subject: issuer.clone(),
        issuer: issuer.clone(),
        signature: String::new(),
        created_at_unix_ms: now,
        expires_at_unix_ms: now + VALIDITY_MS,
        max_depth: 2,
        max_fanout: u32::try_from(workers.len()).unwrap_or(u32::MAX),
        multi_hop_witness_chains: false,
        nodes,
        edges,
        joins: vec![SwarmGraphJoin {
            join_id: format!("join-{run_id}"),
            parent_task_ids: workers
                .iter()
                .map(|worker| worker.task_id.clone())
                .collect(),
            next_task_id: ROOT_TASK.to_string(),
        }],
        budget_pool_ref: pool_id.clone(),
        revocation_epoch_ref: epoch_id.clone(),
        route_plan_refs: workers
            .iter()
            .map(|worker| format!("route-{}", short(&worker.task_id)))
            .collect(),
    };
    task_graph.signature = sign_swarm_task_graph(&task_graph, &keypair)?;
    let graph_sha256 = canonical_hash(&task_graph)?;
    let epoch_root = revocation_epoch_root_hash(&[], &[])?;

    let mut witness_chains = Vec::new();
    let mut continuation_tokens = Vec::new();
    let mut route_plan_receipts = Vec::new();
    let mut allocations = Vec::new();
    for (worker, (child_scope, child_hash)) in workers.iter().zip(&child_hashes) {
        let proof = compute_attenuation_witness(&parent_scope, child_scope)?;
        let mut chain = SwarmDelegationWitnessChain {
            schema: CHIO_SWARM_DELEGATION_WITNESS_CHAIN_SCHEMA.to_string(),
            chain_id: format!("witness-{}", short(&worker.task_id)),
            graph_id: graph_id.clone(),
            parent_task_id: ROOT_TASK.to_string(),
            child_task_id: worker.task_id.clone(),
            hops: vec![SwarmDelegationWitnessHop {
                parent_capability_digest: sha256_hex(ROOT_TASK.as_bytes()),
                child_capability_digest: sha256_hex(worker.task_id.as_bytes()),
                parent_scope_hash: parent_hash.clone(),
                child_scope_hash: child_hash.clone(),
                attenuation_rule_id: "rule-subset-tool-invocation".to_string(),
                scope_subset_proof: proof,
                expires_at_unix_ms: now + VALIDITY_MS,
                issuer: issuer.clone(),
                policy_digest: sha256_hex(b"reference-swarm-policy"),
                witness_signature: String::new(),
            }],
        };
        let signature = sign_swarm_delegation_witness_hop(&chain, &chain.hops[0], &keypair)?;
        chain.hops[0].witness_signature = signature;

        let mut route = SwarmRoutePlanReceipt {
            schema: CHIO_SWARM_ROUTE_PLAN_RECEIPT_SCHEMA.to_string(),
            route_plan_id: format!("route-{}", short(&worker.task_id)),
            graph_id: graph_id.clone(),
            task_id: worker.task_id.clone(),
            selected_route: format!("mcp:{}", worker.server_id),
            candidate_set_digest: sha256_hex(worker.server_id.as_bytes()),
            registry_snapshot_hash: sha256_hex(b"reference-runtime-registry"),
            bridge_id: "mcp".to_string(),
            protocol_target: format!(
                "mcp://{}/{}",
                worker
                    .route_target
                    .trim_start_matches("http://")
                    .trim_start_matches("https://")
                    .trim_end_matches('/'),
                worker.server_id
            ),
            egress_contract_id: format!("mcp:egress-{}", short(&worker.task_id)),
            egress_constraints: vec!["deny-private-network".to_string()],
            attenuation_decision: "accepted".to_string(),
            policy_digest: sha256_hex(b"reference-swarm-route-policy"),
            expires_at_unix_ms: now + VALIDITY_MS,
            issuer: issuer.clone(),
            signature: String::new(),
        };
        route.signature = sign_swarm_route_plan_receipt(&route, &keypair)?;

        let mut token = SwarmContinuationToken {
            schema: CHIO_SWARM_CONTINUATION_TOKEN_SCHEMA.to_string(),
            token_id: format!("continuation-{}", short(&worker.task_id)),
            graph_id: graph_id.clone(),
            child_task_id: worker.task_id.clone(),
            parent_task_id: Some(ROOT_TASK.to_string()),
            join_receipt_id: None,
            parent_receipt_ids: vec![format!("receipt-{}", short(ROOT_TASK))],
            graph_sha256: graph_sha256.clone(),
            route_plan_receipt_id: route.route_plan_id.clone(),
            budget_allocation_id: format!("budget-{}", short(&worker.task_id)),
            witness_chain_ref: Some(chain.chain_id.clone()),
            witness_chain_sha256: Some(canonical_hash(&chain)?),
            revocation_epoch_ref: epoch_id.clone(),
            revocation_epoch_root_hash: epoch_root.clone(),
            session_anchor_ref: format!("session-anchor-{run_id}"),
            nonce: format!("nonce-{run_id}-{}", short(&worker.task_id)),
            mode: SwarmContinuationMode::SingleUse,
            issued_at_unix_ms: now,
            expires_at_unix_ms: now + VALIDITY_MS,
            issuer: issuer.clone(),
            signature: String::new(),
        };
        token.signature = sign_swarm_continuation_token(&token, &keypair)?;

        allocations.push(SwarmBudgetAllocation {
            allocation_id: format!("budget-{}", short(&worker.task_id)),
            task_id: worker.task_id.clone(),
            dimension_id: DIMENSION.to_string(),
            state: SwarmBudgetAllocationState::Active,
            max_units: CALLS_PER_WORKER,
            reserved_units: 0,
            active_units: CALLS_PER_WORKER,
            consumed_units: 0,
            released_units: 0,
            reversed_units: 0,
        });
        witness_chains.push(chain);
        continuation_tokens.push(token);
        route_plan_receipts.push(route);
    }

    let receipt_ids: Vec<String> = workers
        .iter()
        .map(|worker| format!("receipt-{}", short(&worker.task_id)))
        .collect();
    let mut sorted_receipt_ids = receipt_ids.clone();
    sorted_receipt_ids.sort_unstable();
    let mut join = SwarmJoinReceipt {
        schema: CHIO_SWARM_JOIN_RECEIPT_SCHEMA.to_string(),
        join_id: format!("join-{run_id}"),
        graph_id: graph_id.clone(),
        chain_id: chain_id.clone(),
        parent_set_hash: canonical_hash(
            &serde_json::json!({ "chainId": chain_id, "parentReceiptIds": sorted_receipt_ids }),
        )?,
        dag_ordinal: u64::try_from(workers.len()).unwrap_or(u64::MAX),
        hlc_unix_ms: now,
        parent_task_receipts: workers
            .iter()
            .zip(&receipt_ids)
            .map(|(worker, receipt_id)| SwarmJoinParentReceipt {
                task_id: worker.task_id.clone(),
                receipt_id: receipt_id.clone(),
            })
            .collect(),
        expected_parent_receipt_ids: receipt_ids.clone(),
        actual_parent_receipt_ids: receipt_ids.clone(),
        join_predicate: "all_success".to_string(),
        result_digest: sha256_hex(b"pending"),
        next_task_id: ROOT_TASK.to_string(),
        issuer: issuer.clone(),
        signature: String::new(),
    };
    join.signature = sign_swarm_join_receipt(&join, &keypair)?;

    let mut epoch = SwarmRevocationEpoch {
        schema: CHIO_SWARM_REVOCATION_EPOCH_SCHEMA.to_string(),
        epoch_id: epoch_id.clone(),
        root_hash: epoch_root,
        issued_at_unix_ms: now,
        valid_until_unix_ms: now + VALIDITY_MS,
        revoked_subjects: Vec::new(),
        revoked_task_ids: Vec::new(),
        issuer: issuer.clone(),
        signature: String::new(),
    };
    epoch.signature = sign_swarm_revocation_epoch(&epoch, &keypair)?;

    let total_units =
        CALLS_PER_WORKER.saturating_mul(u64::try_from(workers.len()).unwrap_or(u64::MAX));
    let bundle = SwarmAuthorityBundle {
        task_graph,
        continuation_tokens,
        witness_chains,
        join_receipts: vec![join],
        route_plan_receipts,
        budget_pool: SwarmBudgetPool {
            schema: CHIO_SWARM_BUDGET_POOL_SCHEMA.to_string(),
            pool_id: pool_id.clone(),
            graph_id: graph_id.clone(),
            currency: DIMENSION.to_string(),
            total_units,
            allocations,
        },
        revocation_epoch: epoch,
        terminal_receipts: Vec::new(),
        now_unix_ms: now,
    };
    let planned_tasks: Vec<String> = workers
        .iter()
        .map(|worker| worker.task_id.clone())
        .collect();
    let pending = sign_terminal_receipt(
        &keypair,
        run_id,
        &bundle,
        &planned_tasks,
        &sha256_hex(b"pending"),
    )?;
    let mut bundle = bundle;
    bundle.terminal_receipts = vec![pending];
    Ok(SwarmPlan {
        run_id: run_id.to_string(),
        bundle,
        keypair,
        parent_scope,
    })
}

/// The terminal receipt over the bundle's graph, joins and pool as they
/// stand, with one budget rollup per dimension summed from the allocations.
fn sign_terminal_receipt(
    keypair: &Keypair,
    run_id: &str,
    bundle: &SwarmAuthorityBundle,
    completed_task_ids: &[String],
    result_digest: &str,
) -> Fallible<SwarmTerminalGraphReceipt> {
    let mut rollups: BTreeMap<String, SwarmTerminalBudgetRollup> = BTreeMap::new();
    for allocation in &bundle.budget_pool.allocations {
        let rollup = rollups
            .entry(allocation.dimension_id.clone())
            .or_insert_with(|| SwarmTerminalBudgetRollup {
                dimension_id: allocation.dimension_id.clone(),
                reserved_units: 0,
                active_units: 0,
                consumed_units: 0,
                released_units: 0,
                reversed_units: 0,
                total_units: 0,
            });
        rollup.reserved_units = rollup
            .reserved_units
            .saturating_add(allocation.reserved_units);
        rollup.active_units = rollup.active_units.saturating_add(allocation.active_units);
        rollup.consumed_units = rollup
            .consumed_units
            .saturating_add(allocation.consumed_units);
        rollup.released_units = rollup
            .released_units
            .saturating_add(allocation.released_units);
        rollup.reversed_units = rollup
            .reversed_units
            .saturating_add(allocation.reversed_units);
        rollup.total_units = [
            allocation.reserved_units,
            allocation.active_units,
            allocation.consumed_units,
            allocation.released_units,
            allocation.reversed_units,
        ]
        .iter()
        .fold(rollup.total_units, |total, units| {
            total.saturating_add(*units)
        });
    }
    let graph = &bundle.task_graph;
    let mut receipt = SwarmTerminalGraphReceipt {
        schema: CHIO_SWARM_TERMINAL_GRAPH_RECEIPT_SCHEMA.to_string(),
        receipt_id: format!("terminal-{run_id}"),
        graph_id: graph.graph_id.clone(),
        chain_id: format!("swarm-chain-{run_id}"),
        terminal_task_ids: vec![ROOT_TASK.to_string()],
        completed_task_ids: std::iter::once(ROOT_TASK.to_string())
            .chain(completed_task_ids.iter().cloned())
            .collect(),
        join_receipt_ids: bundle
            .join_receipts
            .iter()
            .map(|join| join.join_id.clone())
            .collect(),
        route_plan_receipt_ids: graph.route_plan_refs.clone(),
        budget_pool_id: bundle.budget_pool.pool_id.clone(),
        budget_rollups: rollups.into_values().collect(),
        revocation_epoch_ref: graph.revocation_epoch_ref.clone(),
        result_digest: result_digest.to_string(),
        completed_at_unix_ms: now_unix_ms(),
        issuer: graph.issuer.clone(),
        signature: String::new(),
    };
    receipt.signature = sign_swarm_terminal_graph_receipt(&receipt, keypair)?;
    Ok(receipt)
}

impl SwarmPlan {
    pub fn trusted_keys(&self) -> Vec<PublicKey> {
        vec![self.keypair.public_key()]
    }

    /// Verify the bundle as the runtime admission path would.
    pub fn verify(&self) -> Result<SwarmAuthorityVerifierReport, SwarmAuthorityError> {
        let mut bundle = self.bundle.clone();
        bundle.now_unix_ms = now_unix_ms();
        verify_swarm_authority_bundle(&bundle, &self.trusted_keys())
    }

    /// A worker scope that adds a tool the orchestrator never held has no
    /// attenuation witness, so no delegation hop can carry it.
    pub fn widening_is_refused(&self, server_id: &str, tool: &str) -> bool {
        let mut wider = self.parent_scope.clone();
        wider.grants.push(grant(server_id, tool));
        compute_attenuation_witness(&self.parent_scope, &wider).is_err()
    }

    /// Reserving more units for the workers than the pool holds is refused
    /// before any worker runs.
    pub fn oversubscription_is_refused(&self) -> bool {
        let pool = &self.bundle.budget_pool;
        let request = SwarmBudgetFanoutReservationRequest {
            pool_id: pool.pool_id.clone(),
            graph_id: pool.graph_id.clone(),
            currency: pool.currency.clone(),
            total_units: pool.total_units,
            allocations: pool
                .allocations
                .iter()
                .map(|allocation| SwarmBudgetFanoutAllocationRequest {
                    allocation_id: allocation.allocation_id.clone(),
                    task_id: allocation.task_id.clone(),
                    dimension_id: allocation.dimension_id.clone(),
                    reserved_units: pool.total_units,
                })
                .collect(),
        };
        reserve_swarm_budget_fanout(request).is_err()
    }

    /// Revoke one worker's task in the epoch and re-sign what binds to it.
    pub fn revoke_task(&mut self, task_id: &str) -> Fallible<()> {
        let epoch = &mut self.bundle.revocation_epoch;
        if !epoch
            .revoked_task_ids
            .iter()
            .any(|revoked| revoked == task_id)
        {
            epoch.revoked_task_ids.push(task_id.to_string());
        }
        let root_hash =
            revocation_epoch_root_hash(&epoch.revoked_subjects, &epoch.revoked_task_ids)?;
        epoch.root_hash = root_hash.clone();
        epoch.signature = sign_swarm_revocation_epoch(epoch, &self.keypair)?;
        for token in &mut self.bundle.continuation_tokens {
            token.revocation_epoch_root_hash = root_hash.clone();
            token.signature = sign_swarm_continuation_token(token, &self.keypair)?;
        }
        Ok(())
    }

    /// Close the run: release the pool for the completed workers and sign
    /// the terminal receipt over the result digest.
    pub fn complete(&mut self, completed_task_ids: &[String], result_digest: &str) -> Fallible<()> {
        let released = release_swarm_budget_fanin(SwarmBudgetFanInReleaseRequest {
            pool: self.bundle.budget_pool.clone(),
            completed_task_ids: completed_task_ids.to_vec(),
        })?;
        self.bundle.budget_pool = released;
        let receipt = sign_terminal_receipt(
            &self.keypair,
            &self.run_id,
            &self.bundle,
            completed_task_ids,
            result_digest,
        )?;
        self.bundle.terminal_receipts = vec![receipt];
        Ok(())
    }
}
