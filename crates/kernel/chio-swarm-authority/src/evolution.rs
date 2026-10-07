//! Additive evolution of already issued swarm authority. Old allocations and
//! continuation identities are commitments, including when outcomes are unknown.

use std::collections::BTreeSet;

use chio_core_types::PublicKey;

use crate::{
    verify_swarm_authority_for_admission, SwarmAuthorityBundle, SwarmAuthorityError,
    SwarmAuthorityVerifierReport, SwarmContinuationMode,
};

/// Check a strict extension within the original graph's authority envelope.
///
/// Both snapshots undergo the ordinary signature, attenuation, route, freshness,
/// and budget checks at caller-owned time. The caller must atomically compare
/// and advance its protected head; this pure check does not prevent two writers
/// from independently proposing successors against the same remaining capacity.
///
/// Previous work remains authorized under its original evidence, subject to
/// normal runtime checks. This API neither retires work nor reclaims allocations.
/// Budget conservation concerns declared units, not proof of deposited funds.
pub fn verify_swarm_authority_extension(
    previous: &SwarmAuthorityBundle,
    candidate: &SwarmAuthorityBundle,
    trusted_keys: &[PublicKey],
    now_unix_ms: u64,
) -> Result<SwarmAuthorityVerifierReport, SwarmAuthorityError> {
    let mut previous = previous.clone();
    let mut candidate = candidate.clone();
    previous.now_unix_ms = now_unix_ms;
    candidate.now_unix_ms = now_unix_ms;
    verify_swarm_authority_for_admission(&previous, trusted_keys)?;
    let report = verify_swarm_authority_for_admission(&candidate, trusted_keys)?;

    if !previous.terminal_receipts.is_empty() || !candidate.terminal_receipts.is_empty() {
        return reject("terminal graph cannot participate in a live extension");
    }
    if candidate.task_graph.nodes.len() <= previous.task_graph.nodes.len() {
        return reject("extension must add a task");
    }

    let old = &previous.task_graph;
    let new = &candidate.task_graph;
    // Compare the entire envelope, excluding only the explicitly extensible
    // collections and the signature over those changed collections.
    let mut envelope = new.clone();
    envelope.nodes.clone_from(&old.nodes);
    envelope.edges.clone_from(&old.edges);
    envelope.joins.clone_from(&old.joins);
    envelope.route_plan_refs.clone_from(&old.route_plan_refs);
    envelope.signature.clone_from(&old.signature);
    if &envelope != old {
        return reject("original graph envelope changed");
    }
    retained(&old.nodes, &new.nodes, "task")?;
    retained(&old.edges, &new.edges, "edge")?;
    retained(&old.joins, &new.joins, "join definition")?;
    retained(
        &old.route_plan_refs,
        &new.route_plan_refs,
        "route reference",
    )?;
    retained(
        &previous.witness_chains,
        &candidate.witness_chains,
        "witness",
    )?;
    retained(
        &previous.route_plan_receipts,
        &candidate.route_plan_receipts,
        "route",
    )?;
    retained(
        &previous.join_receipts,
        &candidate.join_receipts,
        "join receipt",
    )?;
    if previous.revocation_epoch != candidate.revocation_epoch {
        return reject("revocation epoch changed");
    }

    let mut pool = candidate.budget_pool.clone();
    pool.allocations
        .clone_from(&previous.budget_pool.allocations);
    if pool != previous.budget_pool {
        return reject("original pool envelope changed");
    }
    retained(
        &previous.budget_pool.allocations,
        &candidate.budget_pool.allocations,
        "allocation",
    )?;

    for token in &previous.continuation_tokens {
        let Some(next) = candidate
            .continuation_tokens
            .iter()
            .find(|t| t.token_id == token.token_id)
        else {
            return reject("issued continuation was removed");
        };
        let mut identity = next.clone();
        identity.graph_sha256.clone_from(&token.graph_sha256);
        identity.signature.clone_from(&token.signature);
        if &identity != token {
            return reject("issued continuation changed");
        }
    }
    let old_tasks: BTreeSet<_> = old.nodes.iter().map(|n| &n.task_id).collect();
    let old_allocations: BTreeSet<_> = previous
        .budget_pool
        .allocations
        .iter()
        .map(|a| &a.allocation_id)
        .collect();
    let old_tokens: BTreeSet<_> = previous
        .continuation_tokens
        .iter()
        .map(|t| &t.token_id)
        .collect();
    let mut allocated_tasks = BTreeSet::new();
    for allocation in &candidate.budget_pool.allocations {
        if !allocated_tasks.insert(&allocation.task_id)
            || (!old_allocations.contains(&allocation.allocation_id)
                && old_tasks.contains(&allocation.task_id))
        {
            return reject("an issued task cannot receive another allocation");
        }
    }
    let mut continued_tasks = BTreeSet::new();
    let mut continued_allocations = BTreeSet::new();
    for token in &candidate.continuation_tokens {
        if token.mode != SwarmContinuationMode::SingleUse
            || !continued_tasks.insert(&token.child_task_id)
            || !continued_allocations.insert(&token.budget_allocation_id)
            || (!old_tokens.contains(&token.token_id) && old_tasks.contains(&token.child_task_id))
        {
            return reject("each task and allocation require one stable single-use continuation");
        }
    }
    Ok(report)
}

fn retained<T: PartialEq>(old: &[T], new: &[T], name: &str) -> Result<(), SwarmAuthorityError> {
    if old.iter().any(|item| !new.contains(item)) {
        return reject(&format!("issued {name} was removed or changed"));
    }
    Ok(())
}

fn reject<T>(detail: &str) -> Result<T, SwarmAuthorityError> {
    Err(SwarmAuthorityError::Rejected(format!(
        "swarm extension rejected: {detail}"
    )))
}
