use super::*;
use chio_swarm_authority::{
    verify_swarm_authority_extension, verify_swarm_authority_for_admission,
};

fn versions() -> Result<(SwarmAuthorityBundle, SwarmAuthorityBundle), Box<dyn Error>> {
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

#[test]
fn extension_adds_live_work_with_original_authority() -> Result<(), Box<dyn Error>> {
    let (prior, next) = versions()?;
    let keys = trusted_witness_keys();
    verify_swarm_authority_for_admission(&prior, &keys)?;
    verify_swarm_authority_for_admission(&next, &keys)?;
    let report = verify_swarm_authority_extension(&prior, &next, &keys, NOW_UNIX_MS)?;
    assert_eq!(report.task_count, 3);
    assert_eq!(report.continuation_count, 2);
    assert!(!report
        .verified_claims
        .contains(&CLAIM_SWARM_TERMINAL_GRAPH_RECEIPT_BOUND.into()));
    Ok(())
}

// These changes are individually valid authority bundles. Only their relationship
// to the previous version reveals the erased or widened commitment.
#[test]
fn extension_rejects_individually_valid_rewrites() -> Result<(), Box<dyn Error>> {
    for mutation in [
        "allocation",
        "pool",
        "nonce",
        "expiry",
        "route",
        "witness",
        "epoch",
        "planner",
    ] {
        let (prior, mut next) = versions()?;
        match mutation {
            "allocation" => {
                next.budget_pool.allocations[0].max_units = 1_000;
                next.budget_pool.allocations[0].active_units = 1_000;
            }
            "pool" => next.budget_pool.total_units += 1,
            "nonce" => next.continuation_tokens[0].nonce = "fresh-attempt".into(),
            "expiry" => next.task_graph.expires_at_unix_ms += 1,
            "route" => {
                next.route_plan_receipts[0].protocol_target = "mcp://replacement".into();
                sign_route_plan_receipt(&mut next.route_plan_receipts[0])?;
            }
            "witness" => {
                next.witness_chains[0].hops[0].child_capability_digest = sha256_hex(b"replacement");
                sign_witness_chain(&mut next.witness_chains[0])?;
            }
            "epoch" => {
                next.revocation_epoch.valid_until_unix_ms += 1;
                sign_revocation_epoch(&mut next.revocation_epoch)?;
            }
            "planner" => next.task_graph.planner_subject = "did:chio:replacement".into(),
            _ => unreachable!(),
        }
        refresh_continuation_graph_digests(&mut next)?;
        verify_swarm_authority_for_admission(&next, &trusted_witness_keys())?;
        assert!(
            verify_swarm_authority_extension(&prior, &next, &trusted_witness_keys(), NOW_UNIX_MS)
                .is_err(),
            "accepted rewrite: {mutation}"
        );
    }
    Ok(())
}

#[test]
fn extension_uses_local_time_and_trusted_keys() -> Result<(), Box<dyn Error>> {
    let (mut prior, mut next) = versions()?;
    prior.now_unix_ms = 0;
    next.now_unix_ms = u64::MAX;
    verify_swarm_authority_extension(&prior, &next, &trusted_witness_keys(), NOW_UNIX_MS)?;
    assert!(verify_swarm_authority_extension(
        &prior,
        &next,
        &trusted_witness_keys(),
        NOW_UNIX_MS + 61_000
    )
    .is_err());
    assert!(verify_swarm_authority_extension(
        &prior,
        &next,
        &[Keypair::generate().public_key()],
        NOW_UNIX_MS
    )
    .is_err());
    Ok(())
}

#[test]
fn extension_cannot_reset_or_reallocate_an_existing_task() -> Result<(), Box<dyn Error>> {
    for mutation in ["token", "allocation", "resumable"] {
        let (prior, mut next) = versions()?;
        match mutation {
            "token" => {
                let mut extra = next.continuation_tokens[0].clone();
                extra.token_id = "another-attempt".into();
                extra.nonce = "another-nonce".into();
                next.continuation_tokens.push(extra);
            }
            "allocation" => {
                let mut extra = next.budget_pool.allocations[0].clone();
                extra.allocation_id = "another-allocation".into();
                next.budget_pool.allocations.push(extra);
            }
            "resumable" => next.continuation_tokens[1].mode = SwarmContinuationMode::Resumable,
            _ => unreachable!(),
        }
        refresh_continuation_graph_digests(&mut next)?;
        assert!(
            verify_swarm_authority_extension(&prior, &next, &trusted_witness_keys(), NOW_UNIX_MS)
                .is_err(),
            "accepted {mutation}"
        );
    }
    Ok(())
}

#[test]
fn extension_rejects_no_growth_and_budget_overflow() -> Result<(), Box<dyn Error>> {
    let (prior, mut next) = versions()?;
    assert!(
        verify_swarm_authority_extension(&prior, &prior, &trusted_witness_keys(), NOW_UNIX_MS)
            .is_err()
    );
    next.budget_pool.allocations[1].max_units = 9_000;
    next.budget_pool.allocations[1].active_units = 9_000;
    assert!(
        verify_swarm_authority_extension(&prior, &next, &trusted_witness_keys(), NOW_UNIX_MS)
            .is_err()
    );
    Ok(())
}
