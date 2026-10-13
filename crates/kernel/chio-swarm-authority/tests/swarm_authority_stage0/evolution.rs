use super::*;
use chio_swarm_authority::{
    verify_swarm_authority_extension, verify_swarm_authority_for_admission, SwarmAuthorityError,
    SwarmAuthorityVerifierReport, MAX_SWARM_GRAPH_EDGES, MAX_SWARM_GRAPH_JOINS,
    MAX_SWARM_GRAPH_TASKS,
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

fn assert_rejected(
    result: Result<SwarmAuthorityVerifierReport, SwarmAuthorityError>,
    expected: &str,
) {
    match result {
        Err(SwarmAuthorityError::Rejected(detail)) => assert_eq!(detail, expected),
        other => panic!("expected rejection {expected:?}, got {other:?}"),
    }
}

fn versions_with_join() -> Result<(SwarmAuthorityBundle, SwarmAuthorityBundle), Box<dyn Error>> {
    let mut prior = sample_swarm_bundle()?;
    prior.terminal_receipts.clear();
    let mut next = prior.clone();
    let mut task = next.task_graph.nodes[1].clone();
    task.task_id = "task-grandchild".into();
    task.parent_task_id = Some("task-child-a".into());
    task.route_plan_ref = Some("route-grandchild".into());
    task.continuation_token_ref = Some("continuation-grandchild".into());
    task.budget_allocation_ref = Some("budget-grandchild".into());
    task.depth = 2;
    next.task_graph.nodes.push(task);
    next.task_graph.edges.push(SwarmGraphEdge {
        from_task_id: "task-child-a".into(),
        to_task_id: "task-grandchild".into(),
        edge_type: "delegates".into(),
    });
    next.task_graph
        .route_plan_refs
        .push("route-grandchild".into());
    next.route_plan_receipts.push(route_plan_receipt(
        "route-grandchild",
        "task-grandchild",
        "mcp",
        "mcp://grandchild",
    )?);
    let mut allocation = next.budget_pool.allocations[0].clone();
    allocation.allocation_id = "budget-grandchild".into();
    allocation.task_id = "task-grandchild".into();
    next.budget_pool.allocations.push(allocation);
    let scope = scope_for("commerce", "reserve_budget", 1);
    let digest = scope_hash(&scope)?;
    next.witness_chains.push(witness_chain(
        "witness-grandchild",
        "task-child-a",
        "task-grandchild",
        &digest,
        &digest,
        compute_attenuation_witness(&scope, &scope)?,
    )?);
    let mut token = next.continuation_tokens[0].clone();
    token.token_id = "continuation-grandchild".into();
    token.child_task_id = "task-grandchild".into();
    token.parent_task_id = Some("task-child-a".into());
    token.parent_receipt_ids = vec!["receipt-child-a".into()];
    token.route_plan_receipt_id = "route-grandchild".into();
    token.budget_allocation_id = "budget-grandchild".into();
    token.nonce = "nonce-grandchild".into();
    next.continuation_tokens.push(token);
    refresh_continuation_graph_digests(&mut next)?;
    Ok((prior, next))
}

#[test]
fn extension_preserves_an_issued_join_and_receipt() -> Result<(), Box<dyn Error>> {
    let (prior, next) = versions_with_join()?;
    verify_swarm_authority_for_admission(&prior, &trusted_witness_keys())?;
    verify_swarm_authority_for_admission(&next, &trusted_witness_keys())?;
    let report =
        verify_swarm_authority_extension(&prior, &next, &trusted_witness_keys(), NOW_UNIX_MS)?;
    assert_eq!(report.task_count, 4);
    assert_eq!(report.join_count, 1);
    assert!(report
        .verified_claims
        .contains(&CLAIM_SWARM_JOIN_RECEIPT_BOUND.into()));
    Ok(())
}

#[test]
fn extension_rejects_individually_valid_join_rewrites() -> Result<(), Box<dyn Error>> {
    for (mutation, expected) in [
        (
            "definition",
            "issued join definition was removed or changed",
        ),
        (
            "remove_definition",
            "issued join definition was removed or changed",
        ),
        ("receipt", "issued join receipt was removed or changed"),
        (
            "remove_receipt",
            "issued join receipt was removed or changed",
        ),
    ] {
        let (prior, mut next) = versions_with_join()?;
        match mutation {
            "definition" => {
                next.task_graph.joins[0].parent_task_ids.reverse();
                next.join_receipts[0].expected_parent_receipt_ids.reverse();
                sign_join_receipt(&mut next.join_receipts[0])?;
            }
            "remove_definition" => {
                next.task_graph.joins.clear();
                next.join_receipts.clear();
            }
            "receipt" => {
                next.join_receipts[0].result_digest = sha256_hex(b"different-join-result");
                sign_join_receipt(&mut next.join_receipts[0])?;
            }
            "remove_receipt" => next.join_receipts.clear(),
            _ => unreachable!(),
        }
        refresh_continuation_graph_digests(&mut next)?;
        verify_swarm_authority_for_admission(&prior, &trusted_witness_keys())?;
        verify_swarm_authority_for_admission(&next, &trusted_witness_keys())?;
        assert_rejected(
            verify_swarm_authority_extension(&prior, &next, &trusted_witness_keys(), NOW_UNIX_MS),
            &format!("swarm extension rejected: {expected}"),
        );
    }
    Ok(())
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
    assert_eq!(prior.task_graph.nodes.len(), 2);
    assert_eq!(next.task_graph.nodes.len(), 3);
    Ok(())
}

#[test]
fn extension_rejects_individually_valid_rewrites() -> Result<(), Box<dyn Error>> {
    for (mutation, expected) in [
        ("allocation", "issued allocation was removed or changed"),
        ("accounting", "issued allocation was removed or changed"),
        ("task", "issued task was removed or changed"),
        ("edge", "issued edge was removed or changed"),
        ("pool", "original pool envelope changed"),
        ("nonce", "issued continuation changed"),
        ("continuation_expiry", "issued continuation changed"),
        ("session", "issued continuation changed"),
        ("parent_receipt", "issued continuation changed"),
        ("expiry", "original graph envelope changed"),
        ("route", "issued route was removed or changed"),
        ("witness", "issued witness was removed or changed"),
        ("epoch", "revocation epoch changed"),
        ("planner", "original graph envelope changed"),
    ] {
        let (prior, mut next) = versions()?;
        match mutation {
            "allocation" => {
                next.budget_pool.allocations[0].max_units = 1_000;
                next.budget_pool.allocations[0].active_units = 1_000;
            }
            "accounting" => {
                next.budget_pool.allocations[0].active_units = 2_000;
                next.budget_pool.allocations[0].consumed_units = 500;
            }
            "task" => {
                next.task_graph.nodes[0].budget_allocation_ref = Some("budget-child-a".into())
            }
            "edge" => next.task_graph.edges[0].edge_type = "depends_on".into(),
            "pool" => next.budget_pool.total_units += 1,
            "nonce" => next.continuation_tokens[0].nonce = "fresh-attempt".into(),
            "continuation_expiry" => next.continuation_tokens[0].expires_at_unix_ms -= 1,
            "session" => next.continuation_tokens[0].session_anchor_ref = "other-session".into(),
            "parent_receipt" => {
                next.continuation_tokens[0].parent_receipt_ids = vec!["other-receipt".into()]
            }
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
        verify_swarm_authority_for_admission(&prior, &trusted_witness_keys())?;
        verify_swarm_authority_for_admission(&next, &trusted_witness_keys())?;
        assert_rejected(
            verify_swarm_authority_extension(&prior, &next, &trusted_witness_keys(), NOW_UNIX_MS),
            &format!("swarm extension rejected: {expected}"),
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
    assert_eq!(prior.now_unix_ms, 0);
    assert_eq!(next.now_unix_ms, u64::MAX);
    assert_rejected(
        verify_swarm_authority_extension(
            &prior,
            &next,
            &trusted_witness_keys(),
            NOW_UNIX_MS + 61_000,
        ),
        "swarm task graph is expired",
    );
    assert_rejected(
        verify_swarm_authority_extension(
            &prior,
            &next,
            &[Keypair::generate().public_key()],
            NOW_UNIX_MS,
        ),
        "swarm task graph issuer is not trusted: swarm-graph-proof-valid",
    );
    Ok(())
}

#[test]
fn extension_cannot_reset_or_reallocate_an_existing_task() -> Result<(), Box<dyn Error>> {
    for (mutation, expected) in [
        (
            "token",
            "each task and allocation require one stable single-use continuation",
        ),
        (
            "allocation",
            "an issued task cannot receive another allocation",
        ),
        (
            "root_allocation",
            "an issued task cannot receive another allocation",
        ),
        (
            "resumable",
            "each task and allocation require one stable single-use continuation",
        ),
    ] {
        let (prior, mut next) = versions()?;
        match mutation {
            "token" => {
                let mut extra = next.continuation_tokens[0].clone();
                extra.token_id = "another-attempt".into();
                extra.nonce = "another-nonce".into();
                next.continuation_tokens.push(extra);
            }
            "allocation" | "root_allocation" => {
                let mut extra = next.budget_pool.allocations[0].clone();
                extra.allocation_id = "another-allocation".into();
                if mutation == "root_allocation" {
                    extra.task_id = "task-root".into();
                    assert!(prior
                        .budget_pool
                        .allocations
                        .iter()
                        .all(|a| a.task_id != "task-root"));
                }
                next.budget_pool.allocations.push(extra);
            }
            "resumable" => next.continuation_tokens[1].mode = SwarmContinuationMode::Resumable,
            _ => unreachable!(),
        }
        refresh_continuation_graph_digests(&mut next)?;
        verify_swarm_authority_for_admission(&prior, &trusted_witness_keys())?;
        verify_swarm_authority_for_admission(&next, &trusted_witness_keys())?;
        assert_rejected(
            verify_swarm_authority_extension(&prior, &next, &trusted_witness_keys(), NOW_UNIX_MS),
            &format!("swarm extension rejected: {expected}"),
        );
    }
    Ok(())
}

#[test]
fn extension_rejects_no_growth_and_budget_overflow() -> Result<(), Box<dyn Error>> {
    let (prior, mut next) = versions()?;
    assert_rejected(
        verify_swarm_authority_extension(&prior, &prior, &trusted_witness_keys(), NOW_UNIX_MS),
        "swarm extension rejected: extension must add a task",
    );
    next.budget_pool.allocations[1].max_units = 9_000;
    next.budget_pool.allocations[1].active_units = 9_000;
    assert_rejected(
        verify_swarm_authority_extension(&prior, &next, &trusted_witness_keys(), NOW_UNIX_MS),
        "swarm budget allocations exceed pool total",
    );
    Ok(())
}

#[test]
fn extension_rejects_either_completed_snapshot() -> Result<(), Box<dyn Error>> {
    for completed_prior in [false, true] {
        let (mut prior, mut next) = versions()?;
        let completed = sample_swarm_bundle()?;
        verify_swarm_authority_bundle(&completed, &trusted_witness_keys())?;
        if completed_prior {
            prior = completed;
        } else {
            next = completed;
        }
        verify_swarm_authority_for_admission(&prior, &trusted_witness_keys())?;
        verify_swarm_authority_for_admission(&next, &trusted_witness_keys())?;
        assert_rejected(
            verify_swarm_authority_extension(&prior, &next, &trusted_witness_keys(), NOW_UNIX_MS),
            "swarm extension rejected: terminal graph cannot participate in a live extension",
        );
    }
    Ok(())
}

fn exceed_ceiling(bundle: &mut SwarmAuthorityBundle, kind: &str, join: &SwarmGraphJoin) {
    match kind {
        "task" => bundle.task_graph.nodes.resize(
            MAX_SWARM_GRAPH_TASKS + 1,
            bundle.task_graph.nodes[0].clone(),
        ),
        "edge" => bundle.task_graph.edges.resize(
            MAX_SWARM_GRAPH_EDGES + 1,
            bundle.task_graph.edges[0].clone(),
        ),
        "join" => bundle
            .task_graph
            .joins
            .resize(MAX_SWARM_GRAPH_JOINS + 1, join.clone()),
        _ => unreachable!(),
    }
}

#[test]
fn extension_rejects_one_over_each_ceiling_in_either_snapshot() -> Result<(), Box<dyn Error>> {
    for previous in [false, true] {
        for (kind, expected) in [
            ("task", "swarm task graph exceeds its task ceiling"),
            ("edge", "swarm task graph exceeds its edge ceiling"),
            ("join", "swarm task graph exceeds its join ceiling"),
        ] {
            let (mut prior, mut next) = versions()?;
            let join = next.task_graph.joins[0].clone();
            exceed_ceiling(if previous { &mut prior } else { &mut next }, kind, &join);
            assert_rejected(
                verify_swarm_authority_extension(
                    &prior,
                    &next,
                    &trusted_witness_keys(),
                    NOW_UNIX_MS,
                ),
                expected,
            );
        }
    }
    Ok(())
}

#[test]
fn extension_preflights_candidate_ceilings_before_prior_authentication(
) -> Result<(), Box<dyn Error>> {
    for (kind, expected) in [
        ("task", "swarm task graph exceeds its task ceiling"),
        ("edge", "swarm task graph exceeds its edge ceiling"),
        ("join", "swarm task graph exceeds its join ceiling"),
    ] {
        let (mut prior, mut next) = versions()?;
        prior.task_graph.signature = "00".repeat(64);
        let join = next.task_graph.joins[0].clone();
        exceed_ceiling(&mut next, kind, &join);
        assert_rejected(
            verify_swarm_authority_extension(&prior, &next, &trusted_witness_keys(), NOW_UNIX_MS),
            expected,
        );
    }
    Ok(())
}
