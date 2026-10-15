use super::*;
use std::sync::{Arc, Barrier};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const NOW: u64 = 1_800_000_001_000;

pub(super) fn versions() -> TestResult<(SwarmAuthorityBundle, SwarmAuthorityBundle)> {
    versions_with_headroom(true)
}

pub(super) fn treaty_versions() -> TestResult<(SwarmAuthorityBundle, SwarmAuthorityBundle)> {
    versions_with_headroom(false)
}

fn versions_with_headroom(
    headroom: bool,
) -> TestResult<(SwarmAuthorityBundle, SwarmAuthorityBundle)> {
    let mut next = runtime_swarm_bundle(false)?;
    // Leave headroom in the native capability so the rebound-continuation test
    // cannot pass merely because a one-invocation capability is exhausted.
    if headroom {
        let scope = runtime_swarm_scope(2);
        next.task_graph.nodes[1].scope_hash = scope_hash(&scope)?;
        let chain = &mut next.witness_chains[0];
        chain.hops[0].child_scope_hash = scope_hash(&scope)?;
        chain.hops[0].child_capability_digest = canonical_test_hash(&capability("task-child-a")?)?;
        chain.hops[0].scope_subset_proof =
            compute_attenuation_witness(&runtime_swarm_scope(3), &scope)?;
        chain.hops[0].witness_signature =
            sign_swarm_delegation_witness_hop(chain, &chain.hops[0], &swarm_witness_keypair())?;
    }
    next.join_receipts.clear();
    next.terminal_receipts.clear();
    resign_graph(&mut next)?;
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
    resign_graph(&mut prior)?;
    Ok((prior, next))
}

pub(super) fn capability(task: &str) -> TestResult<CapabilityToken> {
    let old = swarm_fixtures::runtime_swarm_capability(task)?;
    if task != "task-child-a" {
        return Ok(old);
    }
    Ok(CapabilityToken::sign(
        CapabilityTokenBody {
            id: old.id,
            issuer: old.issuer,
            subject: old.subject,
            scope: runtime_swarm_scope(2),
            issued_at: old.issued_at,
            expires_at: old.expires_at,
            delegation_chain: old.delegation_chain,
            aggregate_invocation_budget: None,
        },
        &swarm_witness_keypair(),
    )?)
}

fn resign_graph(bundle: &mut SwarmAuthorityBundle) -> TestResult {
    bundle.task_graph.signature =
        sign_swarm_task_graph(&bundle.task_graph, &swarm_witness_keypair())?;
    for token in &mut bundle.continuation_tokens {
        token.graph_sha256 = canonical_test_hash(&bundle.task_graph)?;
        if let Some(id) = &token.witness_chain_ref {
            let chain = bundle
                .witness_chains
                .iter()
                .find(|c| &c.chain_id == id)
                .ok_or("witness")?;
            token.witness_chain_sha256 = Some(canonical_test_hash(chain)?);
        }
        token.signature = sign_swarm_continuation_token(token, &swarm_witness_keypair())?;
    }
    Ok(())
}

pub(super) fn open(path: &std::path::Path) -> TestResult<SqliteRuntimeOrchestrationStore> {
    Ok(SqliteRuntimeOrchestrationStore::open_with_clock(
        path,
        chio_test_support::clock::clock(),
    )?)
}

#[test]
fn swarm_evolution_retains_exact_versions_after_reopen() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(NOW / 1000);
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("runtime.db");
    let (prior, next) = versions()?;
    let store = open(&path)?;
    store.insert_swarm_authority_bundle(prior.clone())?;
    store.extend_swarm_authority_bundle(
        &canonical_test_hash(&prior)?,
        next.clone(),
        &trusted_swarm_witness_keys(),
    )?;
    drop(store);
    let reopened = open(&path)?;
    let id = &prior.task_graph.graph_id;
    assert_eq!(reopened.swarm_authority_bundle(id)?, Some(next.clone()));
    assert_eq!(
        reopened.swarm_authority_bundle_for_graph(id, &canonical_test_hash(&prior.task_graph)?)?,
        Some(prior.clone())
    );
    assert_eq!(
        reopened.swarm_authority_bundle_for_graph(id, &canonical_test_hash(&next.task_graph)?)?,
        Some(next.clone())
    );
    assert!(reopened
        .insert_swarm_authority_bundle(prior.clone())
        .is_err());
    assert!(reopened
        .extend_swarm_authority_bundle(
            &canonical_test_hash(&prior)?,
            next.clone(),
            &trusted_swarm_witness_keys()
        )
        .is_err());
    // A missing digest must never resolve a forged historical version. The
    // ordinary hook compares the returned current graph with the requested hash.
    let unknown = reopened
        .swarm_authority_bundle_for_graph(id, &sha256_hex(b"unknown"))?
        .ok_or("missing current graph")?;
    assert_ne!(
        canonical_test_hash(&unknown.task_graph)?,
        sha256_hex(b"unknown")
    );
    Ok(())
}

#[test]
fn swarm_evolution_rejects_rewrite_without_installing_or_archiving() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(NOW / 1000);
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("runtime.db");
    let (prior, mut next) = versions()?;
    let store = open(&path)?;
    store.insert_swarm_authority_bundle(prior.clone())?;
    next.budget_pool.allocations[0].max_units -= 1;
    next.budget_pool.allocations[0].active_units -= 1;
    assert!(store
        .extend_swarm_authority_bundle(
            &canonical_test_hash(&prior)?,
            next,
            &trusted_swarm_witness_keys()
        )
        .is_err());
    assert_eq!(
        store.swarm_authority_bundle(&prior.task_graph.graph_id)?,
        Some(prior)
    );
    let connection = rusqlite::Connection::open(&path)?;
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM runtime_swarm_authority_versions",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(count, 0);
    Ok(())
}

#[test]
fn swarm_evolution_serializes_competing_writers() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(NOW / 1000);
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("runtime.db");
    let (prior, next) = versions()?;
    let store = open(&path)?;
    store.insert_swarm_authority_bundle(prior.clone())?;
    let barrier = Arc::new(Barrier::new(2));
    let expected = canonical_test_hash(&prior)?;
    let mut workers = Vec::new();
    for _ in 0..2 {
        let connection = open(&path)?;
        let barrier = barrier.clone();
        let next = next.clone();
        let expected = expected.clone();
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            connection
                .extend_swarm_authority_bundle(&expected, next, &trusted_swarm_witness_keys())
                .is_ok()
        }));
    }
    let results: Vec<bool> = workers
        .into_iter()
        .map(|w| w.join().map_err(|_| "writer panicked"))
        .collect::<Result<_, _>>()?;
    assert_eq!(results.iter().filter(|accepted| **accepted).count(), 1);
    assert_eq!(
        store.swarm_authority_bundle(&prior.task_graph.graph_id)?,
        Some(next)
    );
    Ok(())
}

#[test]
fn swarm_evolution_rejects_corrupt_historical_binding() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(NOW / 1000);
    for corruption in ["index", "digest", "payload"] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("runtime.db");
        let (prior, next) = versions()?;
        let store = open(&path)?;
        store.insert_swarm_authority_bundle(prior.clone())?;
        store.extend_swarm_authority_bundle(
            &canonical_test_hash(&prior)?,
            next,
            &trusted_swarm_witness_keys(),
        )?;
        let prior_graph_hash = canonical_test_hash(&prior.task_graph)?;
        let connection = rusqlite::Connection::open(&path)?;
        let lookup_hash = if corruption == "index" {
            let changed = sha256_hex(b"substituted-index");
            connection.execute(
                "UPDATE runtime_swarm_authority_versions SET graph_sha256=?1",
                [&changed],
            )?;
            changed
        } else {
            connection.execute(
                if corruption == "digest" {
                    "UPDATE runtime_swarm_authority_versions SET bundle_sha256='forged'"
                } else {
                    "UPDATE runtime_swarm_authority_versions SET raw_json='{}'"
                },
                [],
            )?;
            prior_graph_hash
        };
        drop(store);
        assert!(
            open(&path)?
                .swarm_authority_bundle_for_graph(&prior.task_graph.graph_id, &lookup_hash)
                .is_err(),
            "accepted {corruption}"
        );
    }
    Ok(())
}
