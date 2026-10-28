use super::*;
use runtime_api::SwarmGraphSource;
use std::sync::Arc;

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

pub(super) fn issuer(
    directory: &std::path::Path,
) -> TestResult<chio_store_sqlite::SqliteAuthorityStore> {
    use std::os::unix::fs::DirBuilderExt;
    let database = directory.join("authority.sqlite3");
    let locks = directory.join("locks");
    if !locks.exists() {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
        std::fs::DirBuilder::new().mode(0o700).create(&locks)?;
        chio_store_sqlite::SqliteAuthorityStore::provision(&database, &locks)?;
    }
    Ok(
        chio_store_sqlite::SqliteAuthorityStore::open_serving_with_clock(
            &database,
            &locks,
            chio_test_support::clock::clock(),
        )?,
    )
}

pub(super) fn graphs(authority: &chio_store_sqlite::SqliteAuthorityStore) -> Arc<IssuedGraphs> {
    Arc::new(IssuedGraphs(authority.work_graph_store()))
}

#[test]
fn issued_versions_resolve_exactly_across_restart() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(NOW / 1000);
    let directory = tempfile::tempdir()?;
    let (prior, next) = versions()?;
    let authority = issuer(directory.path())?;
    issue_root(&authority, &prior)?;
    authority.work_graph_store().advance(
        &canonical_test_hash(&prior)?,
        next.clone(),
        &trusted_swarm_witness_keys(),
        &authority.mutation_fence(),
        NOW,
    )?;
    drop(authority);
    let authority = issuer(directory.path())?;
    let source = graphs(&authority);
    let id = prior.task_graph.graph_id.clone();
    assert_eq!(
        source.swarm_graph(&id, &canonical_test_hash(&prior.task_graph)?)?,
        Some(prior)
    );
    assert_eq!(
        source.swarm_graph(&id, &canonical_test_hash(&next.task_graph)?)?,
        Some(next)
    );
    assert_eq!(source.swarm_graph(&id, &sha256_hex(b"unknown"))?, None);
    Ok(())
}

#[test]
fn the_runtime_store_keeps_no_swarm_graphs() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("runtime.db");
    drop(SqliteRuntimeOrchestrationStore::open(&path)?);
    let tables: i64 = rusqlite::Connection::open(&path)?.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE name GLOB 'runtime_swarm_authority_*'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(tables, 0);
    Ok(())
}
