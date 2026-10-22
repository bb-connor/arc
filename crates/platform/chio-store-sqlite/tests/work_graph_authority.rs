//! S1 graph issuance through the serving authority: the issuer head advances
//! only by a fenced expected-head compare-and-swap over a verified additive
//! extension.

use chio_core::crypto::{canonical_json_bytes, sha256_hex, PublicKey};
use chio_core::StoreMutationFence;
use chio_store_sqlite::work_graph_store::{
    SqliteWorkGraphStore, SqliteWorkGraphStoreError, WorkGraphIssuance,
};
use chio_store_sqlite::SqliteAuthorityStore;
use chio_swarm_authority::SwarmAuthorityBundle;
use std::sync::Barrier;

#[path = "work_authority_support/serving.rs"]
mod serving;
#[path = "work_authority_support/swarm.rs"]
mod swarm;
use serving::{Fixture, TestResult};
use swarm::{competing_extension, trusted_witness_keys, versions, with_grandchild, NOW_UNIX_MS};

struct Env {
    fixture: Fixture,
    owner: SqliteAuthorityStore,
    store: SqliteWorkGraphStore,
    fence: StoreMutationFence,
    keys: Vec<PublicKey>,
}

impl Env {
    fn new() -> TestResult<Self> {
        Self::open(Fixture::new(NOW_UNIX_MS)?)
    }

    fn open(fixture: Fixture) -> TestResult<Self> {
        let owner = fixture.open()?;
        let store = owner.work_graph_store();
        let fence = store.mutation_fence();
        Ok(Self {
            fixture,
            owner,
            store,
            fence,
            keys: trusted_witness_keys(),
        })
    }

    fn reopen(self) -> TestResult<Self> {
        let Self {
            fixture,
            owner,
            store,
            ..
        } = self;
        drop(store);
        drop(owner);
        Self::open(fixture)
    }

    fn provision(
        &self,
        root: &SwarmAuthorityBundle,
    ) -> Result<WorkGraphIssuance, SqliteWorkGraphStoreError> {
        self.store
            .provision_root(root.clone(), &self.keys, &self.fence, NOW_UNIX_MS)
    }

    fn advance(
        &self,
        expected: &str,
        candidate: &SwarmAuthorityBundle,
    ) -> Result<WorkGraphIssuance, SqliteWorkGraphStoreError> {
        self.store.advance(
            expected,
            candidate.clone(),
            &self.keys,
            &self.fence,
            NOW_UNIX_MS,
        )
    }

    fn count(&self, table: &str) -> TestResult<i64> {
        Ok(self
            .fixture
            .raw()?
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })?)
    }
}

fn graph_sha256(bundle: &SwarmAuthorityBundle) -> TestResult<String> {
    Ok(sha256_hex(&canonical_json_bytes(&bundle.task_graph)?))
}

fn bytes(bundle: &SwarmAuthorityBundle) -> TestResult<Vec<u8>> {
    Ok(canonical_json_bytes(bundle)?)
}

#[test]
fn provision_a_root_and_advance_once() -> TestResult {
    let (prior, next) = versions()?;
    let env = Env::new()?;
    assert!(env.store.head(&prior.task_graph.graph_id)?.is_none());
    let root = env.provision(&prior)?;
    assert_eq!(root.revision, 1);
    assert_eq!(root.parent_bundle_sha256, None);
    assert_eq!(root.graph_id, prior.task_graph.graph_id);
    assert_eq!(env.provision(&prior)?, root);

    let advanced = env.advance(&root.bundle_sha256, &next)?;
    assert_eq!(advanced.revision, 2);
    assert_eq!(
        advanced.parent_bundle_sha256.as_deref(),
        Some(root.bundle_sha256.as_str())
    );
    let (head, digest) = env
        .store
        .head(&prior.task_graph.graph_id)?
        .ok_or("head after advance")?;
    assert_eq!(digest, advanced.bundle_sha256);
    assert_eq!(bytes(&head)?, bytes(&next)?);
    assert_eq!(env.store.issuance(&advanced.bundle_sha256)?, Some(advanced));
    assert_eq!(env.store.issuance(&root.bundle_sha256)?, Some(root));
    Ok(())
}

#[test]
fn a_different_root_for_an_issued_graph_conflicts() -> TestResult {
    let (prior, next) = versions()?;
    let env = Env::new()?;
    env.provision(&prior)?;
    assert!(matches!(
        env.provision(&next),
        Err(SqliteWorkGraphStoreError::RootConflict)
    ));
    Ok(())
}

#[test]
fn advancing_an_unprovisioned_graph_is_refused() -> TestResult {
    let (_prior, next) = versions()?;
    let env = Env::new()?;
    assert!(matches!(
        env.advance(&"0".repeat(64), &next),
        Err(SqliteWorkGraphStoreError::NotProvisioned)
    ));
    assert_eq!(env.count("work_graph_events")?, 0);
    Ok(())
}

#[test]
fn competing_candidates_commit_exactly_one_head() -> TestResult {
    let (prior, next) = versions()?;
    let rival = competing_extension(&next)?;
    let env = Env::new()?;
    let root = env.provision(&prior)?;
    let barrier = Barrier::new(2);
    let results = std::thread::scope(|scope| {
        let workers: Vec<_> = [&next, &rival]
            .into_iter()
            .map(|candidate| {
                let (env, barrier, root) = (&env, &barrier, &root);
                scope.spawn(move || {
                    barrier.wait();
                    env.advance(&root.bundle_sha256, candidate)
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().map_err(|_| "advance worker panicked"))
            .collect::<Result<Vec<_>, _>>()
    })?;
    let committed: Vec<_> = results.iter().filter_map(|r| r.as_ref().ok()).collect();
    assert_eq!(committed.len(), 1, "{results:?}");
    assert!(
        results
            .iter()
            .any(|r| matches!(r, Err(SqliteWorkGraphStoreError::StaleHead))),
        "{results:?}"
    );
    let (_, head_digest) = env
        .store
        .head(&prior.task_graph.graph_id)?
        .ok_or("head after race")?;
    assert_eq!(head_digest, committed[0].bundle_sha256);
    assert_eq!(env.count("work_graph_issuances")?, 2);
    assert_eq!(env.count("work_graph_events")?, 2);
    Ok(())
}

#[test]
fn the_losing_candidate_stays_stale_after_the_winner() -> TestResult {
    let (prior, next) = versions()?;
    let rival = competing_extension(&next)?;
    let env = Env::new()?;
    let root = env.provision(&prior)?;
    let winner = env.advance(&root.bundle_sha256, &next)?;
    assert!(matches!(
        env.advance(&root.bundle_sha256, &rival),
        Err(SqliteWorkGraphStoreError::StaleHead)
    ));
    let (_, head_digest) = env.store.head(&prior.task_graph.graph_id)?.ok_or("head")?;
    assert_eq!(head_digest, winner.bundle_sha256);
    Ok(())
}

#[test]
fn replaying_a_committed_candidate_returns_its_original_issuance() -> TestResult {
    let (prior, next) = versions()?;
    let later = with_grandchild(&next, "a")?;
    let env = Env::new()?;
    let root = env.provision(&prior)?;
    let first = env.advance(&root.bundle_sha256, &next)?;
    let second = env.advance(&first.bundle_sha256, &later)?;
    assert_eq!(second.revision, 3);
    let events = env.count("work_graph_events")?;

    let replay = env.advance(&root.bundle_sha256, &next)?;
    assert_eq!(replay, first);
    assert_eq!(env.count("work_graph_events")?, events);
    let (_, head_digest) = env.store.head(&prior.task_graph.graph_id)?.ok_or("head")?;
    assert_eq!(head_digest, second.bundle_sha256);
    assert!(matches!(
        env.advance(&second.bundle_sha256, &next),
        Err(SqliteWorkGraphStoreError::StaleHead)
    ));
    Ok(())
}

#[test]
fn version_returns_the_archived_parent_by_graph_digest() -> TestResult {
    let (prior, next) = versions()?;
    let later = with_grandchild(&next, "a")?;
    let env = Env::new()?;
    let graph_id = &prior.task_graph.graph_id;
    let root = env.provision(&prior)?;
    let first = env.advance(&root.bundle_sha256, &next)?;
    env.advance(&first.bundle_sha256, &later)?;
    for expected in [&prior, &next, &later] {
        let found = env
            .store
            .version(graph_id, &graph_sha256(expected)?)?
            .ok_or("issued version must be readable")?;
        assert_eq!(bytes(&found)?, bytes(expected)?);
    }
    assert!(env
        .store
        .version(graph_id, &sha256_hex(b"never issued"))?
        .is_none());
    assert!(env
        .store
        .version("another-graph", &graph_sha256(&prior)?)?
        .is_none());
    Ok(())
}

#[test]
fn a_rejected_extension_leaves_head_and_history_unchanged() -> TestResult {
    let (prior, next) = versions()?;
    let env = Env::new()?;
    let root = env.provision(&prior)?;
    let first = env.advance(&root.bundle_sha256, &next)?;
    let mut shrunk = next.clone();
    shrunk
        .task_graph
        .nodes
        .retain(|node| node.task_id != "task-child-a");
    let events = env.count("work_graph_events")?;
    let issuances = env.count("work_graph_issuances")?;
    let versions_before = env.count("work_graph_versions")?;
    let refused = env.advance(&first.bundle_sha256, &shrunk);
    assert!(
        matches!(refused, Err(SqliteWorkGraphStoreError::Rejected(_))),
        "{refused:?}"
    );
    let (head, digest) = env.store.head(&prior.task_graph.graph_id)?.ok_or("head")?;
    assert_eq!(digest, first.bundle_sha256);
    assert_eq!(bytes(&head)?, bytes(&next)?);
    assert_eq!(env.count("work_graph_events")?, events);
    assert_eq!(env.count("work_graph_issuances")?, issuances);
    assert_eq!(env.count("work_graph_versions")?, versions_before);
    Ok(())
}

#[test]
fn a_stale_fence_is_rejected_without_state_change() -> TestResult {
    let (prior, next) = versions()?;
    let env = Env::new()?;
    let root = env.provision(&prior)?;
    let stale = env.fence.clone();
    let env = env.reopen()?;
    assert!(env.fence.owner_epoch > stale.owner_epoch);
    let events = env.count("work_graph_events")?;

    assert!(env
        .store
        .advance(
            &root.bundle_sha256,
            next.clone(),
            &env.keys,
            &stale,
            NOW_UNIX_MS
        )
        .is_err());
    assert!(env
        .store
        .provision_root(next.clone(), &env.keys, &stale, NOW_UNIX_MS)
        .is_err());
    let (head, digest) = env.store.head(&prior.task_graph.graph_id)?.ok_or("head")?;
    assert_eq!(digest, root.bundle_sha256);
    assert_eq!(bytes(&head)?, bytes(&prior)?);
    assert_eq!(env.count("work_graph_events")?, events);
    assert_eq!(env.count("work_graph_issuances")?, 1);

    env.advance(&root.bundle_sha256, &next)
        .map_err(|error| format!("current fence must still advance: {error}"))?;
    Ok(())
}

#[test]
fn reopen_preserves_head_and_issuances() -> TestResult {
    let (prior, next) = versions()?;
    let env = Env::new()?;
    let root = env.provision(&prior)?;
    let first = env.advance(&root.bundle_sha256, &next)?;
    let events = env.count("work_graph_events")?;

    let env = env.reopen()?;
    let (head, digest) = env
        .store
        .head(&prior.task_graph.graph_id)?
        .ok_or("head after reopen")?;
    assert_eq!(digest, first.bundle_sha256);
    assert_eq!(bytes(&head)?, bytes(&next)?);
    assert_eq!(env.store.issuance(&root.bundle_sha256)?, Some(root.clone()));
    assert_eq!(
        env.store.issuance(&first.bundle_sha256)?,
        Some(first.clone())
    );
    assert_eq!(env.advance(&root.bundle_sha256, &next)?, first);
    assert_eq!(env.count("work_graph_events")?, events);
    let archived = env
        .store
        .version(&prior.task_graph.graph_id, &graph_sha256(&prior)?)?
        .ok_or("archived parent after reopen")?;
    assert_eq!(bytes(&archived)?, bytes(&prior)?);
    Ok(())
}

#[test]
fn a_schema_stamp_mismatch_is_refused() -> TestResult {
    let (prior, _next) = versions()?;
    let env = Env::new()?;
    env.provision(&prior)?;
    let Env {
        fixture,
        owner,
        store,
        ..
    } = env;
    drop(store);
    drop(owner);
    fixture.raw()?.execute_batch(
        "PRAGMA ignore_check_constraints = ON;
         UPDATE chio_store_schema_versions SET version = 2 WHERE store_key = 'work_graph';
         PRAGMA ignore_check_constraints = OFF;",
    )?;
    let error = fixture
        .open()
        .err()
        .ok_or("stale graph schema was admitted")?;
    assert!(matches!(
        error.downcast_ref::<chio_store_sqlite::SqliteServingOwnerError>(),
        Some(chio_store_sqlite::SqliteServingOwnerError::Schema(
            chio_store_sqlite::SchemaVersionError::StaleSchema {
                found: 2,
                current: 1
            }
        ))
    ));
    Ok(())
}

#[test]
fn tampering_with_the_head_fails_reopen() -> TestResult {
    let (prior, next) = versions()?;
    let env = Env::new()?;
    let root = env.provision(&prior)?;
    env.advance(&root.bundle_sha256, &next)?;
    let Env {
        fixture,
        owner,
        store,
        ..
    } = env;
    drop(store);
    drop(owner);
    fixture
        .raw()?
        .execute("UPDATE work_graph_heads SET revision = 1", [])?;
    assert!(fixture.open().is_err());
    Ok(())
}
