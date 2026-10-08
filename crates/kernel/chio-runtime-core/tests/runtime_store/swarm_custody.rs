use super::*;
use chio_runtime_core::CHIO_RUNTIME_ADMISSION_STORE_SCHEMA;
use std::error::Error;

const UNVERIFIED: &str = "runtime_swarm_authority_bundle_unverified";

/// The authentic fixture with a signed task-graph field altered after signing,
/// as an unauthenticated writer would submit it to claim the graph id.
fn forged_squat(authentic: &SwarmAuthorityBundle) -> SwarmAuthorityBundle {
    let mut forged = authentic.clone();
    forged.task_graph.planner_subject = "did:chio:squatter".to_string();
    forged
}

fn expect_unverified(result: Result<(), ChioRuntimeError>) -> Result<(), Box<dyn Error>> {
    let error = result.err().ok_or("unverified swarm bundle was stored")?;
    assert_eq!(error.code(), UNVERIFIED);
    Ok(())
}

/// Every backend refuses a forged bundle and an untrusted signer, leaves the
/// graph id unclaimed, and then stores the authentic bundle.
fn refuses_unverified_then_stores_authentic(
    insert: impl Fn(SwarmAuthorityBundle, &[PublicKey]) -> Result<(), ChioRuntimeError>,
    read: impl Fn(&str) -> Result<Option<SwarmAuthorityBundle>, ChioRuntimeError>,
) -> Result<(), Box<dyn Error>> {
    let authentic = swarm_authority_bundle_fixture()?;
    let trusted = swarm_fixture_trusted_keys(&authentic)?;
    let graph_id = authentic.task_graph.graph_id.clone();

    expect_unverified(insert(forged_squat(&authentic), &trusted))?;
    expect_unverified(insert(
        authentic.clone(),
        &[Keypair::generate().public_key()],
    ))?;
    expect_unverified(insert(authentic.clone(), &[]))?;
    assert_eq!(read(&graph_id)?, None);

    insert(authentic.clone(), &trusted)?;
    assert_eq!(read(&graph_id)?, Some(authentic));
    Ok(())
}

#[test]
fn in_memory_swarm_store_refuses_unverified_bundles() -> Result<(), Box<dyn Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    refuses_unverified_then_stores_authentic(
        |bundle, keys| store.insert_swarm_authority_bundle(bundle, keys),
        |graph_id| store.swarm_authority_bundle(graph_id),
    )
}

#[test]
fn json_swarm_store_refuses_unverified_bundles() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let store = JsonRuntimeAdmissionStore::open(directory.path().join("admission.json"))?;
    refuses_unverified_then_stores_authentic(
        |bundle, keys| store.insert_swarm_authority_bundle(bundle, keys),
        |graph_id| store.swarm_authority_bundle(graph_id),
    )
}

#[test]
fn sqlite_swarm_store_refuses_unverified_bundles() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(directory.path().join("swarm.sqlite3"))?;
    refuses_unverified_then_stores_authentic(
        |bundle, keys| store.insert_swarm_authority_bundle(bundle, keys),
        |graph_id| store.swarm_authority_bundle(graph_id),
    )
}

#[test]
fn sqlite_authentic_swarm_bundle_displaces_stored_squat() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("swarm.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    let authentic = swarm_authority_bundle_fixture()?;
    let trusted = swarm_fixture_trusted_keys(&authentic)?;
    let forged = forged_squat(&authentic);
    let forged_sha256 =
        chio_core_types::hashing::sha256_hex(&chio_core_types::canonical_json_bytes(&forged)?);
    rusqlite::Connection::open(&path)?.execute(
        "INSERT INTO runtime_swarm_authority_bundles (task_graph_id, bundle_sha256, raw_json, created_at_unix_ms) VALUES (?1, ?2, ?3, 1)",
        rusqlite::params![
            forged.task_graph.graph_id,
            forged_sha256,
            serde_json::to_string(&forged)?
        ],
    )?;
    assert_eq!(
        store.swarm_authority_bundle(&authentic.task_graph.graph_id)?,
        Some(forged.clone())
    );

    expect_unverified(store.insert_swarm_authority_bundle(forged, &trusted))?;
    store.insert_swarm_authority_bundle(authentic.clone(), &trusted)?;
    store.insert_swarm_authority_bundle(authentic.clone(), &trusted)?;
    assert_eq!(
        store.swarm_authority_bundle(&authentic.task_graph.graph_id)?,
        Some(authentic)
    );
    Ok(())
}

#[test]
fn json_authentic_swarm_bundle_displaces_stored_squat() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("admission.json");
    let authentic = swarm_authority_bundle_fixture()?;
    let trusted = swarm_fixture_trusted_keys(&authentic)?;
    let forged = forged_squat(&authentic);
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&serde_json::json!({
            "schema": CHIO_RUNTIME_ADMISSION_STORE_SCHEMA,
            "bundles": [],
            "swarmAuthorityBundles": [forged],
            "consumedLeaseIds": [],
        }))?,
    )?;
    let store = JsonRuntimeAdmissionStore::open(&path)?;
    assert_eq!(
        store.swarm_authority_bundle(&authentic.task_graph.graph_id)?,
        Some(forged)
    );

    store.insert_swarm_authority_bundle(authentic.clone(), &trusted)?;
    let reopened = JsonRuntimeAdmissionStore::open(&path)?;
    assert_eq!(
        reopened.swarm_authority_bundle(&authentic.task_graph.graph_id)?,
        Some(authentic)
    );
    Ok(())
}
