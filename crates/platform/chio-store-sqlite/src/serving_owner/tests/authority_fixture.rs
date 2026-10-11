use super::*;

pub(super) fn database_snapshot(authority: &SqliteAuthorityStore, database: &Path, target: &Path) {
    let connection = authority.connection.lock().expect("authority connection");
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint snapshot");
    fs::copy(database, target).expect("copy snapshot");
}

pub(super) fn restore_database_in_place(database: &Path, snapshot: &Path) {
    let mut input = File::open(snapshot).expect("open snapshot");
    let mut output = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(database)
        .expect("open database for restore");
    std::io::copy(&mut input, &mut output).expect("restore database");
    output.sync_all().expect("sync restored database");
    for suffix in ["-wal", "-shm"] {
        let _ = fs::remove_file(PathBuf::from(format!("{}{suffix}", database.display())));
    }
}

pub(super) fn only_serving_lock(lock_root: &Path) -> PathBuf {
    fs::read_dir(lock_root)
        .expect("read lock root")
        .map(|entry| entry.expect("lock entry").path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "lock")
        })
        .expect("serving lock")
}

pub(super) fn serving_lock_paths(lock_root: &Path) -> Vec<PathBuf> {
    let mut paths = fs::read_dir(lock_root)
        .expect("read lock root")
        .map(|entry| entry.expect("lock entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "lock")
        })
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

pub(super) fn path_identity_marker(database: &Path, lock_root: &Path) -> PathBuf {
    super::path_identity::marker_path(
        lock_root,
        &fs::canonicalize(database).expect("canonical database path"),
    )
    .expect("path identity marker")
}

pub(super) fn active_authority(authority: &SqliteAuthorityStore) -> BudgetEventAuthority {
    let fence = authority.mutation_fence();
    BudgetEventAuthority {
        authority_id: fence.store_uuid,
        lease_id: fence.lease_id,
        lease_epoch: fence.owner_epoch,
    }
}

pub(super) fn structured_request(
    authority: Option<BudgetEventAuthority>,
) -> BudgetAuthorizeHoldRequest {
    BudgetAuthorizeHoldRequest {
        capability_id: "cap-structured".to_string(),
        grant_index: 0,
        max_invocations: Some(1),
        invocation_quotas: Vec::new(),
        cumulative_approval: None,
        admission_binding: Some(BudgetAdmissionBinding {
            operation_id: "operation-structured".to_string(),
            revocation_set: CanonicalRevocationSet::canonicalize(
                vec!["cap-structured".to_string()],
            )
            .expect("canonical revocation set"),
            authorization_artifact_digests: vec!["a".repeat(64)],
            last_observed_revocation: None,
            supplemental_verifier_id: None,
            supplemental_verifier_config_digest: None,
            supplemental_authorization_artifact_digest: None,
            supplemental_authorization_expires_at: None,
        }),
        requested_exposure_units: 10,
        max_cost_per_invocation: Some(10),
        max_total_cost_units: Some(10),
        hold_id: Some("hold-structured".to_string()),
        event_id: Some("event-structured".to_string()),
        authority,
    }
}

pub(super) fn provision_structured_authority(
    database: &Path,
    lock_root: &Path,
) -> BudgetEventAuthority {
    SqliteAuthorityStore::provision(database, lock_root).expect("provision");
    let authority = crate::test_authority::open_serving(database, lock_root).expect("open serving");
    let active = active_authority(&authority);
    let budget = authority.budget_store();
    assert!(matches!(
        budget
            .authorize_budget_hold(structured_request(Some(active.clone())))
            .expect("authorize structured hold"),
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));
    drop(budget);
    drop(authority);
    active
}
