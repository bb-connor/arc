use super::*;

fn copy_store(source: &Path, destination: &Path) -> (PathBuf, PathBuf) {
    fs::create_dir(destination).expect("create destination");
    secure_directory(destination);
    let database = destination.join("authority.db");
    fs::copy(source.join("authority.db"), &database).expect("copy database");
    let lock_root = destination.join("locks");
    create_lock_root(&lock_root);
    for entry in fs::read_dir(source.join("locks")).expect("read lock root") {
        let entry = entry.expect("lock root entry");
        fs::copy(entry.path(), lock_root.join(entry.file_name())).expect("copy lock artifact");
    }
    (database, lock_root)
}

#[test]
fn restoring_pre_export_database_cannot_undo_retirement() {
    use std::io::Write;
    let (_temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    drop(crate::test_authority::open_serving(&database, &lock_root).expect("serve"));
    let before = fs::read(&database).expect("snapshot before export");
    SqliteAuthorityStore::export_for_relocation(&database, &lock_root).expect("export");
    // Preserve the inode and all external custody artifacts, restoring only
    // the database bytes as an in-place backup rollback would do.
    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&database)
        .expect("open inode");
    file.write_all(&before).expect("restore snapshot");
    file.sync_all().expect("sync snapshot");
    assert!(SqliteAuthorityStore::open_serving_with_clock(
        &database,
        &lock_root,
        chio_test_support::clock::clock()
    )
    .is_err());
    assert!(SqliteAuthorityStore::export_for_relocation(&database, &lock_root).is_err());
}

#[test]
fn relocation_preserves_other_authorities_in_a_shared_lock_root() {
    let (temp, database, lock_root) = fixture();
    let unrelated = temp.path().join("unrelated.db");
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision source");
    SqliteAuthorityStore::provision(&unrelated, &lock_root).expect("provision unrelated");
    let marker = path_identity_marker(&unrelated, &lock_root);
    let marker_bytes = fs::read(&marker).expect("original marker");
    SqliteAuthorityStore::export_for_relocation(&database, &lock_root).expect("export");
    let moved = temp.path().join("moved.db");
    fs::copy(&database, &moved).expect("copy exported database");
    SqliteAuthorityStore::import_relocated(&moved, &lock_root).expect("import in shared root");
    assert_eq!(fs::read(&marker).expect("retained marker"), marker_bytes);
    drop(
        crate::test_authority::open_serving(&unrelated, &lock_root)
            .expect("unrelated still serves"),
    );
    assert!(SqliteAuthorityStore::open_serving_with_clock(
        &database,
        &lock_root,
        chio_test_support::clock::clock()
    )
    .is_err());
}

#[test]
fn exported_store_refuses_serving_until_a_copy_is_imported_elsewhere() {
    let (temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let epoch_before = {
        let authority =
            crate::test_authority::open_serving(&database, &lock_root).expect("open serving");
        authority.mutation_fence().owner_epoch
    };
    let seal = SqliteAuthorityStore::export_for_relocation(&database, &lock_root).expect("export");
    assert_eq!(seal.owner_epoch, epoch_before);
    assert!(matches!(
        SqliteAuthorityStore::open_serving_with_clock(&database, &lock_root, chio_test_support::clock::clock()),
        Err(SqliteServingOwnerError::Exported(id)) if id == seal.export_id
    ));
    assert!(matches!(
        SqliteAuthorityStore::provision(&database, &lock_root),
        Err(SqliteServingOwnerError::Exported(_))
    ));
    let exported_bytes = fs::read(&database).expect("exported bytes");
    assert_eq!(
        SqliteAuthorityStore::export_for_relocation(&database, &lock_root).expect("resume export"),
        seal
    );
    assert_eq!(fs::read(&database).expect("resumed bytes"), exported_bytes);

    let (moved, moved_lock_root) = copy_store(temp.path(), &temp.path().join("moved"));
    let imported =
        SqliteAuthorityStore::import_relocated(&moved, &moved_lock_root).expect("import");
    assert_eq!(imported.seal, seal);
    // Recover a failure after the database commit but before path-marker sync.
    let marker = path_identity_marker(&moved, &moved_lock_root);
    fs::remove_file(&marker).expect("interrupt finalization");
    assert_eq!(
        SqliteAuthorityStore::import_relocated_checked(&moved, &moved_lock_root, &seal, || panic!(
            "committed import must not verify obsolete file bytes"
        ))
        .expect("resume import"),
        imported
    );
    assert!(marker.is_file(), "retry recreates the path marker");
    let (copied_import, copied_locks) = copy_store(
        &temp.path().join("moved"),
        &temp.path().join("copied-import"),
    );
    assert!(SqliteAuthorityStore::import_relocated(&copied_import, &copied_locks).is_err());
    SqliteAuthorityStore::provision(&moved, &moved_lock_root).expect("re-provision at new path");
    let relocated =
        crate::test_authority::open_serving(&moved, &moved_lock_root).expect("serve at new path");
    let fence = relocated.mutation_fence();
    assert_eq!(fence.store_uuid, seal.store_uuid);
    assert_eq!(fence.owner_epoch, epoch_before + 1);
    relocated
        .verify_database_path(&moved)
        .expect("relocated database matches its serving owner");
    assert_eq!(serving_lock_paths(&moved_lock_root).len(), 1);
    drop(relocated);
    assert!(
        SqliteAuthorityStore::import_relocated(&moved, &moved_lock_root).is_err(),
        "a served import cannot reuse its seal"
    );
    crate::test_authority::open_serving(&moved, &moved_lock_root)
        .expect("relocated store keeps serving across reopen");
    assert!(matches!(
        SqliteAuthorityStore::open_serving_with_clock(
            &database,
            &lock_root,
            chio_test_support::clock::clock()
        ),
        Err(SqliteServingOwnerError::Exported(_))
    ));
}

#[test]
fn import_refuses_stores_that_were_not_exported_or_no_longer_match_their_seal() {
    let (temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    drop(crate::test_authority::open_serving(&database, &lock_root).expect("open serving"));
    let (copy, copy_lock_root) = copy_store(temp.path(), &temp.path().join("unexported"));
    assert!(matches!(
        SqliteAuthorityStore::import_relocated(&copy, &copy_lock_root),
        Err(SqliteServingOwnerError::Invalid(message)) if message.contains("not exported")
    ));

    SqliteAuthorityStore::export_for_relocation(&database, &lock_root).expect("export");
    let (behind, behind_lock_root) = copy_store(temp.path(), &temp.path().join("behind"));
    {
        let connection = Connection::open(&behind).expect("open copy");
        connection
            .execute(
                "UPDATE chio_serving_relocation SET exported_admission_head = exported_admission_head + 1",
                [],
            )
            .expect("alter seal");
    }
    assert!(matches!(
        SqliteAuthorityStore::import_relocated(&behind, &behind_lock_root),
        Err(SqliteServingOwnerError::Invalid(message)) if message.contains("relocation seal")
    ));
}

#[test]
fn a_provisioned_store_that_never_served_relocates_and_serves_at_the_new_path() {
    let (temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let seal = SqliteAuthorityStore::export_for_relocation(&database, &lock_root).expect("export");
    assert_eq!(seal.owner_epoch, 0);
    let (moved, moved_lock_root) = copy_store(temp.path(), &temp.path().join("moved"));
    SqliteAuthorityStore::import_relocated(&moved, &moved_lock_root).expect("import");
    SqliteAuthorityStore::provision(&moved, &moved_lock_root).expect("re-provision");
    let relocated =
        crate::test_authority::open_serving(&moved, &moved_lock_root).expect("serve at new path");
    assert_eq!(relocated.mutation_fence().owner_epoch, 1);
    assert_eq!(relocated.mutation_fence().store_uuid, seal.store_uuid);
}

#[test]
fn import_checks_external_manifest_before_retiring_the_export() {
    let (temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let seal = SqliteAuthorityStore::export_for_relocation(&database, &lock_root).expect("export");
    let (moved, locks) = copy_store(temp.path(), &temp.path().join("moved"));
    let before = fs::read(&moved).expect("exported bytes");
    let result = SqliteAuthorityStore::import_relocated_checked(&moved, &locks, &seal, || {
        Err(SqliteServingOwnerError::Invalid(
            "injected manifest mismatch".into(),
        ))
    });
    assert!(result.is_err());
    assert_eq!(fs::read(&moved).expect("refused bytes"), before);
    let mut other = seal.clone();
    other.export_id = uuid::Uuid::now_v7().to_string();
    assert!(
        SqliteAuthorityStore::import_relocated_checked(&moved, &locks, &other, || panic!(
            "wrong seal must fail first"
        ))
        .is_err()
    );
    assert_eq!(fs::read(&moved).expect("wrong-seal bytes"), before);
    SqliteAuthorityStore::import_relocated_checked(&moved, &locks, &seal, || Ok(()))
        .expect("verified import");
}

#[test]
fn refused_wal_backed_import_does_not_checkpoint_foreign_state_on_close() {
    let (temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let seal = SqliteAuthorityStore::export_for_relocation(&database, &lock_root).expect("export");
    let (moved, locks) = copy_store(temp.path(), &temp.path().join("moved"));
    let reader = Connection::open(&moved).expect("reader");
    reader
        .execute_batch("BEGIN; SELECT * FROM chio_serving_relocation;")
        .expect("pin export");
    let before = fs::read(&moved).expect("exported bytes");
    let imported =
        SqliteAuthorityStore::import_relocated_checked_with_phase(&moved, &locks, &seal, |phase| {
            assert_eq!(phase, RelocationImportPhase::Exported);
            Ok(())
        })
        .expect("import");
    assert!(
        fs::read(&moved).expect("main bytes") == before,
        "fixture must retain the import in WAL"
    );
    let wal = fs::read(moved.with_extension("db-wal")).expect("committed WAL");
    assert!(wal.len() > 32);
    assert_eq!(
        SqliteAuthorityStore::import_relocated_checked(&moved, &locks, &seal, || panic!(
            "already imported"
        ))
        .expect("valid owning retry"),
        imported
    );
    let lock = locks.join(format!("{}.lock", seal.store_uuid));
    let anchor = fs::read(&lock).expect("anchor before callback refusal");
    let snapshot =
        crate::tests::authority_snapshot(&Connection::open(&moved).expect("snapshot connection"))
            .expect("snapshot");
    let refused =
        SqliteAuthorityStore::import_relocated_checked_with_phase(&moved, &locks, &seal, |phase| {
            assert_eq!(phase, RelocationImportPhase::Committed);
            Err(SqliteServingOwnerError::Invalid(
                "application files refused".into(),
            ))
        });
    assert!(refused.is_err());
    assert!(fs::read(&moved).expect("refused main") == before);
    assert!(fs::read(moved.with_extension("db-wal")).expect("refused WAL") == wal);
    assert_eq!(fs::read(&lock).expect("refused anchor"), anchor);
    assert_eq!(
        crate::tests::authority_snapshot(&Connection::open(&moved).expect("snapshot connection"))
            .expect("snapshot"),
        snapshot
    );
    for wrong_seal in [true, false] {
        let destination = temp.path().join(if wrong_seal {
            "wrong-seal"
        } else {
            "foreign-location"
        });
        let (foreign, foreign_locks) = copy_store(&temp.path().join("moved"), &destination);
        let foreign_wal = foreign.with_extension("db-wal");
        fs::write(&foreign_wal, &wal).expect("foreign WAL");
        let main_before = fs::read(&foreign).expect("foreign main");
        let lock = foreign_locks.join(format!("{}.lock", seal.store_uuid));
        let anchor = fs::read(&lock).expect("foreign anchor");
        let mut expected = seal.clone();
        if wrong_seal {
            expected.export_id = uuid::Uuid::now_v7().to_string();
        }
        let refused = SqliteAuthorityStore::import_relocated_checked_with_phase(
            &foreign,
            &foreign_locks,
            &expected,
            |_| panic!("foreign imported state must not reach file verification"),
        );
        assert!(refused.is_err());
        assert!(
            fs::read(&foreign).expect("refused main") == main_before,
            "refusal checkpointed foreign WAL"
        );
        assert!(fs::read(&foreign_wal).expect("retained foreign WAL") == wal);
        assert_eq!(fs::read(&lock).expect("retained anchor"), anchor);
    }
}

#[test]
fn verified_import_retries_after_lock_artifact_io_refusal() {
    let (temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let seal = SqliteAuthorityStore::export_for_relocation(&database, &lock_root).expect("export");
    let (moved, locks) = copy_store(temp.path(), &temp.path().join("moved"));
    let obstruction = path_identity_marker(&moved, &locks);
    fs::create_dir(&obstruction).expect("block lock artifact replacement");
    let verified = std::cell::Cell::new(false);
    let refused =
        SqliteAuthorityStore::import_relocated_checked_with_phase(&moved, &locks, &seal, |phase| {
            assert_eq!(phase, RelocationImportPhase::Exported);
            verified.set(true);
            Ok(())
        });
    assert!(
        verified.get(),
        "failure must follow successful file verification"
    );
    assert!(
        matches!(refused, Err(SqliteServingOwnerError::Invalid(ref reason)) if reason.contains("local path identity continuity marker security check failed") && reason.contains("not a regular file")),
        "{refused:?}"
    );
    // Authorized work may have partially replaced the old locks. Remove only
    // the test-owned obstruction and retry the same export at the same path.
    fs::remove_dir(&obstruction).expect("remove owned obstruction");
    let imported = SqliteAuthorityStore::import_relocated_checked(&moved, &locks, &seal, || Ok(()))
        .expect("retry authorized import");
    assert_eq!(imported.seal, seal);
    assert_eq!(
        SqliteAuthorityStore::import_relocated_checked(&moved, &locks, &seal, || panic!(
            "committed retry"
        ))
        .expect("stable import identity"),
        imported
    );
}

#[test]
fn reimporting_a_retained_export_cannot_roll_back_a_destination_that_served() {
    let (temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    drop(crate::test_authority::open_serving(&database, &lock_root).expect("serve at source"));
    let seal = SqliteAuthorityStore::export_for_relocation(&database, &lock_root).expect("export");
    let (moved, locks) = copy_store(temp.path(), &temp.path().join("moved"));
    SqliteAuthorityStore::import_relocated_checked(&moved, &locks, &seal, || Ok(()))
        .expect("first import");
    SqliteAuthorityStore::provision(&moved, &locks).expect("re-provision at new path");

    let served = temp.path().join("served.db");
    let served_epoch = {
        let authority =
            crate::test_authority::open_serving(&moved, &locks).expect("serve at new path");
        assert!(matches!(
            authority
                .budget_store()
                .authorize_budget_hold(structured_request(Some(active_authority(&authority))))
                .expect("budget hold after import"),
            BudgetAuthorizeHoldDecision::Authorized(_)
        ));
        assert!(authority
            .revocation_store()
            .revoke("revoked-after-import")
            .expect("revocation after import"));
        database_snapshot(&authority, &moved, &served);
        authority.mutation_fence().owner_epoch
    };
    assert!(served_epoch > seal.owner_epoch);

    let lock = locks.join(format!("{}.lock", seal.store_uuid));
    let marker = path_identity_marker(&moved, &locks);
    let anchor = fs::read(&lock).expect("served anchor");
    let lock_inode = lock_identity(&lock);
    let marker_bytes = fs::read(&marker).expect("served path marker");
    // The retained exported file still matches its manifest, so only the
    // destination anchor can tell that this location has served since.
    restore_database_in_place(&moved, &database);
    let exported = fs::read(&moved).expect("re-copied export");

    let canonical_lock = fs::canonicalize(&lock).expect("canonical lock path");
    let refused = SqliteAuthorityStore::import_relocated_checked(&moved, &locks, &seal, || {
        panic!("a served destination refuses before file verification")
    });
    assert!(
        matches!(
            &refused,
            Err(SqliteServingOwnerError::RelocationDestinationAnchored(path))
                if Path::new(path) == canonical_lock
        ),
        "{refused:?}"
    );
    assert_eq!(fs::read(&lock).expect("retained anchor"), anchor);
    assert_eq!(lock_identity(&lock), lock_inode);
    assert_eq!(fs::read(&marker).expect("retained marker"), marker_bytes);
    assert!(fs::read(&moved).expect("refused export") == exported);
    assert_eq!(serving_lock_paths(&locks), vec![lock.clone()]);

    // The anchor still protects the served history: the served database
    // reopens past its epoch and keeps its admissions.
    restore_database_in_place(&moved, &served);
    let reopened = crate::test_authority::open_serving(&moved, &locks).expect("served store");
    assert_eq!(reopened.mutation_fence().owner_epoch, served_epoch + 1);
    assert!(
        reopened
            .revocation_store()
            .observe_revocation("revoked-after-import")
            .expect("observe revocation")
            .revoked
    );
    drop(reopened);

    // A damaged slot beside the served record cannot prove the destination
    // never served, so it refuses as well.
    restore_database_in_place(&moved, &database);
    overwrite_lock_bytes(&lock, 64, &[0xa5; 32]);
    let anchor = fs::read(&lock).expect("damaged anchor");
    assert!(matches!(
        SqliteAuthorityStore::import_relocated_checked(&moved, &locks, &seal, || Ok(())),
        Err(SqliteServingOwnerError::RelocationDestinationAnchored(_))
    ));
    assert_eq!(fs::read(&lock).expect("retained damaged anchor"), anchor);
}

#[test]
fn an_import_stopped_before_its_database_commit_retries_from_the_retained_export() {
    let (temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    drop(crate::test_authority::open_serving(&database, &lock_root).expect("serve at source"));
    let seal = SqliteAuthorityStore::export_for_relocation(&database, &lock_root).expect("export");
    let exported = fs::read(&database).expect("exported bytes");
    for variant in ["seeded", "shaped", "unseeded", "torn-first-seed"] {
        let (moved, locks) = copy_store(temp.path(), &temp.path().join(variant));
        let lock = locks.join(format!("{}.lock", seal.store_uuid));
        crate::serving_owner::relocation::import_commit_cutpoint::arm();
        let stopped =
            SqliteAuthorityStore::import_relocated_checked(&moved, &locks, &seal, || Ok(()));
        assert!(
            matches!(&stopped, Err(SqliteServingOwnerError::OutcomeUnknown(detail)) if detail.contains("before its database commit")),
            "{variant}: {stopped:?}"
        );
        // A crash before the commit leaves the exported database, a fresh
        // seeded lock and no identity marker for the destination path.
        assert!(fs::read(&moved).expect("stopped database") == exported);
        assert!(!path_identity_marker(&moved, &locks).exists());
        assert_eq!(serving_lock_paths(&locks), vec![lock.clone()]);
        match variant {
            "shaped" => overwrite_lock_bytes(&lock, 0, &[0; 2048]),
            "unseeded" => {
                fs::remove_file(&lock).expect("remove seeded lock");
                drop(create_lock_file(&lock).expect("unseeded lock"));
            }
            "torn-first-seed" => overwrite_lock_bytes(&lock, 64, &[0xa5; 32]),
            _ => {}
        }
        let retried = SqliteAuthorityStore::import_relocated_checked_with_phase(
            &moved,
            &locks,
            &seal,
            |phase| {
                assert_eq!(phase, RelocationImportPhase::Exported);
                Ok(())
            },
        )
        .unwrap_or_else(|error| panic!("{variant} retry: {error}"));
        assert_eq!(retried.seal, seal);
        assert!(path_identity_marker(&moved, &locks).is_file());
        SqliteAuthorityStore::provision(&moved, &locks).expect("re-provision at new path");
        let relocated =
            crate::test_authority::open_serving(&moved, &locks).expect("serve after retry");
        assert_eq!(relocated.mutation_fence().owner_epoch, seal.owner_epoch + 1);
        assert_eq!(relocated.mutation_fence().store_uuid, seal.store_uuid);
        assert_eq!(serving_lock_paths(&locks), vec![lock]);
    }
}

#[test]
fn a_copied_marker_for_the_destination_path_does_not_bind_a_new_lock_root() {
    let (temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    drop(crate::test_authority::open_serving(&database, &lock_root).expect("serve at source"));
    let seal = SqliteAuthorityStore::export_for_relocation(&database, &lock_root).expect("export");
    // Same database path, another lock root: the copied marker for this path
    // records the inode it was copied from.
    let locks = temp.path().join("copied-locks");
    create_lock_root(&locks);
    for entry in fs::read_dir(&lock_root).expect("read lock root") {
        let entry = entry.expect("lock root entry");
        fs::copy(entry.path(), locks.join(entry.file_name())).expect("copy lock artifact");
    }
    assert!(path_identity_marker(&database, &locks).is_file());
    let imported =
        SqliteAuthorityStore::import_relocated_checked(&database, &locks, &seal, || Ok(()))
            .expect("import beside a copied marker");
    assert_eq!(imported.seal, seal);
    SqliteAuthorityStore::provision(&database, &locks).expect("re-provision");
    let relocated =
        crate::test_authority::open_serving(&database, &locks).expect("serve under new root");
    assert_eq!(relocated.mutation_fence().owner_epoch, seal.owner_epoch + 1);
}

#[test]
fn an_in_place_import_binds_the_source_location_like_any_destination() {
    let (temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    drop(crate::test_authority::open_serving(&database, &lock_root).expect("serve at source"));
    let seal = SqliteAuthorityStore::export_for_relocation(&database, &lock_root).expect("export");
    let retained = temp.path().join("retained.db");
    fs::copy(&database, &retained).expect("retain export");
    // The source location still holds its retirement record, so it imports
    // in place over its own provisioning marker.
    assert!(path_identity_marker(&database, &lock_root).is_file());
    SqliteAuthorityStore::import_relocated_checked(&database, &lock_root, &seal, || Ok(()))
        .expect("in-place import");
    {
        SqliteAuthorityStore::provision(&database, &lock_root).expect("re-provision");
        let authority =
            crate::test_authority::open_serving(&database, &lock_root).expect("serve in place");
        assert!(matches!(
            authority
                .budget_store()
                .authorize_budget_hold(structured_request(Some(active_authority(&authority))))
                .expect("budget hold after import"),
            BudgetAuthorizeHoldDecision::Authorized(_)
        ));
    }
    let lock = lock_root.join(format!("{}.lock", seal.store_uuid));
    OpenOptions::new()
        .write(true)
        .open(&lock)
        .expect("open lock")
        .set_len(0)
        .expect("empty lock");
    let marker = path_identity_marker(&database, &lock_root);
    let marker_bytes = fs::read(&marker).expect("marker");
    let lock_inode = lock_identity(&lock);
    restore_database_in_place(&database, &retained);
    assert!(matches!(
        SqliteAuthorityStore::import_relocated_checked(&database, &lock_root, &seal, || Ok(())),
        Err(SqliteServingOwnerError::RelocationDestinationAnchored(_))
    ));
    assert!(fs::read(&lock).expect("retained lock").is_empty());
    assert_eq!(lock_identity(&lock), lock_inode);
    assert_eq!(fs::read(&marker).expect("retained marker"), marker_bytes);
    assert!(fs::read(&database).expect("refused export") == fs::read(&retained).expect("retained"));
}

fn overwrite_lock_bytes(path: &Path, offset: u64, bytes: &[u8]) {
    use std::os::unix::fs::FileExt;
    let file = OpenOptions::new()
        .write(true)
        .open(path)
        .expect("open lock for damage");
    file.write_all_at(bytes, offset).expect("damage lock");
    file.sync_all().expect("sync damaged lock");
}

/// The lock's bytes and inode, or nothing when it is absent.
fn lock_state(path: &Path) -> Option<(Vec<u8>, (u64, u64))> {
    path.exists()
        .then(|| (fs::read(path).expect("lock bytes"), lock_identity(path)))
}

fn lock_identity(path: &Path) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::metadata(path).expect("lock metadata");
    (metadata.dev(), metadata.ino())
}

#[test]
fn an_emptied_or_damaged_anchor_cannot_hide_a_committed_import() {
    let (temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    drop(crate::test_authority::open_serving(&database, &lock_root).expect("serve at source"));
    let seal = SqliteAuthorityStore::export_for_relocation(&database, &lock_root).expect("export");
    let exported = fs::read(&database).expect("exported bytes");
    let mut outcomes = Vec::new();
    for variant in [
        "second-slot-zeroed",
        "anchor-zeroed",
        "anchor-emptied",
        "anchor-deleted",
        "first-seed-torn",
        "committed-unserved",
    ] {
        let (moved, locks) = copy_store(temp.path(), &temp.path().join(variant));
        SqliteAuthorityStore::import_relocated_checked(&moved, &locks, &seal, || Ok(()))
            .expect("first import");
        if variant != "committed-unserved" {
            SqliteAuthorityStore::provision(&moved, &locks).expect("re-provision at new path");
            let authority =
                crate::test_authority::open_serving(&moved, &locks).expect("serve at new path");
            assert!(authority.mutation_fence().owner_epoch > seal.owner_epoch);
            if matches!(
                variant,
                "anchor-zeroed" | "anchor-emptied" | "anchor-deleted"
            ) {
                assert!(matches!(
                    authority
                        .budget_store()
                        .authorize_budget_hold(structured_request(Some(active_authority(
                            &authority
                        ))))
                        .expect("budget hold after import"),
                    BudgetAuthorizeHoldDecision::Authorized(_)
                ));
            }
        }
        let lock = locks.join(format!("{}.lock", seal.store_uuid));
        match variant {
            "second-slot-zeroed" => overwrite_lock_bytes(&lock, 1024, &[0; 1024]),
            "anchor-zeroed" => overwrite_lock_bytes(&lock, 0, &[0; 2048]),
            "anchor-emptied" => OpenOptions::new()
                .write(true)
                .open(&lock)
                .expect("open lock")
                .set_len(0)
                .expect("empty lock"),
            "anchor-deleted" => fs::remove_file(&lock).expect("delete lock"),
            "first-seed-torn" => {
                overwrite_lock_bytes(&lock, 1024, &[0; 1024]);
                overwrite_lock_bytes(&lock, 64, &[0xa5; 32]);
            }
            _ => {}
        }
        let marker = path_identity_marker(&moved, &locks);
        let anchor = lock_state(&lock);
        let marker_bytes = fs::read(&marker).expect("native destination marker");
        restore_database_in_place(&moved, &database);

        let result =
            SqliteAuthorityStore::import_relocated_checked(&moved, &locks, &seal, || Ok(()));
        let untouched = lock_state(&lock) == anchor
            && fs::read(&marker).expect("retained marker") == marker_bytes
            && fs::read(&moved).expect("refused export") == exported;
        outcomes.push((variant, result, untouched));
    }
    for (variant, result, untouched) in &outcomes {
        assert!(
            matches!(
                result,
                Err(SqliteServingOwnerError::RelocationDestinationAnchored(_))
            ) && *untouched,
            "{variant} re-imported over a committed destination: {result:?}, untouched {untouched}; all: {outcomes:?}"
        );
    }
}
