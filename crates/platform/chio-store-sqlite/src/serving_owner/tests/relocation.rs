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
fn exported_store_refuses_serving_until_a_copy_is_imported_elsewhere() {
    let (temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let epoch_before = {
        let authority =
            SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open serving");
        authority.mutation_fence().owner_epoch
    };
    let seal = SqliteAuthorityStore::export_for_relocation(&database, &lock_root).expect("export");
    assert_eq!(seal.owner_epoch, epoch_before);
    assert!(matches!(
        SqliteAuthorityStore::open_serving(&database, &lock_root),
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
        SqliteAuthorityStore::open_serving(&moved, &moved_lock_root).expect("serve at new path");
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
    SqliteAuthorityStore::open_serving(&moved, &moved_lock_root)
        .expect("relocated store keeps serving across reopen");
    assert!(matches!(
        SqliteAuthorityStore::open_serving(&database, &lock_root),
        Err(SqliteServingOwnerError::Exported(_))
    ));
}

#[test]
fn import_refuses_stores_that_were_not_exported_or_no_longer_match_their_seal() {
    let (temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    drop(SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open serving"));
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
        SqliteAuthorityStore::open_serving(&moved, &moved_lock_root).expect("serve at new path");
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
