use super::*;

#[test]
fn seal_identity_matches_the_actual_open_database_descriptor() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("descriptor-identity.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    let raw = Connection::open(&path)?;
    let seal = store.seal_legacy_replay_source(&binding()?)?;
    assert_eq!(
        seal.file_identity(),
        &chio_sqlite_file_identity::main_database_file_identity(&raw)?
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::metadata(&path)?;
        assert_eq!(seal.file_identity().device, metadata.dev());
        assert_eq!(seal.file_identity().inode, metadata.ino());
        assert_eq!(seal.file_identity().link_count, metadata.nlink());
    }
    Ok(())
}

#[test]
fn replacing_the_path_does_not_rebind_an_already_open_descriptor() -> TestResult {
    for initially_sealed in [false, true] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("original.sqlite3");
        let displaced = directory.path().join("displaced.sqlite3");
        let store = SqliteRuntimeOrchestrationStore::open(&path)?;
        seed_inventory(&store)?;
        let binding = binding()?;
        let seal = initially_sealed
            .then(|| store.seal_legacy_replay_source(&binding))
            .transpose()?;
        std::fs::rename(&path, &displaced)?;
        // Reuse the configured pathname while the SQLite connection still owns
        // the original inode. No database reads through this new file qualify it.
        let replacement = std::fs::File::create(&path)?;
        assert_code(
            store.seal_legacy_replay_source(&binding),
            "runtime_replay_source_invalid",
        );
        if let Some(seal) = seal.as_ref() {
            assert_code(
                store.load_legacy_replay_source_seal(&binding),
                "runtime_replay_source_invalid",
            );
            assert_code(
                store.verify_legacy_replay_source_seal(seal),
                "runtime_replay_source_invalid",
            );
        }
        drop(replacement);
        std::fs::remove_file(&path)?;
        std::fs::rename(&displaced, &path)?;
        if let Some(seal) = seal.as_ref() {
            store.verify_legacy_replay_source_seal(seal)?;
        } else {
            let seal = store.seal_legacy_replay_source(&binding)?;
            assert_inventory(&seal);
        }
    }
    Ok(())
}

#[test]
fn copied_sealed_database_cannot_reuse_the_original_file_identity() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("source.sqlite3");
    let copy = directory.path().join("copied.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    seed_inventory(&store)?;
    let seal = store.seal_legacy_replay_source(&binding()?)?;
    let raw = Connection::open(&path)?;
    let checkpoint: (i64, i64, i64) =
        raw.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
    assert_eq!(
        checkpoint.0, 0,
        "fixture checkpoint must finish before copying the main file"
    );
    drop(raw);
    drop(store);
    std::fs::copy(&path, &copy)?;
    let copy_raw = Connection::open(&copy)?;
    let before = raw_snapshot(&copy_raw)?;
    assert_ne!(
        seal.file_identity(),
        &chio_sqlite_file_identity::main_database_file_identity(&copy_raw)?
    );
    match SqliteRuntimeOrchestrationStore::open(&copy) {
        Err(error) => assert_eq!(error.code(), "runtime_replay_source_invalid"),
        Ok(_) => panic!("copied source seal was rebound to a different physical file"),
    }
    assert_eq!(raw_snapshot(&copy_raw)?, before);
    SqliteRuntimeOrchestrationStore::open(&path)?.verify_legacy_replay_source_seal(&seal)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn hard_links_reject_initial_seal_and_invalidate_an_existing_seal() -> TestResult {
    for initially_sealed in [false, true] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("single-link.sqlite3");
        let alias = directory.path().join("hard-linked.sqlite3");
        let store = SqliteRuntimeOrchestrationStore::open(&path)?;
        let binding = binding()?;
        let seal = initially_sealed
            .then(|| store.seal_legacy_replay_source(&binding))
            .transpose()?;
        std::fs::hard_link(&path, &alias)?;
        assert_code(
            store.seal_legacy_replay_source(&binding),
            "runtime_replay_source_invalid",
        );
        if let Some(seal) = seal.as_ref() {
            assert_code(
                store.load_legacy_replay_source_seal(&binding),
                "runtime_replay_source_invalid",
            );
            assert_code(
                store.verify_legacy_replay_source_seal(seal),
                "runtime_replay_source_invalid",
            );
        }
        std::fs::remove_file(&alias)?;
        if let Some(seal) = seal.as_ref() {
            store.verify_legacy_replay_source_seal(seal)?;
        } else {
            store.seal_legacy_replay_source(&binding)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn symlink_path_cannot_seal_or_validate_the_target_as_its_own_source() -> TestResult {
    for initially_sealed in [false, true] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("target.sqlite3");
        let alias = directory.path().join("symlink.sqlite3");
        let store = SqliteRuntimeOrchestrationStore::open(&path)?;
        let binding = binding()?;
        let seal = initially_sealed
            .then(|| store.seal_legacy_replay_source(&binding))
            .transpose()?;
        std::os::unix::fs::symlink(&path, &alias)?;
        match SqliteRuntimeOrchestrationStore::open(&alias) {
            Err(error) => assert_eq!(error.code(), "runtime_replay_source_invalid"),
            Ok(aliased) => {
                assert!(
                    !initially_sealed,
                    "opening a sealed source through a symlink must reject"
                );
                assert_code(
                    aliased.seal_legacy_replay_source(&binding),
                    "runtime_replay_source_invalid",
                );
            }
        }
        if let Some(seal) = seal.as_ref() {
            store.verify_legacy_replay_source_seal(seal)?;
        } else {
            assert!(store.load_legacy_replay_source_seal(&binding)?.is_none());
            store.seal_legacy_replay_source(&binding)?;
        }
    }
    Ok(())
}
