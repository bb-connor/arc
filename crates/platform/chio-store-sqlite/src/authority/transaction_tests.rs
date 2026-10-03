use super::*;
use std::collections::BTreeSet;
use std::sync::{Arc, Barrier};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn incomplete_legacy_authority_history_is_refused_without_inventing_issuers() -> TestResult {
    for empty_table in [false, true] {
        let directory = chio_test_support::private_tempdir()?;
        let path = directory.path().join("legacy.db");
        let key = Keypair::generate();
        let connection = Connection::open(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        connection.execute_batch(
            "CREATE TABLE authority_state (
                singleton_id INTEGER PRIMARY KEY, seed_hex TEXT NOT NULL,
                generation INTEGER NOT NULL, rotated_at INTEGER NOT NULL
            );",
        )?;
        connection.execute(
            "INSERT INTO authority_state VALUES (1, ?1, 1, 100)",
            [key.seed_hex()],
        )?;
        if empty_table {
            connection.execute_batch(
                "CREATE TABLE authority_trusted_keys (
                    public_key_hex TEXT PRIMARY KEY, generation INTEGER NOT NULL,
                    activated_at INTEGER NOT NULL
                );",
            )?;
        }
        assert!(matches!(
            SqliteCapabilityAuthority::open(&path),
            Err(AuthorityStoreError::Schema(message))
                if message.contains("authority head is absent from persisted issuer history")
        ));
        let seed: String = connection.query_row(
            "SELECT seed_hex FROM authority_state WHERE singleton_id = 1",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(seed, key.seed_hex());
        let count: i64 =
            connection.query_row("SELECT count(*) FROM authority_trusted_keys", [], |row| {
                row.get(0)
            })?;
        assert_eq!(
            count, 0,
            "opening must not manufacture legacy issuer history"
        );
    }
    Ok(())
}

#[test]
fn complete_legacy_authority_history_survives_explicit_checkpoint_migration() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("legacy.db");
    let key = Keypair::generate();
    let connection = Connection::open(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    connection.execute_batch(
        "CREATE TABLE authority_state (
            singleton_id INTEGER PRIMARY KEY, seed_hex TEXT NOT NULL,
            generation INTEGER NOT NULL, rotated_at INTEGER NOT NULL
        );
        CREATE TABLE authority_trusted_keys (
            public_key_hex TEXT PRIMARY KEY, generation INTEGER NOT NULL,
            activated_at INTEGER NOT NULL
        );",
    )?;
    connection.execute(
        "INSERT INTO authority_state VALUES (1, ?1, 1, 100)",
        [key.seed_hex()],
    )?;
    connection.execute(
        "INSERT INTO authority_trusted_keys VALUES (?1, 1, 100)",
        [key.public_key().to_hex()],
    )?;
    let authority = SqliteCapabilityAuthority::open(&path)?;
    assert_eq!(authority.trusted_public_keys(), vec![key.public_key()]);
    assert_eq!(authority.local_keypair()?.seed_hex(), key.seed_hex());
    assert!(
        authority.signed_snapshot().is_err(),
        "opening does not grant network trust"
    );
    let anchor = authority.initialize_replication("legacy-reviewed-checkpoint")?;
    assert_eq!(anchor.snapshot.trusted_keys.len(), 1);
    assert_eq!(anchor.snapshot.rotated_at, 100);
    assert!(authority.signed_snapshot()?.proof.is_some());
    Ok(())
}

#[test]
fn rotation_rolls_back_seed_head_and_history_when_trust_insert_fails() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("authority.db");
    let authority = SqliteCapabilityAuthority::open(&path)?;
    let before = authority.snapshot()?;
    let seed_before = authority.local_keypair()?.seed_hex();
    let connection = Connection::open(&path)?;
    connection.execute_batch(
        "CREATE TRIGGER fail_trust BEFORE INSERT ON authority_trusted_keys
        BEGIN SELECT RAISE(ABORT, 'injected trust write failure'); END;",
    )?;
    assert!(
        matches!(authority.rotate(), Err(AuthorityStoreError::Sqlite(rusqlite::Error::SqliteFailure(error, Some(message))))
        if error.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_TRIGGER && message == "injected trust write failure")
    );
    assert_eq!(authority.snapshot()?, before);
    assert_eq!(authority.local_keypair()?.seed_hex(), seed_before);
    assert_eq!(
        authority.authority_public_key().to_hex(),
        before.public_key_hex
    );
    connection.execute_batch("DROP TRIGGER fail_trust")?;
    assert_eq!(authority.rotate()?.generation, before.generation + 1);
    drop(authority);
    assert_eq!(
        SqliteCapabilityAuthority::open(&path)?.status()?.generation,
        before.generation + 1
    );
    Ok(())
}

#[test]
fn concurrent_rotations_allocate_unique_generations_and_keep_all_keys() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("authority.db");
    let authority = SqliteCapabilityAuthority::open(&path)?;
    let barrier = Arc::new(Barrier::new(9));
    let mut threads = Vec::new();
    for _ in 0..8 {
        let handle = SqliteCapabilityAuthority::open(&path)?;
        let start = Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            start.wait();
            handle.rotate()
        }));
    }
    barrier.wait();
    let mut generations = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for thread in threads {
        let status = thread.join().map_err(|_| "rotation thread panicked")??;
        generations.insert(status.generation);
        keys.insert(status.public_key.to_hex());
    }
    assert_eq!(generations, (2..=9).collect());
    assert_eq!(keys.len(), 8);
    let snapshot = authority.snapshot()?;
    assert_eq!(snapshot.generation, 9);
    assert_eq!(snapshot.trusted_keys.len(), 9);
    assert!(keys.iter().all(|key| snapshot
        .trusted_keys
        .iter()
        .any(|row| &row.public_key_hex == key)));
    Ok(())
}

#[test]
fn snapshot_refuses_invalid_late_rows_without_partial_trust_or_head_changes() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let authority = SqliteCapabilityAuthority::open(directory.path().join("authority.db"))?;
    let before = authority.snapshot()?;
    let seed_before = authority.local_keypair()?.seed_hex();
    for field in [
        "head-generation",
        "head-time",
        "key-generation",
        "key-time",
        "key-bytes",
        "zero-generation",
    ] {
        let mut snapshot = AuthoritySnapshot {
            public_key_hex: Keypair::generate().public_key().to_hex(),
            generation: 2,
            rotated_at: 10,
            trusted_keys: vec![AuthorityTrustedKeySnapshot {
                public_key_hex: Keypair::generate().public_key().to_hex(),
                generation: 1,
                activated_at: 5,
                lifecycle: None,
            }],
        };
        match field {
            "head-generation" => snapshot.generation = u64::MAX,
            "head-time" => snapshot.rotated_at = u64::MAX,
            "key-generation" => snapshot.trusted_keys[0].generation = u64::MAX,
            "key-time" => snapshot.trusted_keys[0].activated_at = u64::MAX,
            "key-bytes" => snapshot.trusted_keys[0].public_key_hex = "invalid".into(),
            "zero-generation" => snapshot.trusted_keys[0].generation = 0,
            _ => unreachable!(),
        }
        let result = authority.apply_snapshot(&snapshot);
        assert!(
            matches!(result, Err(AuthorityStoreError::Fence(message)) if message == "unsigned authority snapshot")
        );
        assert_eq!(
            authority.snapshot()?,
            before,
            "failed {field} import changed state"
        );
        assert_eq!(authority.local_keypair()?.seed_hex(), seed_before);
    }
    Ok(())
}

#[test]
fn generation_exhaustion_does_not_rotate_or_lose_the_signing_seed() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("authority.db");
    let authority = SqliteCapabilityAuthority::open(&path)?;
    let connection = Connection::open(&path)?;
    connection.execute("UPDATE authority_state SET generation = ?1", [i64::MAX])?;
    connection.execute(
        "UPDATE authority_trusted_keys SET generation = ?1",
        [i64::MAX],
    )?;
    let before = authority.snapshot()?;
    chio_kernel::authority::replication::validate_state(&before)?;
    let seed_before = authority.local_keypair()?.seed_hex();
    assert!(
        matches!(authority.rotate(), Err(AuthorityStoreError::Fence(message))
        if message == "invalid authority state bounds")
    );
    assert_eq!(authority.snapshot()?, before);
    assert_eq!(authority.local_keypair()?.seed_hex(), seed_before);
    Ok(())
}

#[test]
fn failed_snapshot_head_write_rolls_back_already_inserted_history() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let source = SqliteCapabilityAuthority::open(directory.path().join("source.db"))?;
    let path = directory.path().join("follower.db");
    let authority = SqliteCapabilityAuthority::open(&path)?;
    authority.pin_replication_anchor(&source.initialize_replication("test-atomic-import")?)?;
    let before = authority.snapshot()?;
    let seed_before = authority.local_keypair()?.seed_hex();
    source.rotate()?;
    let snapshot = source.signed_snapshot()?;
    let connection = Connection::open(&path)?;
    connection.execute_batch("CREATE TRIGGER fail_head BEFORE UPDATE ON authority_state BEGIN SELECT RAISE(ABORT, 'injected head write failure'); END;")?;
    assert!(matches!(
        authority.apply_signed_snapshot(&snapshot),
        Err(AuthorityStoreError::Sqlite(_))
    ));
    assert_eq!(authority.snapshot()?, before);
    assert_eq!(authority.local_keypair()?.seed_hex(), seed_before);
    connection.execute_batch("DROP TRIGGER fail_head")?;
    assert!(authority.apply_signed_snapshot(&snapshot)?);
    assert_eq!(authority.snapshot()?, source.snapshot()?);
    assert_eq!(authority.local_keypair()?.seed_hex(), seed_before);
    assert!(authority.current_keypair().is_err());
    Ok(())
}

#[test]
fn same_term_competing_leaders_have_exactly_one_winner() -> TestResult {
    use chio_security_types::clock::FixedClock;

    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("authority.db");
    let clock = Arc::new(FixedClock::new(100));
    let authority = SqliteCapabilityAuthority::open_with_clock(&path, clock.clone())?;
    let barrier = Arc::new(Barrier::new(9));
    let mut threads = Vec::new();
    for index in 0..8 {
        let handle = SqliteCapabilityAuthority::open_with_clock(&path, clock.clone())?;
        let start = Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            let leader = format!("https://leader-{index}");
            start.wait();
            let result = handle.enforce_cluster_fence(&leader, 7);
            (leader, result)
        }));
    }
    barrier.wait();
    let mut winners = Vec::new();
    for thread in threads {
        let (leader, result) = thread.join().map_err(|_| "fence thread panicked")?;
        match result {
            Ok(()) => winners.push(leader),
            Err(AuthorityStoreError::Fence(message)) => {
                assert!(message.contains("already fenced to leader"))
            }
            Err(error) => return Err(error.into()),
        }
    }
    assert_eq!(winners.len(), 1);
    let fence = authority.cluster_fence()?;
    assert_eq!(fence.election_term, 7);
    assert_eq!(fence.leader_url.as_ref(), winners.first());
    authority.enforce_cluster_fence(&winners[0], 7)?;
    assert!(
        matches!(authority.seed_cluster_fence(Some("https://overflow"), u64::MAX),
        Err(AuthorityStoreError::Fence(message)) if message == "authority election term exceeds SQLite INTEGER range")
    );
    assert!(
        matches!(authority.enforce_cluster_fence("https://overflow", u64::MAX),
        Err(AuthorityStoreError::Fence(message)) if message == "authority election term exceeds SQLite INTEGER range")
    );
    assert_eq!(authority.cluster_fence()?, fence);
    Ok(())
}

#[test]
fn negative_persisted_metadata_is_refused_instead_of_clamped() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("authority.db");
    let authority = SqliteCapabilityAuthority::open(&path)?;
    let connection = Connection::open(&path)?;
    for (table, field) in [
        ("authority_state", "generation"),
        ("authority_state", "rotated_at"),
        ("authority_trusted_keys", "generation"),
        ("authority_trusted_keys", "activated_at"),
        ("authority_cluster_fence", "election_term"),
        ("authority_cluster_fence", "updated_at"),
        ("authority_cluster_fence", "authority_generation"),
        ("authority_cluster_fence", "authority_rotated_at"),
    ] {
        let previous: i64 =
            connection.query_row(&format!("SELECT {field} FROM {table}"), [], |row| {
                row.get(0)
            })?;
        connection.execute(&format!("UPDATE {table} SET {field} = -1"), [])?;
        let result = if table == "authority_cluster_fence" {
            authority.cluster_fence().map(|_| ())
        } else {
            authority.status().map(|_| ())
        };
        assert!(
            matches!(result, Err(AuthorityStoreError::Fence(message)) if message.contains("must be nonnegative")),
            "{table}.{field}"
        );
        connection.execute(&format!("UPDATE {table} SET {field} = ?1"), [previous])?;
    }
    assert!(authority.current_keypair()?.public_key() == authority.status()?.public_key);
    Ok(())
}

#[test]
fn capability_issuance_refuses_overflowing_expiry() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let authority = SqliteCapabilityAuthority::open(directory.path().join("authority.db"))?;
    let before = authority.snapshot()?;
    let seed_before = authority.local_keypair()?.seed_hex();
    let expected =
        AuthorityStoreError::Fence("capability expiry overflows the timestamp domain".into())
            .to_string();
    assert!(
        matches!(authority.issue_capability(&Keypair::generate().public_key(), ChioScope::default(), u64::MAX),
        Err(KernelError::CapabilityIssuanceFailed(message)) if message == expected)
    );
    assert_eq!(authority.snapshot()?, before);
    assert_eq!(authority.local_keypair()?.seed_hex(), seed_before);
    Ok(())
}

#[test]
fn injected_clock_failure_preserves_authority_and_cluster_fence() -> TestResult {
    use chio_security_types::clock::{Clock, ClockError, ClockReading, FixedClock};
    use std::sync::atomic::{AtomicBool, Ordering};
    struct ControlledClock(AtomicBool);
    impl Clock for ControlledClock {
        fn read(&self) -> Result<ClockReading, ClockError> {
            if self.0.load(Ordering::SeqCst) {
                Err(ClockError::Unavailable)
            } else {
                FixedClock::new(1_000).read()
            }
        }
    }
    let root = chio_test_support::private_tempdir()?;
    let clock = Arc::new(ControlledClock(AtomicBool::new(false)));
    let authority =
        SqliteCapabilityAuthority::open_with_clock(root.path().join("clock.db"), clock.clone())?;
    let before = authority.snapshot()?;
    let fence = authority.cluster_fence()?;
    clock.0.store(true, Ordering::SeqCst);
    assert!(matches!(
        authority.rotate(),
        Err(AuthorityStoreError::Clock(ClockError::Unavailable))
    ));
    assert!(matches!(
        authority.enforce_cluster_fence("leader", 1),
        Err(AuthorityStoreError::Clock(ClockError::Unavailable))
    ));
    assert_eq!(authority.snapshot()?, before);
    assert_eq!(authority.cluster_fence()?, fence);
    clock.0.store(false, Ordering::SeqCst);
    assert_eq!(authority.rotate()?.generation, before.generation + 1);
    Ok(())
}

#[test]
fn unsigned_authority_snapshot_cannot_add_issuer_even_without_head_change() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let authority = SqliteCapabilityAuthority::open(directory.path().join("authority.db"))?;
    let before = authority.snapshot()?;
    let mut forged = before.clone();
    forged.trusted_keys.push(AuthorityTrustedKeySnapshot {
        public_key_hex: Keypair::generate().public_key().to_hex(),
        generation: 1,
        activated_at: before.rotated_at,
        lifecycle: None,
    });
    assert!(
        authority.apply_snapshot(&forged).is_err(),
        "unsigned issuer insertion must reject"
    );
    assert_eq!(authority.snapshot()?, before);
    Ok(())
}
