use super::*;
use std::collections::BTreeSet;
use std::sync::{Arc, Barrier};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn rotation_rolls_back_seed_head_and_history_when_trust_insert_fails() -> TestResult {
    let directory = tempfile::tempdir()?;
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
    let directory = tempfile::tempdir()?;
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
    let directory = tempfile::tempdir()?;
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
        if field == "key-bytes" {
            assert!(matches!(result, Err(AuthorityStoreError::Core(_))));
        } else if field == "zero-generation" {
            assert!(
                matches!(result, Err(AuthorityStoreError::Fence(message)) if message == "authority generation must be positive")
            );
        } else {
            assert!(
                matches!(result, Err(AuthorityStoreError::Fence(message)) if message.contains("exceeds SQLite INTEGER range"))
            );
        }
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
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("authority.db");
    let authority = SqliteCapabilityAuthority::open(&path)?;
    let connection = Connection::open(&path)?;
    connection.execute("UPDATE authority_state SET generation = ?1", [i64::MAX])?;
    let before = authority.snapshot()?;
    let seed_before = authority.local_keypair()?.seed_hex();
    assert!(
        matches!(authority.rotate(), Err(AuthorityStoreError::Fence(message))
        if message == "authority generation exceeds SQLite INTEGER range")
    );
    assert_eq!(authority.snapshot()?, before);
    assert_eq!(authority.local_keypair()?.seed_hex(), seed_before);
    Ok(())
}

#[test]
fn failed_snapshot_head_write_rolls_back_already_inserted_history() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("authority.db");
    let authority = SqliteCapabilityAuthority::open(&path)?;
    let before = authority.snapshot()?;
    let seed_before = authority.local_keypair()?.seed_hex();
    let connection = Connection::open(&path)?;
    connection.execute_batch(
        "CREATE TRIGGER fail_head BEFORE UPDATE ON authority_state
         BEGIN SELECT RAISE(ABORT, 'injected head write failure'); END;",
    )?;
    let remote_key = Keypair::generate().public_key();
    let snapshot = AuthoritySnapshot {
        public_key_hex: remote_key.to_hex(),
        generation: before.generation + 1,
        rotated_at: before.rotated_at,
        trusted_keys: vec![AuthorityTrustedKeySnapshot {
            public_key_hex: Keypair::generate().public_key().to_hex(),
            generation: 1,
            activated_at: 0,
        }],
    };
    assert!(matches!(authority.apply_snapshot(&snapshot),
        Err(AuthorityStoreError::Sqlite(rusqlite::Error::SqliteFailure(error, Some(message))))
        if error.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_TRIGGER && message == "injected head write failure"));
    assert_eq!(authority.snapshot()?, before);
    assert_eq!(
        authority.authority_public_key().to_hex(),
        before.public_key_hex
    );
    assert_eq!(authority.local_keypair()?.seed_hex(), seed_before);
    connection.execute_batch("DROP TRIGGER fail_head")?;
    assert!(authority.apply_snapshot(&snapshot)?);
    assert_eq!(authority.authority_public_key(), remote_key);
    assert_eq!(authority.snapshot()?.trusted_keys.len(), 3);
    assert_eq!(authority.local_keypair()?.seed_hex(), seed_before);
    assert!(
        matches!(authority.current_keypair(), Err(AuthorityStoreError::Fence(message))
        if message.contains("does not match replicated authority public key"))
    );
    Ok(())
}

#[test]
fn same_term_competing_leaders_have_exactly_one_winner() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("authority.db");
    let authority = SqliteCapabilityAuthority::open(&path)?;
    let barrier = Arc::new(Barrier::new(9));
    let mut threads = Vec::new();
    for index in 0..8 {
        let handle = SqliteCapabilityAuthority::open(&path)?;
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
    let directory = tempfile::tempdir()?;
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
    let directory = tempfile::tempdir()?;
    let authority = SqliteCapabilityAuthority::open(directory.path().join("authority.db"))?;
    assert!(
        matches!(authority.issue_capability(&Keypair::generate().public_key(), ChioScope::default(), u64::MAX),
        Err(KernelError::CapabilityIssuanceFailed(message)) if message == "capability expiry overflows the timestamp domain")
    );
    Ok(())
}
