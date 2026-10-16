#![cfg(feature = "sqlite")]

use chio_revocation_oracle::{
    EpochNonce, InMemoryRevocationOracle, RevocationKey, RevocationLeaf, RevocationOracle,
    RevocationOracleError, SqliteRevocationOracle, SqliteRevocationOracleError, SubjectId,
    MAX_REVOCATION_SUBJECT_BYTES,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn key(subject: &str, nonce: u64) -> RevocationKey {
    RevocationKey::new(SubjectId::from(subject), EpochNonce::new(nonce))
}

#[test]
fn the_root_survives_a_reopen_and_matches_the_in_memory_oracle() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("oracle.sqlite3");
    let mut reference = InMemoryRevocationOracle::new();
    {
        let oracle = SqliteRevocationOracle::open(&path)?;
        for (index, subject) in ["passport-a", "passport-b", "passport-c"]
            .iter()
            .enumerate()
        {
            let nonce = u64::MAX - u64::try_from(index)?;
            let now = 1_000 + u64::try_from(index)?;
            let durable = oracle.revoke(key(subject, nonce), now)?;
            assert_eq!(durable, reference.insert(key(subject, nonce), now)?);
        }
    }
    let reopened = SqliteRevocationOracle::open(&path)?;
    assert_eq!(reopened.current_epoch_root()?, reference.epoch_root());
    assert!(reopened.is_revoked(&key("passport-b", u64::MAX - 1))?);
    assert!(!reopened.is_revoked(&key("passport-b", 0))?);
    let proof = reopened.prove_inclusion(&key("passport-c", u64::MAX - 2))?;
    InMemoryRevocationOracle::verify_inclusion(&proof)?;
    Ok(())
}

#[test]
fn the_full_timestamp_range_round_trips() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("oracle.sqlite3");
    let root = SqliteRevocationOracle::open(&path)?.revoke(key("passport-a", 1), u64::MAX)?;
    assert_eq!(root.issued_at_unix_ms, u64::MAX);
    assert_eq!(
        SqliteRevocationOracle::open(&path)?.current_epoch_root()?,
        root
    );
    Ok(())
}

#[test]
fn a_second_handle_observes_revocations_without_reopening() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("oracle.sqlite3");
    let door = SqliteRevocationOracle::open(&path)?;
    let issuer = SqliteRevocationOracle::open(&path)?;
    assert!(!door.is_revoked(&key("passport-a", 7))?);

    let first = issuer.revoke(key("passport-a", 7), 10)?;
    assert!(door.is_revoked(&key("passport-a", 7))?);
    assert_eq!(door.current_epoch_root()?, first);

    let second = door.revoke(key("passport-b", 7), 20)?;
    assert_eq!(issuer.current_epoch_root()?, second);
    assert_eq!(second.leaf_count, 2);
    Ok(())
}

#[test]
fn a_repeated_revocation_is_refused_and_changes_nothing() -> TestResult {
    let oracle = SqliteRevocationOracle::open_in_memory()?;
    let root = oracle.revoke(key("passport-a", 1), 10)?;
    assert_eq!(
        oracle.revoke(key("passport-a", 1), 20),
        Err(SqliteRevocationOracleError::Oracle(
            RevocationOracleError::AlreadyRevoked
        ))
    );
    assert_eq!(oracle.current_epoch_root()?, root);
    Ok(())
}

#[test]
fn a_failed_transaction_publishes_nothing() -> TestResult {
    let oracle = SqliteRevocationOracle::open_in_memory()?;
    let root = oracle.revoke(key("passport-a", 1), 10)?;
    let failed = oracle.transact(20, |txn| {
        txn.revoke(&key("passport-b", 1))?;
        Err::<(), _>(SqliteRevocationOracleError::CorruptRecord(
            "abandoned".to_owned(),
        ))
    });
    assert!(failed.is_err());
    assert!(!oracle.is_revoked(&key("passport-b", 1))?);
    assert_eq!(oracle.current_epoch_root()?, root);
    Ok(())
}

#[test]
fn oversized_and_unpadded_subjects_are_refused() -> TestResult {
    let oracle = SqliteRevocationOracle::open_in_memory()?;
    let long = "s".repeat(MAX_REVOCATION_SUBJECT_BYTES + 1);
    assert_eq!(
        oracle.revoke(key(&long, 1), 10),
        Err(SqliteRevocationOracleError::SubjectTooLong)
    );
    assert!(matches!(
        oracle.revoke(key(" padded", 1), 10),
        Err(SqliteRevocationOracleError::Oracle(
            RevocationOracleError::InvalidRevocationKey(_)
        ))
    ));
    assert_eq!(oracle.current_epoch_root()?.leaf_count, 0);
    Ok(())
}

#[test]
fn foreign_and_unsupported_databases_are_refused() -> TestResult {
    let dir = tempfile::tempdir()?;
    let foreign = dir.path().join("foreign.sqlite3");
    rusqlite::Connection::open(&foreign)?.execute_batch("CREATE TABLE other (x INTEGER);")?;
    assert_eq!(
        SqliteRevocationOracle::open(&foreign).err(),
        Some(SqliteRevocationOracleError::UnstampedDatabase)
    );

    let stale = dir.path().join("stale.sqlite3");
    SqliteRevocationOracle::open(&stale)?;
    let raw = rusqlite::Connection::open(&stale)?;
    raw.execute_batch(
        "PRAGMA ignore_check_constraints = ON;
         UPDATE chio_revocation_oracle_meta SET schema_version = 2;",
    )?;
    assert_eq!(
        SqliteRevocationOracle::open(&stale).err(),
        Some(SqliteRevocationOracleError::UnsupportedSchema(2))
    );
    Ok(())
}

#[test]
fn a_corrupt_leaf_refuses_the_replay_and_reports_revoked() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("oracle.sqlite3");
    let door = SqliteRevocationOracle::open(&path)?;
    door.revoke(key("passport-a", 1), 10)?;
    rusqlite::Connection::open(&path)?.execute(
        "INSERT INTO chio_revocation_oracle_leaves (subject, epoch_nonce, inserted_at_unix_ms)
         VALUES (' padded', zeroblob(8), zeroblob(8))",
        [],
    )?;

    assert!(matches!(
        door.is_revoked(&key("passport-b", 1)),
        Err(SqliteRevocationOracleError::CorruptRecord(_))
    ));
    assert!(RevocationOracle::contains(&door, &key("passport-b", 1)));
    assert!(matches!(
        SqliteRevocationOracle::open(&path).err(),
        Some(SqliteRevocationOracleError::CorruptRecord(_))
    ));
    Ok(())
}

#[test]
fn byte_bounds_hold_at_the_storage_layer() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("oracle.sqlite3");
    SqliteRevocationOracle::open(&path)?;
    let raw = rusqlite::Connection::open(&path)?;
    for (subject, nonce) in [
        ("x".repeat(4097), vec![0_u8; 8]),
        (String::new(), vec![0_u8; 8]),
        ("passport".to_owned(), vec![0_u8; 7]),
        ("pass\u{0}port".to_owned(), vec![0_u8; 8]),
    ] {
        assert!(raw
            .execute(
                "INSERT INTO chio_revocation_oracle_leaves
                    (subject, epoch_nonce, inserted_at_unix_ms) VALUES (?1, ?2, zeroblob(8))",
                rusqlite::params![subject, nonce],
            )
            .is_err());
    }
    Ok(())
}

#[test]
fn malformed_utf8_subjects_are_refused_at_the_storage_layer() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("oracle.sqlite3");
    SqliteRevocationOracle::open(&path)?;
    let raw = rusqlite::Connection::open(&path)?;
    let malformed = raw.execute(
        "INSERT INTO chio_revocation_oracle_leaves
            (subject, epoch_nonce, inserted_at_unix_ms)
         VALUES (CAST(unhex(replace(hex(zeroblob(16385)), '00', '80')) AS TEXT),
                 zeroblob(8), zeroblob(8))",
        [],
    );
    assert!(
        matches!(
            malformed,
            Err(rusqlite::Error::SqliteFailure(ref error, _))
                if error.code == rusqlite::ErrorCode::ConstraintViolation
        ),
        "{malformed:?}"
    );
    raw.execute(
        "INSERT INTO chio_revocation_oracle_leaves
            (subject, epoch_nonce, inserted_at_unix_ms)
         VALUES (CAST(x'80ff' AS TEXT), zeroblob(8), zeroblob(8))",
        [],
    )?;
    assert!(matches!(
        SqliteRevocationOracle::open(&path).err(),
        Some(SqliteRevocationOracleError::Storage(_))
    ));
    Ok(())
}

#[test]
fn leaves_page_in_sequence_order_from_a_cursor() -> TestResult {
    let oracle = SqliteRevocationOracle::open_in_memory()?;
    oracle.revoke(key("passport-a", 1), 10)?;
    oracle.revoke(key("passport-b", 2), 20)?;
    oracle.revoke(key("passport-c", 3), 30)?;

    let first = oracle.leaves_after(0, 2)?;
    assert_eq!(
        first,
        vec![
            RevocationLeaf {
                seq: 1,
                key: key("passport-a", 1),
                inserted_at_unix_ms: 10,
            },
            RevocationLeaf {
                seq: 2,
                key: key("passport-b", 2),
                inserted_at_unix_ms: 20,
            },
        ]
    );
    let rest = oracle.leaves_after(2, 2)?;
    assert_eq!(
        rest,
        vec![RevocationLeaf {
            seq: 3,
            key: key("passport-c", 3),
            inserted_at_unix_ms: 30,
        }]
    );
    assert!(oracle.leaves_after(3, 2)?.is_empty());
    Ok(())
}

#[test]
fn the_staged_root_is_the_root_the_transaction_commits() -> TestResult {
    let oracle = SqliteRevocationOracle::open_in_memory()?;
    oracle.revoke(key("passport-a", 1), 10)?;
    let (staged, committed) = oracle.transact(20, |txn| {
        txn.revoke(&key("passport-b", 1))?;
        Ok(txn.epoch_root())
    })?;
    assert_eq!(staged, committed);
    assert_eq!(committed.leaf_count, 2);
    Ok(())
}
