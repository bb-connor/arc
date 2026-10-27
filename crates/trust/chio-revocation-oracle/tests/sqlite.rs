#![cfg(feature = "sqlite")]

use chio_revocation_oracle::{
    credential_revocation_key, passport_revocation_key, EpochNonce, EpochRoot,
    InMemoryRevocationOracle, PassportRevocationLeaf, PassportRevocationLeafError,
    PassportRevocationLeafKind, RevocationKey, RevocationLeaf, RevocationOracle,
    RevocationOracleError, SignedEpochRoot, SqliteRevocationOracle, SqliteRevocationOracleError,
    SubjectId, MAX_REVOCATION_SUBJECT_BYTES,
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

fn leaf(seq: u64, subject: &str, nonce: u64, inserted_at_unix_ms: u64) -> RevocationLeaf {
    RevocationLeaf {
        seq,
        key: key(subject, nonce),
        inserted_at_unix_ms,
    }
}

#[test]
fn leaves_after_pages_in_sequence_order_within_the_limit() -> TestResult {
    let oracle = SqliteRevocationOracle::open_in_memory()?;
    oracle.revoke(key("passport-a", 1), 10)?;
    oracle.revoke(key("passport-b", 2), 20)?;
    oracle.revoke(key("passport-c", 3), 30)?;

    assert_eq!(
        oracle.leaves_after(0, 2)?,
        vec![leaf(1, "passport-a", 1, 10), leaf(2, "passport-b", 2, 20)]
    );
    assert_eq!(
        oracle.leaves_after(2, 2)?,
        vec![leaf(3, "passport-c", 3, 30)]
    );
    assert!(oracle.leaves_after(3, 2)?.is_empty());
    assert!(oracle.leaves_after(0, 0)?.is_empty());
    assert!(matches!(
        oracle.leaves_after(u64::MAX, 1),
        Err(SqliteRevocationOracleError::CursorOutOfRange(u64::MAX))
    ));
    Ok(())
}

#[test]
fn leaves_are_numbered_densely_from_one_across_transactions() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("oracle.sqlite3");
    let first = SqliteRevocationOracle::open(&path)?;
    let second = SqliteRevocationOracle::open(&path)?;
    first.transact(10, |txn| {
        txn.revoke(&key("passport-a", 1))?;
        txn.revoke(&key("passport-b", 1))?;
        Ok(())
    })?;
    second.revoke(key("passport-c", 1), 20)?;
    first.revoke(key("passport-d", 1), 30)?;

    let seqs = SqliteRevocationOracle::open(&path)?
        .leaves_after(0, 16)?
        .into_iter()
        .map(|leaf| leaf.seq)
        .collect::<Vec<_>>();
    assert_eq!(seqs, vec![1, 2, 3, 4]);
    assert_eq!(second.current_epoch_root()?.leaf_count, 4);
    Ok(())
}

#[test]
fn a_rolled_back_transaction_leaves_no_gap_in_seq() -> TestResult {
    let oracle = SqliteRevocationOracle::open_in_memory()?;
    oracle.revoke(key("passport-a", 1), 10)?;
    let refused = oracle.transact(20, |txn| {
        txn.revoke(&key("passport-b", 1))?;
        txn.revoke(&key("passport-c", 1))?;
        Err::<(), _>(SqliteRevocationOracleError::Storage("refused".to_string()))
    });
    assert!(refused.is_err());
    oracle.revoke(key("passport-d", 1), 30)?;

    assert_eq!(
        oracle.leaves_after(0, 16)?,
        vec![leaf(1, "passport-a", 1, 10), leaf(2, "passport-d", 1, 30)]
    );
    assert!(!oracle.is_revoked(&key("passport-b", 1))?);
    Ok(())
}

#[test]
fn a_gap_in_the_stored_sequence_is_refused_as_corrupt() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("oracle.sqlite3");
    SqliteRevocationOracle::open(&path)?.revoke(key("passport-a", 1), 10)?;
    rusqlite::Connection::open(&path)?.execute(
        "UPDATE chio_revocation_oracle_leaves SET seq = 2 WHERE seq = 1",
        [],
    )?;
    assert!(matches!(
        SqliteRevocationOracle::open(&path),
        Err(SqliteRevocationOracleError::CorruptRecord(_))
    ));
    Ok(())
}

#[test]
fn the_staged_root_includes_keys_revoked_in_the_open_transaction() -> TestResult {
    let oracle = SqliteRevocationOracle::open_in_memory()?;
    oracle.revoke(key("passport-a", 1), 10)?;
    let ((before, staged), committed) = oracle.transact(20, |txn| {
        let before = txn.epoch_root();
        txn.revoke(&key("passport-b", 1))?;
        Ok((before, txn.epoch_root()))
    })?;
    assert_eq!(before.leaf_count, 1);
    assert_eq!(staged, committed);
    assert_eq!(committed.leaf_count, 2);
    assert_eq!(oracle.current_epoch_root()?, committed);
    Ok(())
}

#[test]
fn an_epoch_root_with_an_unknown_field_is_refused() -> TestResult {
    let root = SqliteRevocationOracle::open_in_memory()?.revoke(key("passport-a", 1), 10)?;
    let mut value = serde_json::to_value(&root)?;
    assert_eq!(serde_json::from_value::<EpochRoot>(value.clone())?, root);
    value
        .as_object_mut()
        .ok_or("an epoch root encodes as an object")?
        .insert("extra".to_string(), serde_json::json!(true));
    assert!(serde_json::from_value::<EpochRoot>(value).is_err());
    Ok(())
}

#[test]
fn a_signed_root_with_an_unknown_nested_field_is_refused() -> TestResult {
    let root = SqliteRevocationOracle::open_in_memory()?.revoke(key("passport-a", 1), 10)?;
    let signed = serde_json::json!({
        "root": serde_json::to_value(&root)?,
        "signature": {
            "signer_id": "operator",
            "algorithm": "ed25519",
            "signature_bytes": [1, 2, 3],
        },
    });
    serde_json::from_value::<SignedEpochRoot>(signed.clone())?;
    for (path, field) in [("", "extra"), ("root", "extra"), ("signature", "extra")] {
        let mut value = signed.clone();
        let target = if path.is_empty() {
            &mut value
        } else {
            value.get_mut(path).ok_or("nested member")?
        };
        target
            .as_object_mut()
            .ok_or("nested object")?
            .insert(field.to_string(), serde_json::json!(0));
        assert!(
            serde_json::from_value::<SignedEpochRoot>(value).is_err(),
            "an unknown field under `{path}` must be refused"
        );
    }
    Ok(())
}

#[test]
fn a_leaf_projects_to_seq_kind_and_subject_with_the_nonce_from_the_kind() -> TestResult {
    let digest = "ab".repeat(32);
    let oracle = SqliteRevocationOracle::open_in_memory()?;
    oracle.transact(10, |txn| {
        txn.revoke(&passport_revocation_key("passport-a"))?;
        txn.revoke(&credential_revocation_key(&digest))?;
        Ok(())
    })?;
    let leaves = oracle
        .leaves_after(0, 16)?
        .iter()
        .map(PassportRevocationLeaf::from_oracle_leaf)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        leaves,
        vec![
            PassportRevocationLeaf {
                seq: 1,
                kind: PassportRevocationLeafKind::Passport,
                subject: "passport-a".to_string(),
            },
            PassportRevocationLeaf {
                seq: 2,
                kind: PassportRevocationLeafKind::Credential,
                subject: digest.clone(),
            },
        ]
    );
    assert_eq!(
        serde_json::to_value(&leaves)?,
        serde_json::json!([
            {"seq": 1, "kind": "passport", "subject": "passport-a"},
            {"seq": 2, "kind": "credential", "subject": digest},
        ])
    );
    assert_eq!(
        leaves[1].to_revocation_key(),
        credential_revocation_key(&digest)
    );
    Ok(())
}

#[test]
fn a_leaf_with_a_nonce_outside_the_kind_table_is_unpublishable() -> TestResult {
    let oracle = SqliteRevocationOracle::open_in_memory()?;
    oracle.revoke(key("passport-a", 7), 10)?;
    let leaves = oracle.leaves_after(0, 1)?;
    let stored = leaves.first().ok_or("one leaf")?;
    assert_eq!(
        PassportRevocationLeaf::from_oracle_leaf(stored),
        Err(PassportRevocationLeafError::UnpublishableLeaf { seq: 1 })
    );
    Ok(())
}

#[test]
fn a_leaf_document_with_an_unknown_field_or_kind_is_refused() -> TestResult {
    let valid = serde_json::json!({"seq": 1, "kind": "passport", "subject": "passport-a"});
    serde_json::from_value::<PassportRevocationLeaf>(valid)?;
    for refused in [
        serde_json::json!({"seq": 1, "kind": "passport", "subject": "passport-a", "epochNonce": 1}),
        serde_json::json!({"seq": 1, "kind": "capability", "subject": "passport-a"}),
        serde_json::json!({"seq": 1, "subject": "passport-a"}),
    ] {
        assert!(serde_json::from_value::<PassportRevocationLeaf>(refused).is_err());
    }
    Ok(())
}
