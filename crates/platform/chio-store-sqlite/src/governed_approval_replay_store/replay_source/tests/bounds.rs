use super::*;

#[test]
fn invalid_storage_rows_and_metadata_refuse_sealing_without_pruning() -> TestResult {
    for sql in [
        "UPDATE chio_governed_approval_replay_entries SET expires_at = -1",
        "UPDATE chio_governed_approval_replay_entries SET expires_at = 'invalid'",
        "UPDATE chio_governed_approval_replay_entries SET subject_id = x'80'",
        "UPDATE chio_governed_approval_replay_entries SET subject_id = ' padded'",
        "UPDATE chio_governed_approval_replay_entries SET request_id = char(0)",
        "UPDATE chio_governed_approval_replay_entries SET dispatch_reservation_id = ''",
        "UPDATE chio_governed_approval_replay_entries SET intent_hash = replace(hex(zeroblob(257)), '0', 'a')",
        "UPDATE chio_governed_approval_replay_clock SET pruned_through = wall_clock_high_water + 1",
        "UPDATE chio_governed_approval_replay_clock SET wall_clock_high_water = 'invalid'",
        "UPDATE chio_governed_approval_replay_limits SET capacity = 1.5",
        "DELETE FROM chio_governed_approval_replay_clock",
        "DELETE FROM chio_governed_approval_replay_limits",
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("approval.db");
        let store = SqliteGovernedApprovalReplayStore::open(&path)?;
        assert!(reserve(&store, "reserved")?);
        let expected = store.preview_legacy_replay_source(&binding()?)?;
        let connection = Connection::open(&path)?;
        connection.execute_batch(sql)?;
        assert!(store.preview_legacy_replay_source(&binding()?).is_err(), "{sql}");
        assert!(store.seal_expected_legacy_replay_source(&expected).is_err());
        assert!(!schema::has_evidence(&connection)?);
        assert_eq!(connection.query_row("SELECT COUNT(*) FROM chio_governed_approval_replay_entries", [], |row| row.get::<_, i64>(0))?, 1);
    }
    Ok(())
}

#[test]
fn oversized_inventory_is_refused_without_partial_evidence() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("approval.db");
    let store =
        SqliteGovernedApprovalReplayStore::open_with_capacity(&path, evidence::MAX_MARKERS + 1)?;
    let connection = Connection::open(&path)?;
    connection.execute_batch("WITH RECURSIVE ids(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM ids WHERE n < 16385)
        INSERT INTO chio_governed_approval_replay_entries SELECT 'subject', 'request-' || n, 'intent', 9223372036854775807, NULL FROM ids")?;
    assert!(store.preview_legacy_replay_source(&binding()?).is_err());
    assert!(!schema::has_evidence(&connection)?);
    Ok(())
}

#[test]
fn canonical_codec_rejects_unknown_fields_corruption_and_lossy_numbers() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("approval.db");
    let store = SqliteGovernedApprovalReplayStore::open(&path)?;
    assert!(reserve(&store, "reserved")?);
    Connection::open(&path)?.execute(
        "UPDATE chio_governed_approval_replay_entries SET expires_at = 9223372036854775807",
        [],
    )?;
    let snapshot = store.preview_legacy_replay_source(&binding()?)?;
    let value = read_value(&snapshot)?;
    assert_eq!(
        value["body"]["inventory"]["markers"][0]["expires_at"],
        i64::MAX.to_string()
    );
    assert_eq!(
        GovernedApprovalReplaySourceSnapshot::from_canonical_bytes(&snapshot.canonical_bytes()?)?,
        snapshot
    );
    let mut mutations = Vec::new();
    let mut changed = value.clone();
    changed["unexpected"] = true.into();
    mutations.push(changed);
    let mut changed = value.clone();
    changed["body"]["inventory"]["capacity"] = 8192.into();
    mutations.push(changed);
    let mut changed = value.clone();
    changed["body"]["inventory"]["capacity"] = "08192".into();
    mutations.push(changed);
    let mut changed = value.clone();
    changed["body"]["inventory"]["markers"][0]["expires_at"] = "9223372036854775808".into();
    mutations.push(changed);
    let mut changed = value.clone();
    changed["body"]["inventory"]["markers"][0]["intent_hash"] = "substituted".into();
    mutations.push(changed);
    for changed in mutations {
        let bytes = chio_core::canonical::canonical_json_bytes(&changed)?;
        assert!(GovernedApprovalReplaySourceSnapshot::from_canonical_bytes(&bytes).is_err());
    }
    assert!(GovernedApprovalReplaySourceSnapshot::from_canonical_bytes(
        &serde_json::to_vec_pretty(&value)?
    )
    .is_err());
    assert!(
        GovernedApprovalReplaySourceSnapshot::from_canonical_bytes(&vec![
            b' ';
            evidence::MAX_BYTES + 1
        ])
        .is_err()
    );
    Ok(())
}

#[test]
fn marker_payload_byte_bound_is_enforced_before_inventory_allocation() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("approval.db");
    let store = SqliteGovernedApprovalReplayStore::open(&path)?;
    let connection = Connection::open(&path)?;
    connection.execute_batch("WITH RECURSIVE ids(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM ids WHERE n < 6000)
        INSERT INTO chio_governed_approval_replay_entries SELECT replace(hex(zeroblob(256)), '0', 'a'),
            'request-' || n, replace(hex(zeroblob(256)), '0', 'b'), 9223372036854775807,
            replace(hex(zeroblob(256)), '0', 'c') FROM ids")?;
    assert!(store.preview_legacy_replay_source(&binding()?).is_err());
    assert!(!schema::has_evidence(&connection)?);
    Ok(())
}

#[test]
fn valid_digest_cannot_hide_duplicate_unordered_or_over_capacity_markers() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = SqliteGovernedApprovalReplayStore::open(directory.path().join("approval.db"))?;
    assert!(reserve(&store, "first")?);
    assert!(reserve(&store, "second")?);
    let snapshot = store.preview_legacy_replay_source(&binding()?)?;
    let original = read_value(&snapshot)?;
    for case in 0..5 {
        let mut changed = original.clone();
        match case {
            0 => {
                changed["body"]["inventory"]["markers"][1] =
                    changed["body"]["inventory"]["markers"][0].clone()
            }
            1 => {
                let first = changed["body"]["inventory"]["markers"][0].clone();
                changed["body"]["inventory"]["markers"][0] =
                    changed["body"]["inventory"]["markers"][1].clone();
                changed["body"]["inventory"]["markers"][1] = first;
            }
            2 => changed["body"]["inventory"]["capacity"] = "1".into(),
            3 => changed["body"]["inventory"]["capacity"] = "08192".into(),
            _ => changed["body"]["inventory"]["pruned_through"] = "-1".into(),
        }
        let mut bytes = b"chio:governed-approval-replay-source-inventory:v1\0".to_vec();
        bytes.extend(chio_core::canonical::canonical_json_bytes(
            &changed["body"],
        )?);
        changed["inventory_sha256"] = chio_core::sha256_hex(&bytes).into();
        let encoded = chio_core::canonical::canonical_json_bytes(&changed)?;
        assert!(GovernedApprovalReplaySourceSnapshot::from_canonical_bytes(&encoded).is_err());
    }
    Ok(())
}

#[test]
fn migrated_subjectless_markers_keep_wildcard_semantics_in_frozen_inventory() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("approval.db");
    let legacy = Connection::open(&path)?;
    legacy.execute_batch(
        "CREATE TABLE chio_governed_approval_replay_entries (
        request_id TEXT NOT NULL, intent_hash TEXT NOT NULL, expires_at INTEGER NOT NULL,
        dispatch_reservation_id TEXT, PRIMARY KEY(request_id, intent_hash));",
    )?;
    legacy.execute(
        "INSERT INTO chio_governed_approval_replay_entries VALUES ('reserved', 'intent', ?1, NULL)",
        [super::super::super::now_secs() + 3600],
    )?;
    drop(legacy);
    let store = SqliteGovernedApprovalReplayStore::open(&path)?;
    assert!(!reserve(&store, "reserved")?);
    assert!(!store.reserve_for_dispatch(
        "other-subject",
        "reserved",
        "intent",
        u64::MAX >> 1,
        "owner"
    )?);
    let expected = store.preview_legacy_replay_source(&binding()?)?;
    let value = read_value(&expected)?;
    assert_eq!(
        value["body"]["inventory"]["markers"][0]["subject_id"],
        super::super::super::LEGACY_UNSCOPED_SUBJECT_ID
    );
    store.seal_expected_legacy_replay_source(&expected)?;
    store.verify_legacy_replay_source_seal(&expected)?;
    Ok(())
}
