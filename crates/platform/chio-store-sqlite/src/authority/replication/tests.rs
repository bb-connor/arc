use super::*;
use chio_kernel::authority::replication::AuthorityEnvelopeClockPolicy;
use chio_security_types::clock::{Clock, ClockReading, FixedClock};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Barrier,
};
type TestResult = Result<(), Box<dyn std::error::Error>>;

struct TestClock(AtomicU64);
impl Clock for TestClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        match self.0.load(Ordering::SeqCst) {
            u64::MAX => Err(ClockError::Unavailable),
            time => FixedClock::from_millis(time).read(),
        }
    }
}
fn clock() -> Arc<TestClock> {
    Arc::new(TestClock(AtomicU64::new(100_000)))
}
fn image(
    authority: &SqliteCapabilityAuthority,
) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    let connection = SqliteCapabilityAuthority::open_connection(&authority.custody)?;
    let mut result = Vec::new();
    for table in [
        "authority_state",
        "authority_trusted_keys",
        "authority_replication",
        "authority_cluster_fence",
    ] {
        let mut stmt = connection.prepare(&format!("SELECT * FROM {table} ORDER BY 1"))?;
        let width = stmt.column_count();
        let rows = stmt.query_map([], |row| {
            let cells = (0..width)
                .map(|i| row.get_ref(i).map(|v| format!("{v:?}")))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(cells.join("|"))
        })?;
        for row in rows {
            result.push((table.into(), row?));
        }
    }
    Ok(result)
}
fn source_pair(
    root: &Path,
    time: Arc<TestClock>,
) -> Result<
    (
        SqliteCapabilityAuthority,
        SqliteCapabilityAuthority,
        AuthorityReplicationAnchor,
    ),
    Box<dyn std::error::Error>,
> {
    let source = SqliteCapabilityAuthority::open_with_clock(root.join("source.db"), time.clone())?;
    let follower = SqliteCapabilityAuthority::open_with_clock(root.join("follower.db"), time)?;
    let anchor = source.initialize_replication("cluster-a:authority")?;
    follower.pin_replication_anchor(&anchor)?;
    Ok((source, follower, anchor))
}

#[test]
fn honest_rotation_replication_relay_and_restart_preserve_local_custody() -> TestResult {
    let root = chio_test_support::private_tempdir()?;
    let time = clock();
    let (source, follower, anchor) = source_pair(root.path(), time.clone())?;
    let local_seed = follower.local_keypair()?.seed_hex();
    let first = source.signed_snapshot()?;
    assert!(!follower.apply_signed_snapshot(&first)?);
    source.rotate()?;
    source.rotate()?;
    let signed = source.signed_snapshot()?;
    assert!(follower.apply_signed_snapshot(&signed)?);
    assert!(!follower.apply_signed_snapshot(&signed)?);
    assert_eq!(follower.snapshot()?, source.snapshot()?);
    assert_eq!(follower.local_keypair()?.seed_hex(), local_seed);
    assert!(follower.current_keypair().is_err());
    assert!(follower.rotate().is_err());
    assert_eq!(follower.signed_snapshot()?, signed);
    let reopened =
        SqliteCapabilityAuthority::open_with_clock(root.path().join("follower.db"), time)?;
    assert_eq!(reopened.snapshot()?, source.snapshot()?);
    assert_eq!(reopened.replication_anchor()?, anchor);
    assert!(!reopened.apply_signed_snapshot(&signed)?);
    assert_eq!(reopened.snapshot()?.trusted_keys.len(), 3);
    Ok(())
}

#[test]
fn network_state_never_bootstraps_or_repins_authority() -> TestResult {
    let root = chio_test_support::private_tempdir()?;
    let time = clock();
    let source =
        SqliteCapabilityAuthority::open_with_clock(root.path().join("source.db"), time.clone())?;
    let follower =
        SqliteCapabilityAuthority::open_with_clock(root.path().join("follower.db"), time)?;
    assert!(source.signed_snapshot().is_err());
    let anchor = source.initialize_replication("cluster-a")?;
    let signed = source.signed_snapshot()?;
    let before = image(&follower)?;
    assert!(follower.apply_signed_snapshot(&signed).is_err());
    assert_eq!(image(&follower)?, before);
    assert!(follower.pin_replication_anchor(&anchor)?);
    assert!(!follower.pin_replication_anchor(&anchor)?);
    let mut wrong = anchor.clone();
    wrong.stream_id = "cluster-b".into();
    let pinned = image(&follower)?;
    assert!(follower.pin_replication_anchor(&wrong).is_err());
    assert!(source.initialize_replication("cluster-b").is_err());
    assert_eq!(image(&follower)?, pinned);
    Ok(())
}

#[test]
fn unsigned_substituted_stale_conflicting_and_unpinned_state_leave_every_table_unchanged(
) -> TestResult {
    let root = chio_test_support::private_tempdir()?;
    let (source, follower, _) = source_pair(root.path(), clock())?;
    source.rotate()?;
    let signed = source.signed_snapshot()?;
    let attacker = Keypair::generate();
    let before = image(&follower)?;
    let cached = follower.trusted_public_keys();
    for fault in [
        "unsigned",
        "history",
        "head",
        "stream",
        "root",
        "signature",
        "rotation-signature",
        "predecessor",
        "generation",
        "future",
        "expired",
        "long-lived",
        "set-digest",
    ] {
        let mut bad = signed.clone();
        if fault == "unsigned" {
            bad.proof = None;
        } else if fault == "history" {
            bad.snapshot.trusted_keys.insert(
                0,
                AuthorityTrustedKeySnapshot {
                    public_key_hex: attacker.public_key().to_hex(),
                    generation: 1,
                    activated_at: 99,
                    lifecycle: None,
                },
            );
        } else if fault == "head" {
            bad.snapshot.public_key_hex = attacker.public_key().to_hex();
        } else {
            let proof = bad.proof.as_mut().ok_or("missing proof")?;
            match fault {
                "stream" => proof.stream_id = "other-stream".into(),
                "root" => proof.anchor_digest = "00".repeat(32),
                "signature" => proof.signature = attacker.sign(b"substitution"),
                "rotation-signature" => {
                    proof.transitions[0].signature = attacker.sign(b"substitution")
                }
                "predecessor" => proof.transitions[0].body.previous_commitment = "00".repeat(32),
                "generation" => proof.transitions[0].body.generation = 3,
                "future" => proof.issued_at = 101,
                "expired" => proof.expires_at = 100,
                "long-lived" => proof.expires_at = 1000,
                "set-digest" => proof.transitions[0].body.issuer_set_digest = "00".repeat(32),
                _ => return Err("unknown fault".into()),
            }
        }
        assert!(
            follower.apply_signed_snapshot(&bad).is_err(),
            "accepted {fault}"
        );
        assert_eq!(image(&follower)?, before, "mutation on {fault}");
        assert_eq!(follower.trusted_public_keys(), cached);
    }
    assert!(follower.apply_signed_snapshot(&signed)?);
    let stale = signed;
    source.rotate()?;
    follower.apply_signed_snapshot(&source.signed_snapshot()?)?;
    let after = image(&follower)?;
    assert!(follower.apply_signed_snapshot(&stale).is_err());
    assert_eq!(image(&follower)?, after);
    Ok(())
}

#[test]
fn clock_failure_and_restart_regression_refuse_import_export_and_rotation() -> TestResult {
    let root = chio_test_support::private_tempdir()?;
    let time = clock();
    let (source, follower, _) = source_pair(root.path(), time.clone())?;
    let snapshot = source.signed_snapshot()?;
    let before = image(&follower)?;
    time.0.store(u64::MAX, Ordering::SeqCst);
    assert!(matches!(
        follower.apply_signed_snapshot(&snapshot),
        Err(AuthorityStoreError::Clock(ClockError::Unavailable))
    ));
    assert!(source.signed_snapshot().is_err());
    assert!(source.rotate().is_err());
    assert_eq!(image(&follower)?, before);
    time.0.store(99_000, Ordering::SeqCst);
    assert!(matches!(
        SqliteCapabilityAuthority::open_with_clock(root.path().join("follower.db"), time.clone()),
        Err(AuthorityStoreError::Clock(ClockError::WallClockRegression))
    ));
    assert_eq!(image(&follower)?, before);
    time.0.store(401_000, Ordering::SeqCst);
    let reopened =
        SqliteCapabilityAuthority::open_with_clock(root.path().join("follower.db"), time)?;
    // A successful reopen advances the durable clock floor. The expired import
    // must preserve that accepted state without changing issuer authority.
    assert_eq!(reopened.snapshot()?, follower.snapshot()?);
    let after_reopen = image(&reopened)?;
    assert!(reopened.apply_signed_snapshot(&snapshot).is_err());
    assert_eq!(image(&reopened)?, after_reopen);
    Ok(())
}

#[test]
fn competing_authenticated_successors_have_one_durable_winner() -> TestResult {
    let root = chio_test_support::private_tempdir()?;
    let time = clock();
    let (source, _follower, anchor) = source_pair(root.path(), time.clone())?;
    let signer = source.current_keypair()?;
    let mut threads = Vec::new();
    let barrier = Arc::new(Barrier::new(3));
    for _ in 0..2 {
        let key = Keypair::generate();
        let transition = SignedAuthorityTransition::sign(
            &anchor,
            &anchor.snapshot,
            &anchor.commitment()?,
            &key.public_key(),
            100,
            &signer,
        )?;
        let snapshot = SignedAuthoritySnapshot::sign(&anchor, vec![transition], 100, &key)?;
        let handle = SqliteCapabilityAuthority::open_with_clock(
            root.path().join("follower.db"),
            time.clone(),
        )?;
        let barrier = barrier.clone();
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            handle.apply_signed_snapshot(&snapshot)
        }));
    }
    barrier.wait();
    let mut accepted = 0;
    let mut rejected = 0;
    for thread in threads {
        match thread.join().map_err(|_| "thread panicked")? {
            Ok(true) => accepted += 1,
            Err(AuthorityStoreError::Fence(message)) if message == "authority history conflict" => {
                rejected += 1
            }
            other => return Err(format!("unexpected import outcome: {other:?}").into()),
        }
    }
    assert_eq!((accepted, rejected), (1, 1));
    let reopened =
        SqliteCapabilityAuthority::open_with_clock(root.path().join("follower.db"), time)?;
    assert_eq!(reopened.snapshot()?.trusted_keys.len(), 2);
    assert_eq!(reopened.status()?.generation, 2);
    Ok(())
}

#[test]
fn failed_head_or_replay_write_rolls_back_import_and_rotation() -> TestResult {
    let root = chio_test_support::private_tempdir()?;
    let (source, follower, _) = source_pair(root.path(), clock())?;
    source.rotate()?;
    let snapshot = source.signed_snapshot()?;
    for table in ["authority_state", "authority_replication"] {
        let connection = SqliteCapabilityAuthority::open_connection(&follower.custody)?;
        connection.execute_batch(&format!("CREATE TRIGGER injected_failure BEFORE UPDATE ON {table} BEGIN SELECT RAISE(ABORT, 'injected failure'); END;"))?;
        let before = image(&follower)?;
        assert!(follower.apply_signed_snapshot(&snapshot).is_err());
        assert_eq!(image(&follower)?, before);
        connection.execute_batch("DROP TRIGGER injected_failure")?;
    }
    let connection = SqliteCapabilityAuthority::open_connection(&source.custody)?;
    connection.execute_batch("CREATE TRIGGER injected_failure BEFORE UPDATE ON authority_state BEGIN SELECT RAISE(ABORT, 'injected failure'); END;")?;
    let before = image(&source)?;
    assert!(source.rotate().is_err());
    assert_eq!(image(&source)?, before);
    assert!(follower.apply_signed_snapshot(&snapshot)?);
    Ok(())
}

#[test]
fn final_f11_configured_skew_imports_revocation_and_survives_relay_and_restart() -> TestResult {
    let root = chio_test_support::private_tempdir()?;
    let source_time = clock();
    let follower_time = clock();
    let source = SqliteCapabilityAuthority::open_with_clock(
        root.path().join("source.db"),
        source_time.clone(),
    )?;
    let follower_path = root.path().join("follower.db");
    let follower =
        SqliteCapabilityAuthority::open_with_clock(&follower_path, follower_time.clone())?;
    let anchor = source.initialize_replication("skewed-authority")?;
    follower.pin_replication_anchor(&anchor)?;
    let compromised = source.status()?.public_key;
    source_time.0.store(101_000, Ordering::SeqCst);
    source.rotate()?;
    source.revoke_issuer(&compromised)?;
    let signed = source.signed_snapshot()?;
    let policy = AuthorityEnvelopeClockPolicy::new(1)?;
    let follower = SqliteCapabilityAuthority::open_with_clock_and_replication_policy(
        &follower_path,
        follower_time.clone(),
        policy,
    )?;
    assert!(follower.apply_signed_snapshot(&signed)?);
    assert!(!follower.apply_signed_snapshot(&signed)?);
    assert_eq!(follower.snapshot()?, source.snapshot()?);
    assert_eq!(follower.signed_snapshot()?, signed);
    assert!(follower.current_keypair().is_err());
    assert!(follower.rotate().is_err());

    // The admitted remote transition must not advance the local clock floor
    // to the signer's clock, or this same-clock restart would be refused.
    let reopened = SqliteCapabilityAuthority::open_with_clock_and_replication_policy(
        &follower_path,
        follower_time.clone(),
        policy,
    )?;
    assert_eq!(reopened.snapshot()?, source.snapshot()?);
    assert!(!reopened.apply_signed_snapshot(&signed)?);
    let inspection = crate::authority::SqliteAuthorityInspection::open_existing_with_clock_and_replication_policy(
        &follower_path, follower_time.clone(), policy,
    )?;
    let verification = inspection.verification_status()?;
    assert!(!verification.holds_current_signing_custody);
    assert!(!verification
        .status
        .trusted_public_keys
        .contains(&compromised));
    assert!(
        verification.status.trusted_public_keys.is_empty(),
        "skew admission must not give the future-activated successor early issuer authority"
    );
    follower_time.0.store(101_000, Ordering::SeqCst);
    assert_eq!(
        inspection.verification_status()?.status.trusted_public_keys,
        vec![source.status()?.public_key]
    );
    Ok(())
}

#[test]
fn final_f11_zero_skew_refuses_future_envelopes_without_mutating_authority() -> TestResult {
    let root = chio_test_support::private_tempdir()?;
    let source_time = clock();
    let follower_time = clock();
    let source = SqliteCapabilityAuthority::open_with_clock(
        root.path().join("source.db"),
        source_time.clone(),
    )?;
    let follower =
        SqliteCapabilityAuthority::open_with_clock(root.path().join("follower.db"), follower_time)?;
    follower.pin_replication_anchor(&source.initialize_replication("strict-authority")?)?;
    source_time.0.store(101_000, Ordering::SeqCst);
    let signed = source.signed_snapshot()?;
    let before = image(&follower)?;
    assert!(follower.apply_signed_snapshot(&signed).is_err());
    assert_eq!(image(&follower)?, before);
    Ok(())
}

#[test]
fn final_f11_skew_does_not_extend_expiry_or_allow_local_clock_regression() -> TestResult {
    let root = chio_test_support::private_tempdir()?;
    let source_time = clock();
    let follower_time = clock();
    let source = SqliteCapabilityAuthority::open_with_clock(
        root.path().join("source.db"),
        source_time.clone(),
    )?;
    let follower_path = root.path().join("follower.db");
    let policy = AuthorityEnvelopeClockPolicy::new(1)?;
    let follower = SqliteCapabilityAuthority::open_with_clock_and_replication_policy(
        &follower_path,
        follower_time.clone(),
        policy,
    )?;
    follower.pin_replication_anchor(&source.initialize_replication("expiry-authority")?)?;
    source_time.0.store(101_000, Ordering::SeqCst);
    let signed = source.signed_snapshot()?;
    assert!(!follower.apply_signed_snapshot(&signed)?);
    follower_time.0.store(401_000, Ordering::SeqCst);
    let before = image(&follower)?;
    assert!(follower.apply_signed_snapshot(&signed).is_err());
    assert!(follower.signed_snapshot().is_err());
    assert_eq!(image(&follower)?, before);
    let inspection = crate::authority::SqliteAuthorityInspection::open_existing_with_clock_and_replication_policy(
        &follower_path, follower_time.clone(), policy,
    )?;
    assert!(inspection.verification_status().is_err());

    // Returning to an earlier local reading stays forbidden even though the
    // configured peer skew would permit a future signed observation.
    follower_time.0.store(99_999, Ordering::SeqCst);
    assert!(follower.apply_signed_snapshot(&signed).is_err());
    assert!(
        SqliteCapabilityAuthority::open_with_clock_and_replication_policy(
            &follower_path,
            follower_time,
            policy,
        )
        .is_err()
    );
    assert_eq!(image(&follower)?, before);
    Ok(())
}
