#![cfg(target_os = "linux")]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chio_kernel::CapabilityAuthority;
use chio_security_types::clock::{Clock, ClockError, ClockReading, FixedClock};
use chio_store_sqlite::SqliteCapabilityAuthority;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[path = "authority_lifecycle/portable.rs"]
mod portable;

fn private_root() -> Result<tempfile::TempDir, std::io::Error> {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir()?;
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
    Ok(root)
}

struct AuthorityClock(AtomicU64);

impl Clock for AuthorityClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        let seconds = self.0.load(Ordering::SeqCst);
        if seconds == u64::MAX {
            return Err(ClockError::Unavailable);
        }
        FixedClock::new(seconds).read()
    }
}

#[test]
fn kg2_rotated_issuer_does_not_remain_trusted_indefinitely() -> TestResult {
    let root = private_root()?;
    let clock = Arc::new(AuthorityClock(AtomicU64::new(100)));
    let authority = SqliteCapabilityAuthority::open_with_clock(
        root.path().join("authority.db"),
        clock.clone(),
    )?;
    let old = authority.authority_public_key()?;
    clock.0.store(101, Ordering::SeqCst);
    let current = authority.rotate()?.public_key;
    clock.0.store(100_000, Ordering::SeqCst);
    assert_eq!(authority.trusted_public_keys(), vec![current]);
    assert_ne!(authority.authority_public_key()?, old);
    Ok(())
}

#[test]
fn kg2_authority_clock_failure_cannot_reuse_cached_issuer_trust() -> TestResult {
    let root = private_root()?;
    let clock = Arc::new(AuthorityClock(AtomicU64::new(100)));
    let authority = SqliteCapabilityAuthority::open_with_clock(
        root.path().join("authority.db"),
        clock.clone(),
    )?;
    assert_eq!(authority.trusted_public_keys().len(), 1);
    clock.0.store(u64::MAX, Ordering::SeqCst);
    assert_eq!(authority.trusted_public_keys(), Vec::new());
    Ok(())
}

#[test]
fn kg2_lifecycle_deadlines_retirement_and_replay_survive_restart() -> TestResult {
    let root = private_root()?;
    let clock = Arc::new(AuthorityClock(AtomicU64::new(100)));
    let source_path = root.path().join("source.db");
    let follower_path = root.path().join("follower.db");
    let source = SqliteCapabilityAuthority::open_with_clock(&source_path, clock.clone())?;
    let follower = SqliteCapabilityAuthority::open_with_clock(&follower_path, clock.clone())?;
    let anchor = source.initialize_replication("lifecycle-tests")?;
    assert_eq!(anchor.schema, "chio.authority-replication-anchor.v1");
    follower.pin_replication_anchor(&anchor)?;
    let old = source.authority_public_key()?;
    clock.0.store(101, Ordering::SeqCst);
    let new = source.rotate_with_verification_deadline(110)?.public_key;
    let rotation = source.signed_snapshot()?;
    let proof = rotation.proof.as_ref().ok_or("rotation proof missing")?;
    assert_eq!(proof.schema, "chio.authority-snapshot.v1");
    assert_eq!(
        proof
            .transitions
            .first()
            .ok_or("rotation transition missing")?
            .body
            .schema,
        "chio.authority-lifecycle.v1"
    );
    follower.apply_signed_snapshot(&rotation)?;
    clock.0.store(109, Ordering::SeqCst);
    assert_eq!(
        follower.trusted_public_keys(),
        vec![old.clone(), new.clone()]
    );
    follower.check_issuer_lifecycle(&old, 101, 109)?;
    assert!(matches!(
        follower.check_issuer_lifecycle(&old, 102, 109),
        Err(chio_kernel::KernelError::UntrustedIssuer)
    ));
    clock.0.store(110, Ordering::SeqCst);
    assert_eq!(follower.trusted_public_keys(), vec![new.clone()]);
    drop(follower);
    let follower = SqliteCapabilityAuthority::open_with_clock(&follower_path, clock.clone())?;
    assert_eq!(follower.trusted_public_keys(), vec![new.clone()]);
    source.retire_issuer(&old)?;
    let retired = source.signed_snapshot()?;
    follower.apply_signed_snapshot(&retired)?;
    assert!(
        matches!(follower.apply_signed_snapshot(&rotation), Err(chio_kernel::AuthorityStoreError::Fence(message)) if message == "authority replay regression")
    );
    assert_eq!(follower.snapshot()?, retired.snapshot);
    source.revoke_issuer(&old)?;
    follower.apply_signed_snapshot(&source.signed_snapshot()?)?;
    assert_eq!(follower.trusted_public_keys(), vec![new]);
    assert!(
        matches!(source.retire_issuer(&old), Err(chio_kernel::AuthorityStoreError::Fence(message)) if message == "issuer lifecycle is already terminal")
    );
    drop(source);
    clock.0.store(109, Ordering::SeqCst);
    assert!(matches!(
        SqliteCapabilityAuthority::open_with_clock(&source_path, clock),
        Err(chio_kernel::AuthorityStoreError::Clock(
            ClockError::WallClockRegression
        ))
    ));
    Ok(())
}

#[test]
fn kg2_independent_recovery_revokes_all_prior_issuers_without_seed_replication() -> TestResult {
    use chio_core::crypto::Keypair;
    let root = private_root()?;
    let clock = Arc::new(AuthorityClock(AtomicU64::new(100)));
    let source =
        SqliteCapabilityAuthority::open_with_clock(root.path().join("source.db"), clock.clone())?;
    let follower =
        SqliteCapabilityAuthority::open_with_clock(root.path().join("follower.db"), clock.clone())?;
    let recovery = Keypair::generate();
    let anchor =
        source.initialize_replication_with_recovery("recoverable", Some(&recovery.public_key()))?;
    follower.pin_replication_anchor(&anchor)?;
    let follower_seed = follower.local_keypair()?.seed_hex();
    let old = source.authority_public_key()?;
    let before = source.snapshot()?;
    assert!(
        matches!(source.recover_authority(&Keypair::generate()), Err(chio_kernel::AuthorityStoreError::Fence(message)) if message == "lifecycle signer does not own the required authority")
    );
    assert_eq!(source.snapshot()?, before);
    clock.0.store(101, Ordering::SeqCst);
    let current = source.recover_authority(&recovery)?.public_key;
    follower.apply_signed_snapshot(&source.signed_snapshot()?)?;
    assert_eq!(follower.trusted_public_keys(), vec![current.clone()]);
    assert_ne!(current, old);
    assert_eq!(follower.local_keypair()?.seed_hex(), follower_seed);
    assert!(
        matches!(follower.current_keypair(), Err(chio_kernel::AuthorityStoreError::Fence(message)) if message.contains("local signing seed public key"))
    );
    Ok(())
}

#[test]
fn kg2_retirement_rolls_back_history_commitment_and_clock_on_sql_failure() -> TestResult {
    let root = private_root()?;
    let path = root.path().join("source.db");
    let clock = Arc::new(AuthorityClock(AtomicU64::new(100)));
    let source = SqliteCapabilityAuthority::open_with_clock(&path, clock.clone())?;
    source.initialize_replication("rollback")?;
    let old = source.authority_public_key()?;
    clock.0.store(101, Ordering::SeqCst);
    source.rotate()?;
    let before = source.signed_snapshot()?;
    let seed = source.local_keypair()?.seed_hex();
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute_batch("CREATE TRIGGER fail_lifecycle BEFORE INSERT ON authority_trusted_keys BEGIN SELECT RAISE(ABORT, 'lifecycle fault'); END;")?;
    assert!(
        matches!(source.retire_issuer(&old), Err(chio_kernel::AuthorityStoreError::Sqlite(rusqlite::Error::SqliteFailure(_, Some(message)))) if message == "lifecycle fault")
    );
    assert_eq!(source.signed_snapshot()?, before);
    assert_eq!(source.local_keypair()?.seed_hex(), seed);
    connection.execute_batch("DROP TRIGGER fail_lifecycle")?;
    source.retire_issuer(&old)?;
    assert_eq!(source.trusted_public_keys().len(), 1);
    Ok(())
}

#[test]
fn kg2_competing_lifecycle_imports_commit_one_complete_history() -> TestResult {
    use chio_kernel::authority::{
        lifecycle::AuthorityLifecycleChange,
        replication::{SignedAuthoritySnapshot, SignedAuthorityTransition},
    };
    let root = private_root()?;
    let clock = Arc::new(AuthorityClock(AtomicU64::new(100)));
    let source =
        SqliteCapabilityAuthority::open_with_clock(root.path().join("source.db"), clock.clone())?;
    let follower = Arc::new(SqliteCapabilityAuthority::open_with_clock(
        root.path().join("follower.db"),
        clock.clone(),
    )?);
    let anchor = source.initialize_replication("competing-lifecycle")?;
    follower.pin_replication_anchor(&anchor)?;
    let old = source.authority_public_key()?;
    clock.0.store(101, Ordering::SeqCst);
    source.rotate()?;
    let base = source.signed_snapshot()?;
    follower.apply_signed_snapshot(&base)?;
    let proof = base.proof.as_ref().ok_or("missing proof")?;
    let head = source.current_keypair()?;
    let seed = follower.local_keypair()?.seed_hex();
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let mut workers = Vec::new();
    for change in [
        AuthorityLifecycleChange::Retire {
            public_key_hex: old.to_hex(),
        },
        AuthorityLifecycleChange::Revoke {
            public_key_hex: old.to_hex(),
        },
    ] {
        let transition = SignedAuthorityTransition::sign_change(
            &anchor,
            &base.snapshot,
            &proof.chain_commitment,
            change,
            &head.public_key(),
            101,
            &head,
        )?;
        let mut chain = proof.transitions.clone();
        chain.push(transition);
        let signed = SignedAuthoritySnapshot::sign(&anchor, chain, 101, &head)?;
        let authority = follower.clone();
        let barrier = barrier.clone();
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            authority.apply_signed_snapshot(&signed)
        }));
    }
    let mut committed = 0;
    let mut conflicted = 0;
    for worker in workers {
        match worker.join().map_err(|_| "lifecycle worker panicked")? {
            Ok(true) => committed += 1,
            Err(chio_kernel::AuthorityStoreError::Fence(message))
                if message == "authority history conflict" =>
            {
                conflicted += 1
            }
            other => return Err(format!("unexpected competing import result: {other:?}").into()),
        }
    }
    assert_eq!((committed, conflicted), (1, 1));
    assert_eq!(follower.status()?.generation, 3);
    assert_eq!(follower.trusted_public_keys(), vec![head.public_key()]);
    assert_eq!(follower.local_keypair()?.seed_hex(), seed);
    Ok(())
}

#[test]
fn kg2_authority_wire_without_explicit_lifecycle_is_refused() -> TestResult {
    use chio_core::crypto::{sha256_hex, Keypair};
    use chio_kernel::authority::{
        lifecycle::{apply_lifecycle_change, AuthorityLifecycleChange},
        replication::{verify_authority_chain, AuthorityTransitionBody, SignedAuthorityTransition},
    };
    let root = private_root()?;
    let source = SqliteCapabilityAuthority::open_with_clock(
        root.path().join("source.db"),
        Arc::new(AuthorityClock(AtomicU64::new(100))),
    )?;
    let anchor = source.initialize_replication("rotation-domain")?;
    let next = Keypair::generate();
    let change = AuthorityLifecycleChange::Rotate { verify_until: 200 };
    let derived =
        apply_lifecycle_change(&anchor.snapshot, &change, &next.public_key().to_hex(), 100)?;
    let body = AuthorityTransitionBody {
        schema: "chio.authority-rotation.v1".into(),
        stream_id: anchor.stream_id.clone(),
        anchor_digest: anchor.commitment()?,
        previous_commitment: anchor.commitment()?,
        generation: derived.generation,
        public_key_hex: derived.public_key_hex,
        rotated_at: 100,
        issuer_set_digest: sha256_hex(&chio_core::canonical_json_bytes(&derived.trusted_keys)?),
        change,
    };
    let signature = source.current_keypair()?.sign_wrapped(
        "chio.authority-lifecycle.v1",
        &chio_core::CanonicalBytes::from_serializable(&body)?,
    )?;
    let result = verify_authority_chain(
        &anchor,
        &[SignedAuthorityTransition {
            body: body.clone(),
            signature,
        }],
    );
    assert!(
        matches!(result, Err(chio_kernel::AuthorityStoreError::Fence(message))
        if message == "authority transition predecessor or domain mismatch")
    );
    let mut wire = serde_json::to_value(&body)?;
    wire.as_object_mut()
        .ok_or("transition body is not an object")?
        .remove("change");
    let error = serde_json::from_value::<AuthorityTransitionBody>(wire)
        .err()
        .ok_or("transition without a lifecycle operation decoded")?;
    assert_eq!(error.to_string(), "missing field `change`");
    let mut key = serde_json::to_value(anchor.snapshot.trusted_keys.first().ok_or("no issuer")?)?;
    key.as_object_mut()
        .ok_or("trusted key is not an object")?
        .remove("lifecycle");
    let error = serde_json::from_value::<chio_kernel::AuthorityTrustedKeySnapshot>(key)
        .err()
        .ok_or("trusted key without a lifecycle decoded")?;
    assert_eq!(error.to_string(), "missing field `lifecycle`");
    let mut foreign = anchor.clone();
    foreign.schema = "chio.authority-replication-anchor.v2".into();
    assert!(
        matches!(foreign.validate(), Err(chio_kernel::AuthorityStoreError::Fence(message))
        if message == "invalid replication anchor domain")
    );
    Ok(())
}

#[test]
fn kg2_invalid_deadlines_and_head_removal_preserve_all_authority_state() -> TestResult {
    let root = private_root()?;
    let clock = Arc::new(AuthorityClock(AtomicU64::new(100)));
    let source = SqliteCapabilityAuthority::open_with_clock(root.path().join("source.db"), clock)?;
    source.initialize_replication("refused-operations")?;
    let current = source.authority_public_key()?;
    let before = source.signed_snapshot()?;
    let seed = source.local_keypair()?.seed_hex();
    for deadline in [99, 3701, u64::MAX] {
        assert!(
            matches!(source.rotate_with_verification_deadline(deadline), Err(chio_kernel::AuthorityStoreError::Fence(message)) if message == "issuer verification deadline outside grace bound")
        );
    }
    for result in [
        source.retire_issuer(&current),
        source.revoke_issuer(&current),
    ] {
        assert!(
            matches!(result, Err(chio_kernel::AuthorityStoreError::Fence(message)) if message == "head removal requires an atomic successor")
        );
    }
    assert_eq!(source.signed_snapshot()?, before);
    assert_eq!(source.local_keypair()?.seed_hex(), seed);
    Ok(())
}

#[test]
fn kg2_recovery_root_cannot_become_regular_issuer() -> TestResult {
    use chio_core::crypto::Keypair;
    use chio_kernel::authority::{
        lifecycle::AuthorityLifecycleChange, replication::SignedAuthorityTransition,
    };
    let root = private_root()?;
    let source = SqliteCapabilityAuthority::open_with_clock(
        root.path().join("source.db"),
        Arc::new(AuthorityClock(AtomicU64::new(100))),
    )?;
    let recovery = Keypair::generate();
    let anchor = source.initialize_replication_with_recovery(
        "independent-recovery",
        Some(&recovery.public_key()),
    )?;
    let result = SignedAuthorityTransition::sign_change(
        &anchor,
        &anchor.snapshot,
        &anchor.commitment()?,
        AuthorityLifecycleChange::Rotate { verify_until: 200 },
        &recovery.public_key(),
        100,
        &source.current_keypair()?,
    );
    assert!(
        matches!(result, Err(chio_kernel::AuthorityStoreError::Fence(message)) if message == "recovery root cannot be a capability issuer")
    );
    Ok(())
}

#[test]
fn kg2_signed_history_cannot_promote_recovery_root_to_issuer() -> TestResult {
    use chio_core::crypto::{sha256_hex, Keypair};
    use chio_kernel::authority::{
        lifecycle::{apply_lifecycle_change, AuthorityLifecycleChange},
        replication::{verify_authority_chain, AuthorityTransitionBody, SignedAuthorityTransition},
    };
    let root = private_root()?;
    let source = SqliteCapabilityAuthority::open_with_clock(
        root.path().join("source.db"),
        Arc::new(AuthorityClock(AtomicU64::new(100))),
    )?;
    let recovery = Keypair::generate();
    let anchor = source.initialize_replication_with_recovery(
        "independent-recovery",
        Some(&recovery.public_key()),
    )?;
    let change = AuthorityLifecycleChange::Rotate { verify_until: 200 };
    let derived = apply_lifecycle_change(
        &anchor.snapshot,
        &change,
        &recovery.public_key().to_hex(),
        100,
    )?;
    let body = AuthorityTransitionBody {
        schema: "chio.authority-lifecycle.v1".into(),
        stream_id: anchor.stream_id.clone(),
        anchor_digest: anchor.commitment()?,
        previous_commitment: anchor.commitment()?,
        generation: derived.generation,
        public_key_hex: derived.public_key_hex,
        rotated_at: 100,
        issuer_set_digest: sha256_hex(&chio_core::canonical_json_bytes(&derived.trusted_keys)?),
        change,
    };
    let signature = source.current_keypair()?.sign_wrapped(
        "chio.authority-lifecycle.v1",
        &chio_core::CanonicalBytes::from_serializable(&body)?,
    )?;
    let result = verify_authority_chain(&anchor, &[SignedAuthorityTransition { body, signature }]);
    assert!(
        matches!(result, Err(chio_kernel::AuthorityStoreError::Fence(message))
        if message == "recovery root cannot be a capability issuer")
    );
    Ok(())
}

#[test]
fn schema_reopen_refuses_deleted_identity_without_repair() -> TestResult {
    let root = private_root()?;
    let path = root.path().join("authority.db");
    drop(SqliteCapabilityAuthority::open(&path)?);
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute("DELETE FROM authority_state", [])?;
    let result = SqliteCapabilityAuthority::open(&path);
    let count: i64 =
        connection.query_row("SELECT COUNT(*) FROM authority_state", [], |row| row.get(0))?;
    assert_eq!(count, 0);
    assert!(matches!(
        result,
        Err(chio_kernel::AuthorityStoreError::MissingIdentity)
    ));
    Ok(())
}

#[test]
fn schema_reopen_refuses_deleted_fence_without_repair() -> TestResult {
    let root = private_root()?;
    let path = root.path().join("authority.db");
    drop(SqliteCapabilityAuthority::open(&path)?);
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute("DELETE FROM authority_cluster_fence", [])?;
    let result = SqliteCapabilityAuthority::open(&path);
    let count: i64 =
        connection.query_row("SELECT COUNT(*) FROM authority_cluster_fence", [], |row| {
            row.get(0)
        })?;
    assert_eq!(count, 0);
    assert!(matches!(
        result,
        Err(chio_kernel::AuthorityStoreError::MissingClusterFence)
    ));
    Ok(())
}

#[test]
fn schema_reopen_refuses_deleted_stamp_without_repair() -> TestResult {
    let root = private_root()?;
    let path = root.path().join("authority.db");
    drop(SqliteCapabilityAuthority::open(&path)?);
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute("DELETE FROM chio_store_schema_versions", [])?;
    let result = SqliteCapabilityAuthority::open(&path);
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM chio_store_schema_versions",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    assert!(
        matches!(result, Err(chio_kernel::AuthorityStoreError::Schema(chio_security_types::schema::SchemaRefusal::MissingSchema { store_key }))
        if store_key == "authority")
    );
    Ok(())
}
