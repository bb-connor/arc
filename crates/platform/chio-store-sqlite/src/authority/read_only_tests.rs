use super::*;
use chio_security_types::clock::{ClockError, FixedClock};
use rusqlite::OpenFlags;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const PROVISIONED_AT_MS: u64 = 1_800_000_000_000;

fn fixed(unix_millis: u64) -> Arc<dyn Clock> {
    Arc::new(FixedClock::from_millis(unix_millis))
}

fn provisioned(
) -> Result<(tempfile::TempDir, PathBuf, SqliteCapabilityAuthority), Box<dyn std::error::Error>> {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("authority.sqlite3");
    let owner = SqliteCapabilityAuthority::open_with_clock(&path, fixed(PROVISIONED_AT_MS))?;
    Ok((directory, path, owner))
}

/// A separate reader. `PRAGMA data_version` moves when another connection commits.
struct Witness(Connection);

impl Witness {
    fn open(path: &Path) -> Result<Self, rusqlite::Error> {
        Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).map(Self)
    }

    fn data_version(&self) -> rusqlite::Result<i64> {
        self.0
            .query_row("PRAGMA data_version", [], |row| row.get(0))
    }

    fn observed_ms(&self) -> rusqlite::Result<i64> {
        self.0.query_row(
            "SELECT observed_ms FROM authority_state WHERE singleton_id = 1",
            [],
            |row| row.get(0),
        )
    }
}

#[test]
fn inspection_matches_the_owner_without_committing_a_write() -> TestResult {
    let (_directory, path, owner) = provisioned()?;
    let expected = owner.status()?;
    let expected_signer = owner.local_keypair()?;
    let witness = Witness::open(&path)?;
    let version = witness.data_version()?;
    let floor = witness.observed_ms()?;

    let inspection =
        SqliteAuthorityInspection::open_existing_with_clock(&path, fixed(PROVISIONED_AT_MS + 1))?;
    let status = inspection.status()?;
    assert_eq!(status.public_key, expected.public_key);
    assert_eq!(status.generation, expected.generation);
    assert_eq!(status.rotated_at, expected.rotated_at);
    assert_eq!(status.issuer_state, expected.issuer_state);
    assert_eq!(status.trusted_public_keys, expected.trusted_public_keys);
    assert_eq!(
        inspection.local_keypair()?.public_key(),
        expected_signer.public_key()
    );

    assert_eq!(
        witness.data_version()?,
        version,
        "inspection committed a write"
    );
    assert_eq!(witness.observed_ms()?, floor, "inspection moved the floor");
    Ok(())
}

#[test]
fn inspection_refuses_absent_or_uninitialized_storage_without_creating_it() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let clock = fixed(PROVISIONED_AT_MS);

    let missing_parent = directory.path().join("missing");
    assert!(matches!(
        SqliteAuthorityInspection::open_existing_with_clock(
            missing_parent.join("authority.sqlite3"),
            clock.clone()
        ),
        Err(AuthorityInspectionError::Uninitialized)
    ));
    assert!(!missing_parent.exists());

    let absent = directory.path().join("absent.sqlite3");
    assert!(matches!(
        SqliteAuthorityInspection::open_existing_with_clock(&absent, clock.clone()),
        Err(AuthorityInspectionError::Uninitialized)
    ));
    assert!(!absent.exists());

    let empty = directory.path().join("empty.sqlite3");
    std::fs::write(&empty, b"")?;
    std::fs::set_permissions(&empty, std::fs::Permissions::from_mode(0o600))?;
    assert!(matches!(
        SqliteAuthorityInspection::open_existing_with_clock(&empty, clock.clone()),
        Err(AuthorityInspectionError::Uninitialized)
    ));
    assert_eq!(std::fs::metadata(&empty)?.len(), 0);

    let (_provisioned, unbootstrapped, owner) = provisioned()?;
    drop(owner);
    Connection::open(&unbootstrapped)?.execute("DELETE FROM authority_state", [])?;
    assert!(matches!(
        SqliteAuthorityInspection::open_existing_with_clock(&unbootstrapped, clock),
        Err(AuthorityInspectionError::Uninitialized)
    ));
    let rows: i64 = Witness::open(&unbootstrapped)?.0.query_row(
        "SELECT COUNT(*) FROM authority_state",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(rows, 0, "inspection must never bootstrap signing material");
    Ok(())
}

#[test]
fn inspection_refuses_a_clock_below_the_persisted_floor_without_moving_it() -> TestResult {
    let (_directory, path, _owner) = provisioned()?;
    let witness = Witness::open(&path)?;
    assert!(matches!(
        SqliteAuthorityInspection::open_existing_with_clock(&path, fixed(PROVISIONED_AT_MS - 1)),
        Err(AuthorityInspectionError::Store(AuthorityStoreError::Clock(
            ClockError::WallClockRegression
        )))
    ));
    assert_eq!(u64::try_from(witness.observed_ms()?)?, PROVISIONED_AT_MS);

    let inspection =
        SqliteAuthorityInspection::open_existing_with_clock(&path, fixed(PROVISIONED_AT_MS))?;
    let later = PROVISIONED_AT_MS + 10_000;
    SqliteCapabilityAuthority::open_with_clock(&path, fixed(later))?.status()?;
    assert_eq!(u64::try_from(witness.observed_ms()?)?, later);
    assert!(matches!(
        inspection.status(),
        Err(AuthorityInspectionError::Store(AuthorityStoreError::Clock(
            ClockError::WallClockRegression
        )))
    ));
    assert!(inspection.local_keypair().is_err());
    assert_eq!(
        u64::try_from(witness.observed_ms()?)?,
        later,
        "a refused inspection must leave the persisted floor in place"
    );
    Ok(())
}

#[test]
fn inspection_refuses_unsafe_custody_and_never_repairs_it() -> TestResult {
    let (directory, path, owner) = provisioned()?;
    drop(owner);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
    assert!(matches!(
        SqliteAuthorityInspection::open_existing_with_clock(&path, fixed(PROVISIONED_AT_MS)),
        Err(AuthorityInspectionError::Store(AuthorityStoreError::Fence(message)))
            if message.contains("authority file custody")
    ));
    assert_eq!(
        std::fs::metadata(&path)?.permissions().mode() & 0o7777,
        0o644
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;

    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755))?;
    assert!(matches!(
        SqliteAuthorityInspection::open_existing_with_clock(&path, fixed(PROVISIONED_AT_MS)),
        Err(AuthorityInspectionError::Store(AuthorityStoreError::Fence(message)))
            if message.contains("authority file custody")
    ));
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[test]
fn inspection_refuses_storage_that_needs_owner_migration() -> TestResult {
    let (_directory, path, owner) = provisioned()?;
    drop(owner);
    let raw = Connection::open(&path)?;
    raw.execute(
        "UPDATE chio_store_schema_versions SET version = ?1 WHERE store_key = ?2",
        rusqlite::params![
            AUTHORITY_STORE_SUPPORTED_SCHEMA_VERSION - 1,
            AUTHORITY_STORE_SCHEMA_KEY
        ],
    )?;
    assert!(matches!(
        SqliteAuthorityInspection::open_existing_with_clock(&path, fixed(PROVISIONED_AT_MS)),
        Err(AuthorityInspectionError::Store(AuthorityStoreError::Schema(message)))
            if message.contains("needs migration")
    ));
    let version: i32 = raw.query_row(
        "SELECT version FROM chio_store_schema_versions WHERE store_key = ?1",
        [AUTHORITY_STORE_SCHEMA_KEY],
        |row| row.get(0),
    )?;
    assert_eq!(version, AUTHORITY_STORE_SUPPORTED_SCHEMA_VERSION - 1);
    Ok(())
}

#[test]
fn inspection_reads_while_an_authority_writer_holds_the_write_lock() -> TestResult {
    let (_directory, path, owner) = provisioned()?;
    let expected = owner.status()?;
    let expected_signer = owner.local_keypair()?;
    let writer = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    writer.busy_timeout(std::time::Duration::ZERO)?;
    writer.execute_batch("BEGIN IMMEDIATE")?;
    let inspection =
        SqliteAuthorityInspection::open_existing_with_clock(&path, fixed(PROVISIONED_AT_MS))?;
    assert_eq!(inspection.status()?.public_key, expected.public_key);
    assert_eq!(
        inspection.local_keypair()?.public_key(),
        expected_signer.public_key()
    );
    writer.execute_batch("ROLLBACK")?;
    Ok(())
}

#[test]
fn inspection_publishes_rotation_and_lifecycle_from_the_owner() -> TestResult {
    let (_directory, path, owner) = provisioned()?;
    let original = owner.status()?;
    owner.initialize_replication("inspection-lifecycle")?;
    let inspection =
        SqliteAuthorityInspection::open_existing_with_clock(&path, fixed(PROVISIONED_AT_MS))?;

    let rotated = owner.rotate()?;
    let status = inspection.status()?;
    assert_eq!(status.public_key, rotated.public_key);
    assert_eq!(status.generation, 2);
    assert_eq!(status.trusted_public_keys, rotated.trusted_public_keys);
    assert_eq!(inspection.local_keypair()?.public_key(), rotated.public_key);

    let revoked = owner.revoke_issuer(&original.public_key)?;
    let status = inspection.status()?;
    assert_eq!(status.trusted_public_keys, revoked.trusted_public_keys);
    assert!(!status.trusted_public_keys.contains(&original.public_key));
    assert_eq!(status.issuer_state, revoked.issuer_state);
    Ok(())
}

#[test]
fn final_f11_peer_prefix_inspection_preserves_actual_import_replay_refusal() -> TestResult {
    let (_directory, path, owner) = provisioned()?;
    owner.initialize_replication("peer-prefix-replay")?;
    let older = owner.signed_snapshot()?;
    let later =
        SqliteCapabilityAuthority::open_with_clock(&path, fixed(PROVISIONED_AT_MS + 2_000))?;
    let newer = later.signed_snapshot()?;
    let witness = Witness::open(&path)?;
    let version = witness.data_version()?;
    let floor = witness.observed_ms()?;
    let inspection = SqliteAuthorityInspection::open_existing_with_clock(
        &path,
        fixed(PROVISIONED_AT_MS + 2_000),
    )?;
    let evidence = inspection.peer_chain_evidence(&older)?;
    assert_eq!(evidence.history, AuthorityPeerHistory::ConsistentPrefix);
    assert_eq!(
        evidence.chain_commitment,
        older
            .proof
            .as_ref()
            .ok_or("missing signed proof")?
            .chain_commitment
    );
    assert_eq!(
        witness.data_version()?,
        version,
        "peer inspection wrote storage"
    );
    assert_eq!(
        witness.observed_ms()?,
        floor,
        "peer inspection advanced the clock floor"
    );
    assert!(matches!(
        later.apply_signed_snapshot(&older),
        Err(AuthorityStoreError::Fence(reason))
            if reason == "authority envelope replay regresses issuance time"
    ));
    assert_eq!(
        witness.data_version()?,
        version,
        "replay refusal committed a write"
    );
    assert_eq!(later.signed_snapshot()?, newer);
    Ok(())
}

#[test]
fn final_f11_peer_history_inspection_distinguishes_extension_prefix_and_fork() -> TestResult {
    use chio_kernel::authority::replication::{SignedAuthoritySnapshot, SignedAuthorityTransition};
    let (directory, path, owner) = provisioned()?;
    let original_key = owner.local_keypair()?;
    let anchor = owner.initialize_replication("peer-history-classification")?;
    let prefix = owner.signed_snapshot()?;
    let fork_key = Keypair::generate();
    let fork_transition = SignedAuthorityTransition::sign(
        &anchor,
        &anchor.snapshot,
        &anchor.commitment()?,
        &fork_key.public_key(),
        PROVISIONED_AT_MS / 1_000,
        &original_key,
    )?;
    let fork = SignedAuthoritySnapshot::sign(
        &anchor,
        vec![fork_transition],
        PROVISIONED_AT_MS / 1_000,
        &fork_key,
    )?;
    owner.rotate()?;
    let extension = owner.signed_snapshot()?;
    let inspection =
        SqliteAuthorityInspection::open_existing_with_clock(&path, fixed(PROVISIONED_AT_MS))?;
    assert_eq!(
        inspection.peer_chain_evidence(&prefix)?.history,
        AuthorityPeerHistory::ConsistentPrefix
    );
    assert_eq!(
        inspection.peer_chain_evidence(&fork)?.history,
        AuthorityPeerHistory::Conflicting
    );
    assert!(matches!(owner.apply_signed_snapshot(&fork),
        Err(AuthorityStoreError::Fence(reason)) if reason == "authority history conflict"
    ));
    let follower_path = directory.path().join("follower.sqlite3");
    let follower =
        SqliteCapabilityAuthority::open_with_clock(&follower_path, fixed(PROVISIONED_AT_MS))?;
    follower.pin_replication_anchor(&anchor)?;
    follower.apply_signed_snapshot(&prefix)?;
    let follower_view = SqliteAuthorityInspection::open_existing_with_clock(
        &follower_path,
        fixed(PROVISIONED_AT_MS),
    )?;
    let evidence = follower_view.peer_chain_evidence(&extension)?;
    assert_eq!(evidence.history, AuthorityPeerHistory::Newer);
    assert!(evidence.contains_authenticated_history(&anchor.commitment()?));
    assert!(evidence.contains_authenticated_history(&evidence.chain_commitment));
    assert!(!evidence.contains_authenticated_history(
        &fork
            .proof
            .as_ref()
            .ok_or("missing fork proof")?
            .chain_commitment
    ));
    assert_eq!(evidence.authenticated_history_commitments().len(), 2);
    assert_eq!(
        follower_view.status()?.generation,
        1,
        "peer evidence imported state"
    );
    assert!(follower.apply_signed_snapshot(&extension)?);
    assert_eq!(follower.status()?.generation, 2);
    Ok(())
}

#[test]
fn final_f11_verification_view_binds_exact_envelope_history_and_exclusive_expiry() -> TestResult {
    let (directory, _path, owner) = provisioned()?;
    let anchor = owner.initialize_replication("verification-view-evidence")?;
    let signed = owner.signed_snapshot()?;
    let follower_path = directory.path().join("follower.sqlite3");
    let follower =
        SqliteCapabilityAuthority::open_with_clock(&follower_path, fixed(PROVISIONED_AT_MS))?;
    follower.pin_replication_anchor(&anchor)?;
    follower.apply_signed_snapshot(&signed)?;
    let inspection = SqliteAuthorityInspection::open_existing_with_clock(
        &follower_path,
        fixed(PROVISIONED_AT_MS),
    )?;
    let view = inspection.replicated_verification_status()?;
    let expires_at = signed
        .proof
        .as_ref()
        .ok_or("missing signed proof")?
        .expires_at
        * 1_000;
    assert!(view.matches_imported_envelope(&signed.envelope_digest()?));
    assert!(view.contains_authenticated_history(&anchor.commitment()?));
    assert!(view.is_live_at(UnixMillis::new(expires_at - 1)));
    assert!(
        !view.is_live_at(UnixMillis::new(expires_at)),
        "exclusive expiry was extended"
    );
    assert!(
        !view.is_live_at(UnixMillis::new(PROVISIONED_AT_MS - 1)),
        "local clock rollback was accepted"
    );
    owner.rotate()?;
    let next = owner.signed_snapshot()?;
    assert!(!view.matches_imported_envelope(&next.envelope_digest()?));
    follower.apply_signed_snapshot(&next)?;
    let updated = inspection.replicated_verification_status()?;
    assert!(updated.contains_authenticated_history(&anchor.commitment()?));
    assert!(updated.contains_authenticated_history(
        &next
            .proof
            .as_ref()
            .ok_or("missing next proof")?
            .chain_commitment
    ));
    assert!(updated.matches_imported_envelope(&next.envelope_digest()?));
    Ok(())
}
