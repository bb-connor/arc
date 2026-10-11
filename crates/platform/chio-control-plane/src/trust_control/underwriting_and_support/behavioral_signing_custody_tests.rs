//! Report signing inspects custody that the authority owner already provisioned.

use super::*;
use rusqlite::{Connection, OpenFlags};
use std::os::unix::fs::PermissionsExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn behavioral_signer_reads_the_existing_plain_seed_without_replacing_it() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let seed = directory.path().join("authority.seed");
    let owner = crate::load_or_create_authority_keypair(&seed)?;
    let original = std::fs::read(&seed)?;

    let signer = load_behavioral_feed_signing_keypair(Some(&seed), None)?;
    assert_eq!(signer.public_key(), owner.public_key());
    assert_eq!(std::fs::read(&seed)?, original);
    Ok(())
}

#[test]
fn behavioral_signer_refuses_a_missing_plain_seed_without_creating_custody() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let seed = directory.path().join("authority.seed");
    let result = load_behavioral_feed_signing_keypair(Some(&seed), None);
    assert!(
        result.is_err() && !seed.exists(),
        "report signing accepted absent seed custody or created a new seed"
    );
    assert!(std::fs::read_dir(directory.path())?.next().is_none());
    Ok(())
}

#[test]
fn behavioral_signer_refuses_a_missing_database_without_creating_files() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    for path in [
        directory.path().join("authority.sqlite3"),
        directory.path().join("missing/authority.sqlite3"),
    ] {
        let result = load_behavioral_feed_signing_keypair(None, Some(&path));
        assert!(
            result.is_err() && !path.exists(),
            "report signing accepted absent database custody or created a database"
        );
        assert!(std::fs::read_dir(directory.path())?.next().is_none());
    }
    Ok(())
}

#[test]
fn behavioral_signer_refuses_an_empty_database_without_creating_a_schema() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("authority.sqlite3");
    std::fs::write(&path, [])?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    let result = load_behavioral_feed_signing_keypair(None, Some(&path));
    assert!(
        result.is_err() && std::fs::metadata(&path)?.len() == 0,
        "report signing bootstrapped an empty authority database"
    );
    let entries = std::fs::read_dir(directory.path())?.collect::<Result<Vec<_>, _>>()?;
    assert_eq!(entries.len(), 1, "report signing created database sidecars");
    Ok(())
}

#[test]
fn behavioral_signer_reads_a_provisioned_database_without_committing_a_write() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("authority.sqlite3");
    let owner =
        SqliteCapabilityAuthority::open_with_clock(&path, chio_test_support::clock::clock())?;
    let key = owner.local_keypair()?.public_key();
    let witness = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let data_version = || witness.query_row("PRAGMA data_version", [], |row| row.get::<_, i64>(0));
    let clock_floor = || {
        witness.query_row(
            "SELECT observed_ms FROM authority_state WHERE singleton_id = 1",
            [],
            |row| row.get::<_, i64>(0),
        )
    };
    let original_version = data_version()?;
    let original_floor = clock_floor()?;

    let signer = load_behavioral_feed_signing_keypair(None, Some(&path))?;
    assert_eq!(signer.public_key(), key);
    assert_eq!(
        data_version()?,
        original_version,
        "report signer committed a write"
    );
    assert_eq!(
        clock_floor()?,
        original_floor,
        "report signer advanced the clock floor"
    );
    Ok(())
}

#[test]
fn behavioral_signer_keeps_persisted_millisecond_floor_refusal() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("authority.sqlite3");
    let _owner =
        SqliteCapabilityAuthority::open_with_clock(&path, chio_test_support::clock::clock())?;
    let raw = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    let future_floor = i64::try_from(chio_test_support::clock::unix_millis())?
        .checked_add(86_400_000)
        .ok_or("fixture clock floor overflow")?;
    raw.execute(
        "UPDATE authority_state SET observed_ms = ?1 WHERE singleton_id = 1",
        [future_floor],
    )?;
    let witness = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let version: i64 = witness.query_row("PRAGMA data_version", [], |row| row.get(0))?;

    let result = load_behavioral_feed_signing_keypair(None, Some(&path));
    assert!(matches!(
        result,
        Err(CliError::AuthorityStore(
            chio_kernel::AuthorityStoreError::Clock(
                chio_security_types::clock::ClockError::WallClockRegression
            )
        ))
    ));
    let persisted: i64 = witness.query_row(
        "SELECT observed_ms FROM authority_state WHERE singleton_id = 1",
        [],
        |row| row.get(0),
    )?;
    let after_version: i64 = witness.query_row("PRAGMA data_version", [], |row| row.get(0))?;
    assert_eq!(persisted, future_floor);
    assert_eq!(after_version, version, "clock refusal committed a write");
    Ok(())
}

#[test]
fn behavioral_report_keeps_local_node_signer_after_replication_moves_head() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let source = SqliteCapabilityAuthority::open_with_clock(
        directory.path().join("source.sqlite3"),
        chio_test_support::clock::clock(),
    )?;
    let follower_path = directory.path().join("follower.sqlite3");
    let follower = SqliteCapabilityAuthority::open_with_clock(
        &follower_path,
        chio_test_support::clock::clock(),
    )?;
    let follower_key = follower.local_keypair()?.public_key();
    let anchor = source.initialize_replication("behavioral-local-observation")?;
    follower.pin_replication_anchor(&anchor)?;
    source.rotate()?;
    assert!(follower.apply_signed_snapshot(&source.signed_snapshot()?)?);
    let replicated_head = follower.status()?.public_key;
    assert_ne!(replicated_head, follower_key);
    let custody_refusal = format!(
        "local signing seed public key {} does not match replicated authority public key {}",
        follower_key.to_hex(),
        replicated_head.to_hex(),
    );
    assert!(matches!(
        follower.current_keypair(),
        Err(chio_kernel::AuthorityStoreError::Fence(reason)) if reason == custody_refusal
    ));

    let receipts = SqliteReceiptStore::open(directory.path().join("receipts.sqlite3"))?;
    let feed = super::super::reports::build_signed_behavioral_feed(
        &receipts,
        None,
        None,
        Some(&follower_path),
        &BehavioralFeedQuery {
            read_context: Some(chio_kernel::ReceiptReadContext::admin_service()),
            ..BehavioralFeedQuery::default()
        },
    )?;
    assert_eq!(feed.signer_key, follower_key);
    assert!(feed.verify_signature()?);
    Ok(())
}
