use std::sync::{Arc, Barrier};

use super::*;

fn app_binding() -> MobileAttestationBinding {
    MobileAttestationBinding::AppAttest {
        key_id: "app-attest-key-1".to_string(),
        app_id: "TEAMID.dev.chio.app".to_string(),
        audience: "urn:chio:mobile:production".to_string(),
    }
}

fn play_binding() -> MobileAttestationBinding {
    MobileAttestationBinding::PlayIntegrity {
        package_name: "dev.chio.app".to_string(),
        audience: "urn:chio:mobile:production".to_string(),
    }
}

fn challenge(
    binding: MobileAttestationBinding,
    nonce_byte: u8,
    issued_at: u64,
) -> IssuedMobileChallenge {
    match build_challenge(
        binding,
        [nonce_byte; MOBILE_CHALLENGE_BYTES],
        issued_at,
        issued_at + 300,
    ) {
        Ok(challenge) => challenge,
        Err(error) => panic!("challenge fixture must build: {error}"),
    }
}

#[cfg(all(feature = "sqlite-store", unix))]
fn secure_sqlite_tempdir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("mobile challenge directory must construct: {error}"));
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|error| panic!("mobile challenge directory must harden: {error}"));
    directory
}

#[test]
fn issued_challenge_binds_nonce_application_and_validity() {
    let store: Arc<dyn MobileChallengeStore> = Arc::new(InMemoryMobileChallengeStore::new());
    let authority = MobileChallengeAuthority::new(store);
    let issued = match authority.issue(play_binding(), 1_000) {
        Ok(issued) => issued,
        Err(error) => panic!("challenge issue must succeed: {error}"),
    };
    assert_eq!(issued.schema, MOBILE_CHALLENGE_SCHEMA);
    assert_eq!(issued.expires_at_unix_seconds, 1_300);
    assert!(issued.validate().is_ok());

    let mut tampered = issued;
    tampered.binding = MobileAttestationBinding::PlayIntegrity {
        package_name: "dev.chio.attacker".to_string(),
        audience: "urn:chio:mobile:production".to_string(),
    };
    assert!(matches!(
        tampered.validate(),
        Err(MobileChallengeError::Invalid(_))
    ));
}

#[test]
fn in_memory_challenge_is_consumed_exactly_once() {
    let store = InMemoryMobileChallengeStore::new();
    let issued = challenge(play_binding(), 1, 1_000);
    assert!(matches!(store.register_if_absent(&issued), Ok(true)));
    let snapshot = match store.load_active(&issued.challenge_id, 1_001) {
        Ok(snapshot) => snapshot,
        Err(error) => panic!("issued challenge must load: {error}"),
    };
    if let Err(error) = store.consume_verified(&snapshot, None, 1_002) {
        panic!("first challenge consume must succeed: {error}");
    }
    let replay = store.load_active(&issued.challenge_id, 1_003);
    assert!(matches!(replay, Err(MobileChallengeError::Replayed { .. })));
}

#[test]
fn invalid_platform_verification_does_not_consume_challenge() {
    let store = Arc::new(InMemoryMobileChallengeStore::new());
    let authority = MobileChallengeAuthority::new(store.clone());
    let issued = match authority.issue(app_binding(), 2_000) {
        Ok(issued) => issued,
        Err(error) => panic!("challenge issue must succeed: {error}"),
    };
    assert!(matches!(
        authority.verify_play_integrity_and_consume(&issued.challenge_id, "not-a-token", 2_001),
        Err(MobileChallengeError::Invalid(_))
    ));
    assert!(store.load_active(&issued.challenge_id, 2_002).is_ok());
}

#[test]
fn app_attest_counter_advance_is_atomic_with_challenge_consume() {
    let store = InMemoryMobileChallengeStore::new();
    let first = challenge(app_binding(), 2, 3_000);
    assert!(matches!(store.register_if_absent(&first), Ok(true)));
    let first_snapshot = match store.load_active(&first.challenge_id, 3_001) {
        Ok(snapshot) => snapshot,
        Err(error) => panic!("first App Attest challenge must load: {error}"),
    };
    assert_eq!(first_snapshot.previous_app_attest_counter(), None);
    if let Err(error) = store.consume_verified(&first_snapshot, Some(7), 3_002) {
        panic!("initial App Attest counter must commit: {error}");
    }

    let second = challenge(app_binding(), 3, 3_100);
    assert!(matches!(store.register_if_absent(&second), Ok(true)));
    let second_snapshot = match store.load_active(&second.challenge_id, 3_101) {
        Ok(snapshot) => snapshot,
        Err(error) => panic!("second App Attest challenge must load: {error}"),
    };
    assert_eq!(second_snapshot.previous_app_attest_counter(), Some(7));
    assert!(matches!(
        store.consume_verified(&second_snapshot, Some(7), 3_102),
        Err(MobileChallengeError::Attestation(
            AttestationError::CounterRollback
        ))
    ));
    if let Err(error) = store.consume_verified(&second_snapshot, Some(8), 3_103) {
        panic!("advancing counter must consume the still-active challenge: {error}");
    }
}

#[test]
fn concurrent_app_attest_challenges_compare_and_swap_counter_state() {
    let store = InMemoryMobileChallengeStore::new();
    let first = challenge(app_binding(), 4, 4_000);
    let second = challenge(app_binding(), 5, 4_000);
    assert!(matches!(store.register_if_absent(&first), Ok(true)));
    assert!(matches!(store.register_if_absent(&second), Ok(true)));
    let first_snapshot = match store.load_active(&first.challenge_id, 4_001) {
        Ok(snapshot) => snapshot,
        Err(error) => panic!("first concurrent challenge must load: {error}"),
    };
    let second_snapshot = match store.load_active(&second.challenge_id, 4_001) {
        Ok(snapshot) => snapshot,
        Err(error) => panic!("second concurrent challenge must load: {error}"),
    };
    if let Err(error) = store.consume_verified(&first_snapshot, Some(1), 4_002) {
        panic!("first counter transition must commit: {error}");
    }
    assert!(matches!(
        store.consume_verified(&second_snapshot, Some(2), 4_003),
        Err(MobileChallengeError::Invalid(_))
    ));
}

#[test]
fn expired_challenges_fail_closed_and_gc_reopens_capacity() {
    let store = match InMemoryMobileChallengeStore::with_limits(1, 1) {
        Ok(store) => store,
        Err(error) => panic!("bounded store must construct: {error}"),
    };
    let expired = challenge(play_binding(), 6, 5_000);
    assert!(matches!(store.register_if_absent(&expired), Ok(true)));
    assert!(matches!(
        store.load_active(&expired.challenge_id, 4_999),
        Err(MobileChallengeError::Invalid(_))
    ));
    assert!(matches!(
        store.load_active(&expired.challenge_id, 5_300),
        Err(MobileChallengeError::Invalid(_))
    ));
    let blocked = challenge(play_binding(), 7, 5_300);
    assert!(matches!(
        store.register_if_absent(&blocked),
        Err(MobileChallengeError::StoreUnavailable(_))
    ));
    assert!(matches!(store.gc_expired(5_300), Ok(1)));
    assert!(matches!(store.register_if_absent(&blocked), Ok(true)));
}

#[test]
fn mobile_challenge_errors_keep_stable_urns() {
    assert_eq!(
        MobileChallengeError::Invalid("invalid".to_string()).urn(),
        URN_MOBILE_CHALLENGE_INVALID
    );
    assert_eq!(
        MobileChallengeError::Replayed {
            challenge_id: "a".repeat(64)
        }
        .urn(),
        URN_MOBILE_CHALLENGE_REPLAYED
    );
    assert_eq!(
        MobileChallengeError::StoreUnavailable("offline".to_string()).urn(),
        URN_MOBILE_CHALLENGE_STORE_UNAVAILABLE
    );
    assert_eq!(
        MobileChallengeError::Attestation(AttestationError::CounterRollback).urn(),
        crate::attestation::errors::URN_APP_ATTEST_COUNTER_ROLLBACK
    );
}

#[cfg(all(feature = "sqlite-store", unix))]
#[test]
fn sqlite_single_use_and_counter_state_survive_reopen() {
    let directory = secure_sqlite_tempdir();
    let path = directory.path().join("mobile-challenges.sqlite3");
    let first = challenge(app_binding(), 8, 6_000);
    {
        let store = SqliteMobileChallengeStore::open(&path)
            .unwrap_or_else(|error| panic!("SQLite challenge store must open: {error}"));
        assert!(matches!(store.register_if_absent(&first), Ok(true)));
        let snapshot = store
            .load_active(&first.challenge_id, 6_001)
            .unwrap_or_else(|error| panic!("SQLite challenge must load: {error}"));
        store
            .consume_verified(&snapshot, Some(11), 6_002)
            .unwrap_or_else(|error| panic!("SQLite challenge must consume: {error}"));
    }
    let reopened = SqliteMobileChallengeStore::open(&path)
        .unwrap_or_else(|error| panic!("SQLite challenge store must reopen: {error}"));
    assert!(matches!(
        reopened.load_active(&first.challenge_id, 6_003),
        Err(MobileChallengeError::Replayed { .. })
    ));
    let second = challenge(app_binding(), 9, 6_100);
    assert!(matches!(reopened.register_if_absent(&second), Ok(true)));
    let snapshot = reopened
        .load_active(&second.challenge_id, 6_101)
        .unwrap_or_else(|error| panic!("second SQLite challenge must load: {error}"));
    assert_eq!(snapshot.previous_app_attest_counter(), Some(11));
}

#[cfg(all(feature = "sqlite-store", unix))]
#[test]
fn sqlite_parallel_consumers_admit_exactly_one() {
    let directory = secure_sqlite_tempdir();
    let path = directory.path().join("mobile-challenge-race.sqlite3");
    let writer = SqliteMobileChallengeStore::open(&path)
        .unwrap_or_else(|error| panic!("SQLite challenge store must open: {error}"));
    let issued = challenge(play_binding(), 10, 7_000);
    assert!(matches!(writer.register_if_absent(&issued), Ok(true)));
    let first = Arc::new(
        SqliteMobileChallengeStore::open(&path)
            .unwrap_or_else(|error| panic!("first race store must open: {error}")),
    );
    let second = Arc::new(
        SqliteMobileChallengeStore::open(&path)
            .unwrap_or_else(|error| panic!("second race store must open: {error}")),
    );
    let first_snapshot = first
        .load_active(&issued.challenge_id, 7_001)
        .unwrap_or_else(|error| panic!("first race snapshot must load: {error}"));
    let second_snapshot = second
        .load_active(&issued.challenge_id, 7_001)
        .unwrap_or_else(|error| panic!("second race snapshot must load: {error}"));
    let barrier = Arc::new(Barrier::new(3));
    let first_barrier = Arc::clone(&barrier);
    let first_thread = std::thread::spawn(move || {
        first_barrier.wait();
        first.consume_verified(&first_snapshot, None, 7_002)
    });
    let second_barrier = Arc::clone(&barrier);
    let second_thread = std::thread::spawn(move || {
        second_barrier.wait();
        second.consume_verified(&second_snapshot, None, 7_002)
    });
    barrier.wait();
    let first_result = first_thread
        .join()
        .unwrap_or_else(|error| panic!("first consumer thread panicked: {error:?}"));
    let second_result = second_thread
        .join()
        .unwrap_or_else(|error| panic!("second consumer thread panicked: {error:?}"));
    let successes = usize::from(first_result.is_ok()) + usize::from(second_result.is_ok());
    assert_eq!(successes, 1, "exactly one consumer must commit");
    let replays = [first_result, second_result]
        .into_iter()
        .filter(|result| matches!(result, Err(MobileChallengeError::Replayed { .. })))
        .count();
    assert_eq!(replays, 1, "the losing consumer must observe replay");
}

#[cfg(feature = "sqlite-store")]
#[test]
fn sqlite_store_rejects_relative_production_paths() {
    assert!(matches!(
        SqliteMobileChallengeStore::open(std::path::Path::new("mobile.sqlite3")),
        Err(MobileChallengeError::Invalid(_))
    ));
    assert!(SqliteMobileChallengeStore::open_in_memory().is_ok());
}

#[cfg(all(feature = "sqlite-store", unix))]
#[test]
fn sqlite_store_fails_closed_when_database_permissions_drift() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = secure_sqlite_tempdir();
    let path = directory.path().join("mobile-challenge-mode.sqlite3");
    let store = SqliteMobileChallengeStore::open(&path)
        .unwrap_or_else(|error| panic!("SQLite challenge store must open: {error}"));
    let issued = challenge(play_binding(), 11, 8_000);
    assert!(matches!(store.register_if_absent(&issued), Ok(true)));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))
        .unwrap_or_else(|error| panic!("database permissions must change: {error}"));
    assert!(matches!(
        store.load_active(&issued.challenge_id, 8_001),
        Err(MobileChallengeError::StoreUnavailable(_))
    ));
}

#[cfg(all(feature = "sqlite-store", unix))]
#[test]
fn sqlite_store_fails_closed_when_database_identity_drifts() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = secure_sqlite_tempdir();
    let path = directory.path().join("mobile-challenge-identity.sqlite3");
    let displaced = directory.path().join("displaced.sqlite3");
    let store = SqliteMobileChallengeStore::open(&path)
        .unwrap_or_else(|error| panic!("SQLite challenge store must open: {error}"));
    let issued = challenge(play_binding(), 12, 9_000);
    assert!(matches!(store.register_if_absent(&issued), Ok(true)));
    std::fs::rename(&path, &displaced)
        .unwrap_or_else(|error| panic!("database must move: {error}"));
    std::fs::File::create(&path)
        .unwrap_or_else(|error| panic!("replacement database must construct: {error}"));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .unwrap_or_else(|error| panic!("replacement permissions must harden: {error}"));
    assert!(matches!(
        store.load_active(&issued.challenge_id, 9_001),
        Err(MobileChallengeError::StoreUnavailable(_))
    ));
}
