use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};

use chio_core::hashing::sha256;
use chio_security_types::ports::{
    Digest32, PortErrorKind, RecordId, SealedDecoyRegistryStore, TenantId,
    WatermarkObservationStore, WatermarkSequenceStore,
};
use chio_security_types::{
    DecoyAeadNonce, DecoyArtifactLookup, DecoyScan, DecoySurface, EncryptedDecoyEnvelope,
    SealedDecoyCasRequest, SealedDecoyRecord, SealedMarkerLookup, SealedPublicRefLookup,
    WatermarkObservation, WatermarkObservationResult, WatermarkSequenceKey,
    WatermarkSequenceReservation, WatermarkSequenceReservationResult,
};
use chio_store_sqlite::SqliteSealedDecoyRegistryStore;
use chio_test_support::prelude::*;
use rusqlite::{params, Connection};
use tempfile::TempDir;

const RECORDS_TABLE: &str = "sealed_decoy_records_v1";
const OPERATIONS_TABLE: &str = "sealed_decoy_operation_owners_v1";
const TRANSITIONS_TABLE: &str = "sealed_decoy_transitions_v1";
const SEQUENCE_HEADS_TABLE: &str = "watermark_sequence_heads_v1";
const SEQUENCE_OPERATIONS_TABLE: &str = "watermark_sequence_operations_v1";
const OBSERVATIONS_TABLE: &str = "watermark_observations_v1";

fn tenant(value: &str) -> TenantId {
    TenantId::new(value).test_expect("valid tenant")
}

fn record_id(value: impl Into<String>) -> RecordId {
    RecordId::new(value).test_expect("valid record id")
}

const fn token(fill: u8) -> Digest32 {
    Digest32::new([fill; 32])
}

fn hashed_token(domain: &[u8], secret: &[u8]) -> Digest32 {
    let mut input = Vec::with_capacity(domain.len() + secret.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(secret);
    let hash = sha256(&input);
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(hash.as_ref());
    Digest32::new(digest)
}

fn record(
    tenant_id: &TenantId,
    artifact: u8,
    surface: DecoySurface,
    marker: u8,
    version: u8,
    generation: u64,
    sealed_bytes: (u8, u8),
) -> SealedDecoyRecord {
    SealedDecoyRecord {
        tenant_id: tenant_id.clone(),
        artifact_token: token(artifact),
        public_ref_token: (surface == DecoySurface::SignedWatermark)
            .then(|| token(artifact ^ 0x80)),
        surface,
        marker_token: token(marker),
        version_hash: token(version),
        generation,
        nonce: DecoyAeadNonce::new([sealed_bytes.0; 12]),
        encrypted_envelope: EncryptedDecoyEnvelope::new(vec![sealed_bytes.1; 32])
            .test_expect("bounded encrypted envelope"),
    }
}

fn request(
    record: SealedDecoyRecord,
    expected_generation: Option<u64>,
    operation: u8,
    transition: u8,
) -> SealedDecoyCasRequest {
    SealedDecoyCasRequest {
        record,
        expected_generation,
        operation_token: token(operation),
        transition_token: token(transition),
    }
}

fn sequence_reservation(
    tenant_id: &TenantId,
    key_suffix: &str,
    public_ref: u8,
    sequence: u64,
    operation_id: &str,
) -> WatermarkSequenceReservation {
    WatermarkSequenceReservation {
        key: WatermarkSequenceKey {
            tenant_id: tenant_id.clone(),
            application_id: record_id(format!("application-{key_suffix}")),
            session_id: record_id(format!("session-{key_suffix}")),
            tool_id: record_id(format!("tool-{key_suffix}")),
            public_ref_token: token(public_ref),
        },
        sequence,
        operation_id: record_id(operation_id),
    }
}

fn observation(
    source_tenant_id: &TenantId,
    observing_tenant_id: &TenantId,
    public_ref: u8,
    observation_id: &str,
) -> WatermarkObservation {
    WatermarkObservation {
        source_tenant_id: source_tenant_id.clone(),
        observing_tenant_id: observing_tenant_id.clone(),
        public_ref_token: token(public_ref),
        observation_id: record_id(observation_id),
        payload_digest: token(40),
        token_digest: token(41),
        evidence_ref: record_id("evidence-a"),
        observed_at_unix_ms: 1_000,
    }
}

fn database(temp: &TempDir, name: &str) -> PathBuf {
    temp.path().join(format!("{name}.sqlite3"))
}

fn open(path: &Path) -> SqliteSealedDecoyRegistryStore {
    SqliteSealedDecoyRegistryStore::open(path).test_expect("open sealed decoy registry")
}

fn assert_error_kind<T>(
    result: Result<T, chio_security_types::ports::PortError>,
    expected: PortErrorKind,
) {
    match result {
        Ok(_) => panic!("operation unexpectedly succeeded"),
        Err(error) => assert_eq!(error.kind(), expected),
    }
}

#[test]
fn durable_open_rejects_memory_uris_queries_and_fragments() {
    for path in [
        "",
        ":memory:",
        "file:sealed-decoy.sqlite3",
        "FiLe:sealed-decoy.sqlite3",
        "sealed-decoy.sqlite3?mode=rwc",
        "sealed-decoy.sqlite3#fragment",
    ] {
        assert_error_kind(
            SqliteSealedDecoyRegistryStore::open(path),
            PortErrorKind::InvalidData,
        );
    }
}

#[test]
fn durable_open_rejects_constraint_incompatible_preexisting_schema() {
    let temp = tempfile::tempdir().test_expect("temporary directory");
    let path = database(&temp, "weak-preexisting-schema");
    let raw = Connection::open(&path).test_expect("open weak schema fixture");
    raw.execute_batch(
        r#"
        CREATE TABLE sealed_decoy_records_v1 (
            tenant_id TEXT NOT NULL,
            artifact_token BLOB NOT NULL,
            public_ref_token BLOB,
            surface TEXT NOT NULL,
            marker_token BLOB NOT NULL,
            version_hash BLOB NOT NULL,
            generation INTEGER NOT NULL,
            nonce BLOB NOT NULL,
            ciphertext BLOB NOT NULL,
            PRIMARY KEY (tenant_id, artifact_token)
        ) STRICT, WITHOUT ROWID;
        "#,
    )
    .test_expect("create weak strict schema");
    drop(raw);

    assert_error_kind(
        SqliteSealedDecoyRegistryStore::open(&path),
        PortErrorKind::IntegrityFailure,
    );
}

#[test]
fn transition_replay_returns_original_snapshot_after_later_update_and_reopen() {
    let temp = tempfile::tempdir().test_expect("temporary directory");
    let path = database(&temp, "transition-replay");
    let tenant_id = tenant("tenant-a");
    let created = record(&tenant_id, 1, DecoySurface::BrowserCookie, 2, 3, 0, (4, 5));
    let create = request(created.clone(), None, 10, 20);
    let mut updated = created.clone();
    updated.generation = 1;
    updated.nonce = DecoyAeadNonce::new([6; 12]);
    updated.encrypted_envelope =
        EncryptedDecoyEnvelope::new(vec![7; 48]).test_expect("updated envelope");
    let update = request(updated.clone(), Some(0), 10, 21);

    {
        let store = open(&path);
        assert_eq!(store.compare_and_swap(&create).test_unwrap(), created);
        assert_eq!(store.compare_and_swap(&update).test_unwrap(), updated);
    }

    let reopened = open(&path);
    assert_eq!(reopened.compare_and_swap(&create).test_unwrap(), created);
    assert_eq!(reopened.compare_and_swap(&update).test_unwrap(), updated);
    assert_eq!(
        reopened
            .load_by_id(&DecoyArtifactLookup {
                tenant_id,
                artifact_token: token(1),
            })
            .test_unwrap(),
        Some(updated)
    );
}

#[test]
fn transition_replay_rejects_shape_valid_equal_generation_tampering() {
    let temp = tempfile::tempdir().test_expect("temporary directory");
    let path = database(&temp, "transition-valid-shape-tamper");
    let tenant_id = tenant("tenant-a");
    let created = record(&tenant_id, 1, DecoySurface::BrowserCookie, 2, 3, 0, (4, 5));
    let create = request(created, None, 10, 20);
    let store = open(&path);
    store.compare_and_swap(&create).test_unwrap();

    let raw = Connection::open(&path).test_expect("open raw transition tamper database");
    raw.execute(
        "UPDATE sealed_decoy_records_v1 SET nonce = ?1, ciphertext = ?2 \
         WHERE tenant_id = ?3 AND artifact_token = ?4",
        params![
            vec![9_u8; 12],
            vec![10_u8; 32],
            tenant_id.as_str(),
            &token(1).as_bytes()[..],
        ],
    )
    .test_expect("apply shape-valid current row tamper");
    assert_error_kind(
        store.compare_and_swap(&create),
        PortErrorKind::IntegrityFailure,
    );
}

#[test]
fn stable_operation_can_record_distinct_retry_transitions_for_one_artifact() {
    let temp = tempfile::tempdir().test_expect("temporary directory");
    let store = open(&database(&temp, "operation-retry"));
    let tenant_id = tenant("tenant-a");
    let first = record(&tenant_id, 1, DecoySurface::CredentialFile, 2, 3, 0, (4, 5));
    let first_request = request(first.clone(), None, 30, 40);
    store.compare_and_swap(&first_request).test_unwrap();

    let mut retry_result = first.clone();
    retry_result.generation = 1;
    retry_result.nonce = DecoyAeadNonce::new([8; 12]);
    retry_result.encrypted_envelope =
        EncryptedDecoyEnvelope::new(vec![9; 64]).test_expect("retry envelope");
    let retry_request = request(retry_result.clone(), Some(0), 30, 41);
    assert_eq!(
        store.compare_and_swap(&retry_request).test_unwrap(),
        retry_result
    );
    assert_eq!(store.compare_and_swap(&first_request).test_unwrap(), first);
}

#[test]
fn operation_reuse_across_artifacts_and_transition_mutation_conflict() {
    let temp = tempfile::tempdir().test_expect("temporary directory");
    let store = open(&database(&temp, "token-conflicts"));
    let tenant_id = tenant("tenant-a");
    let first = record(&tenant_id, 1, DecoySurface::HoneyTool, 2, 3, 0, (4, 5));
    let first_request = request(first.clone(), None, 50, 60);
    store.compare_and_swap(&first_request).test_unwrap();

    let second = record(&tenant_id, 6, DecoySurface::HoneyTool, 7, 8, 0, (9, 10));
    assert_error_kind(
        store.compare_and_swap(&request(second, None, 50, 61)),
        PortErrorKind::Conflict,
    );

    let mut changed_replay = first_request;
    changed_replay.expected_generation = Some(0);
    assert_error_kind(
        store.compare_and_swap(&changed_replay),
        PortErrorKind::Conflict,
    );
}

#[test]
fn marker_collision_is_tenant_and_surface_scoped() {
    let temp = tempfile::tempdir().test_expect("temporary directory");
    let store = open(&database(&temp, "marker-collision"));
    let tenant_id = tenant("tenant-a");
    let first = record(&tenant_id, 1, DecoySurface::FileMarker, 9, 2, 0, (3, 4));
    store
        .compare_and_swap(&request(first, None, 1, 11))
        .test_unwrap();

    let collision = record(&tenant_id, 2, DecoySurface::FileMarker, 9, 3, 0, (4, 5));
    assert_error_kind(
        store.compare_and_swap(&request(collision, None, 2, 12)),
        PortErrorKind::Conflict,
    );

    let other_surface = record(
        &tenant_id,
        3,
        DecoySurface::SignedWatermark,
        9,
        4,
        0,
        (5, 6),
    );
    store
        .compare_and_swap(&request(other_surface, None, 3, 13))
        .test_unwrap();
}

#[test]
fn public_reference_lookup_is_keyed_unique_and_tenant_scoped() {
    let temp = tempfile::tempdir().test_expect("temporary directory");
    let store = open(&database(&temp, "public-reference"));
    let tenant_a = tenant("tenant-a");
    let tenant_b = tenant("tenant-b");
    let first = record(&tenant_a, 1, DecoySurface::SignedWatermark, 2, 3, 0, (4, 5));
    let public_ref_token = first.public_ref_token.test_expect("public reference");
    store
        .compare_and_swap(&request(first.clone(), None, 10, 20))
        .test_unwrap();
    assert_eq!(
        store
            .load_by_public_ref(&SealedPublicRefLookup {
                tenant_id: tenant_a.clone(),
                public_ref_token,
            })
            .test_unwrap(),
        Some(first)
    );
    assert_eq!(
        store
            .load_by_public_ref(&SealedPublicRefLookup {
                tenant_id: tenant_b.clone(),
                public_ref_token,
            })
            .test_unwrap(),
        None
    );

    let mut collision = record(&tenant_a, 2, DecoySurface::SignedWatermark, 3, 4, 0, (5, 6));
    collision.public_ref_token = Some(public_ref_token);
    assert_error_kind(
        store.compare_and_swap(&request(collision, None, 11, 21)),
        PortErrorKind::Conflict,
    );

    let mut cross_tenant = record(&tenant_b, 2, DecoySurface::SignedWatermark, 3, 4, 0, (5, 6));
    cross_tenant.public_ref_token = Some(public_ref_token);
    store
        .compare_and_swap(&request(cross_tenant, None, 10, 20))
        .test_unwrap();

    let mut without_public_ref = record(&tenant_a, 3, DecoySurface::FileMarker, 4, 5, 0, (6, 7));
    without_public_ref.public_ref_token = None;
    store
        .compare_and_swap(&request(without_public_ref, None, 12, 22))
        .test_unwrap();
}

#[test]
fn public_reference_shape_follows_surface_lifecycle() {
    let temp = tempfile::tempdir().test_expect("temporary directory");
    let store = open(&database(&temp, "public-reference-shape"));
    let tenant_id = tenant("tenant-a");

    let mut unsigned_with_ref = record(&tenant_id, 1, DecoySurface::BrowserCookie, 2, 3, 0, (4, 5));
    unsigned_with_ref.public_ref_token = Some(token(80));
    assert_error_kind(
        store.compare_and_swap(&request(unsigned_with_ref, None, 10, 20)),
        PortErrorKind::InvalidData,
    );

    let mut watermark_without_ref = record(
        &tenant_id,
        2,
        DecoySurface::SignedWatermark,
        3,
        4,
        0,
        (5, 6),
    );
    watermark_without_ref.public_ref_token = None;
    assert_error_kind(
        store.compare_and_swap(&request(watermark_without_ref, None, 11, 21)),
        PortErrorKind::InvalidData,
    );
}

#[test]
fn cas_rejects_immutable_mutation_stale_state_and_generation_skips() {
    let temp = tempfile::tempdir().test_expect("temporary directory");
    let store = open(&database(&temp, "cas-invariants"));
    let tenant_id = tenant("tenant-a");
    let initial = record(
        &tenant_id,
        1,
        DecoySurface::CanaryCapability,
        2,
        3,
        0,
        (4, 5),
    );
    store
        .compare_and_swap(&request(initial.clone(), None, 10, 20))
        .test_unwrap();

    let mutations = [
        {
            let mut value = initial.clone();
            value.tenant_id = tenant("tenant-b");
            value.generation = 1;
            value
        },
        {
            let mut value = initial.clone();
            value.artifact_token = token(8);
            value.generation = 1;
            value
        },
        {
            let mut value = initial.clone();
            value.surface = DecoySurface::HoneyTool;
            value.generation = 1;
            value
        },
        {
            let mut value = initial.clone();
            value.marker_token = token(8);
            value.generation = 1;
            value
        },
        {
            let mut value = initial.clone();
            value.version_hash = token(8);
            value.generation = 1;
            value
        },
    ];
    for (index, mutation) in mutations.into_iter().enumerate() {
        assert_error_kind(
            store.compare_and_swap(&request(
                mutation,
                Some(0),
                30_u8.saturating_add(index as u8),
                40_u8.saturating_add(index as u8),
            )),
            PortErrorKind::Conflict,
        );
    }

    let watermark = record(
        &tenant_id,
        9,
        DecoySurface::SignedWatermark,
        10,
        11,
        0,
        (12, 13),
    );
    store
        .compare_and_swap(&request(watermark.clone(), None, 70, 80))
        .test_unwrap();
    let mut changed_public_ref = watermark;
    changed_public_ref.public_ref_token = Some(token(99));
    changed_public_ref.generation = 1;
    assert_error_kind(
        store.compare_and_swap(&request(changed_public_ref, Some(0), 71, 81)),
        PortErrorKind::Conflict,
    );

    let mut skipped = initial.clone();
    skipped.generation = 2;
    assert_error_kind(
        store.compare_and_swap(&request(skipped, Some(0), 50, 60)),
        PortErrorKind::Conflict,
    );

    let mut stale = initial.clone();
    stale.generation = 1;
    assert_error_kind(
        store.compare_and_swap(&request(stale, Some(9), 51, 61)),
        PortErrorKind::Conflict,
    );

    let invalid_create = record(
        &tenant("tenant-c"),
        1,
        DecoySurface::CanaryCapability,
        2,
        3,
        1,
        (4, 5),
    );
    assert_error_kind(
        store.compare_and_swap(&request(invalid_create, None, 52, 62)),
        PortErrorKind::Conflict,
    );

    let mut empty_ciphertext = record(
        &tenant("tenant-d"),
        1,
        DecoySurface::BrowserCookie,
        2,
        3,
        0,
        (4, 5),
    );
    empty_ciphertext.encrypted_envelope =
        EncryptedDecoyEnvelope::new(Vec::new()).test_expect("type permits empty envelope");
    assert_error_kind(
        store.compare_and_swap(&request(empty_ciphertext, None, 53, 63)),
        PortErrorKind::InvalidData,
    );
}

#[test]
fn concurrent_expected_generation_writers_have_one_winner() {
    let temp = tempfile::tempdir().test_expect("temporary directory");
    let path = database(&temp, "concurrent-cas");
    let tenant_id = tenant("tenant-a");
    let initial = record(
        &tenant_id,
        1,
        DecoySurface::InternalHostname,
        2,
        3,
        0,
        (4, 5),
    );
    open(&path)
        .compare_and_swap(&request(initial.clone(), None, 1, 2))
        .test_unwrap();

    let mut left = initial.clone();
    left.generation = 1;
    left.nonce = DecoyAeadNonce::new([10; 12]);
    left.encrypted_envelope =
        EncryptedDecoyEnvelope::new(vec![11; 32]).test_expect("left envelope");
    let mut right = initial;
    right.generation = 1;
    right.nonce = DecoyAeadNonce::new([12; 12]);
    right.encrypted_envelope =
        EncryptedDecoyEnvelope::new(vec![13; 32]).test_expect("right envelope");

    let barrier = Arc::new(Barrier::new(2));
    let left_barrier = Arc::clone(&barrier);
    let left_path = path.clone();
    let left_thread = std::thread::spawn(move || {
        let store = open(&left_path);
        left_barrier.wait();
        store.compare_and_swap(&request(left, Some(0), 20, 21))
    });
    let right_barrier = Arc::clone(&barrier);
    let right_path = path.clone();
    let right_thread = std::thread::spawn(move || {
        let store = open(&right_path);
        right_barrier.wait();
        store.compare_and_swap(&request(right, Some(0), 20, 22))
    });

    let left_result = match left_thread.join() {
        Ok(result) => result,
        Err(_) => panic!("left writer panicked"),
    };
    let right_result = match right_thread.join() {
        Ok(result) => result,
        Err(_) => panic!("right writer panicked"),
    };
    let results = [left_result, right_result];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| result
                .as_ref()
                .is_err_and(|error| error.kind() == PortErrorKind::Conflict))
            .count(),
        1
    );

    let current = open(&path)
        .load_by_id(&DecoyArtifactLookup {
            tenant_id,
            artifact_token: token(1),
        })
        .test_unwrap()
        .test_expect("winner persisted");
    assert_eq!(current.generation, 1);
    assert!(matches!(current.nonce.as_bytes()[0], 10 | 12));
}

#[test]
fn every_read_surface_is_tenant_isolated() {
    let temp = tempfile::tempdir().test_expect("temporary directory");
    let store = open(&database(&temp, "tenant-isolation"));
    let tenant_a = tenant("tenant-a");
    let tenant_b = tenant("tenant-b");
    let record_a = record(&tenant_a, 1, DecoySurface::BrowserCookie, 2, 3, 0, (4, 5));
    let record_b = record(&tenant_b, 1, DecoySurface::BrowserCookie, 2, 3, 0, (6, 7));
    store
        .compare_and_swap(&request(record_a.clone(), None, 8, 9))
        .test_unwrap();
    store
        .compare_and_swap(&request(record_b.clone(), None, 8, 9))
        .test_unwrap();

    assert_eq!(
        store
            .load_by_id(&DecoyArtifactLookup {
                tenant_id: tenant_a.clone(),
                artifact_token: token(1),
            })
            .test_unwrap(),
        Some(record_a.clone())
    );
    assert_eq!(
        store
            .load_by_id(&DecoyArtifactLookup {
                tenant_id: tenant_b.clone(),
                artifact_token: token(1),
            })
            .test_unwrap(),
        Some(record_b.clone())
    );
    assert_eq!(
        store
            .load_by_marker(&SealedMarkerLookup {
                tenant_id: tenant_a.clone(),
                surface: DecoySurface::BrowserCookie,
                marker_token: token(2),
            })
            .test_unwrap(),
        Some(record_a)
    );
    assert_eq!(
        store
            .load_by_marker(&SealedMarkerLookup {
                tenant_id: tenant_b.clone(),
                surface: DecoySurface::BrowserCookie,
                marker_token: token(2),
            })
            .test_unwrap(),
        Some(record_b)
    );
    assert_eq!(
        store
            .scan(&DecoyScan {
                tenant_id: tenant_a,
                after_artifact_token: None,
                limit: 10,
            })
            .test_unwrap()
            .records
            .len(),
        1
    );
    assert_eq!(
        store
            .scan(&DecoyScan {
                tenant_id: tenant_b,
                after_artifact_token: None,
                limit: 10,
            })
            .test_unwrap()
            .records
            .len(),
        1
    );
}

#[test]
fn scan_uses_byte_ordered_opaque_cursor_without_duplicates() {
    let temp = tempfile::tempdir().test_expect("temporary directory");
    let store = open(&database(&temp, "cursor-scan"));
    let tenant_id = tenant("tenant-a");
    for artifact in [3_u8, 1, 5, 2, 4] {
        let value = record(
            &tenant_id,
            artifact,
            DecoySurface::CredentialArtifact,
            artifact,
            99,
            0,
            (artifact, artifact),
        );
        store
            .compare_and_swap(&request(
                value,
                None,
                artifact.saturating_add(10),
                artifact.saturating_add(20),
            ))
            .test_unwrap();
    }

    let first = store
        .scan(&DecoyScan {
            tenant_id: tenant_id.clone(),
            after_artifact_token: None,
            limit: 2,
        })
        .test_unwrap();
    assert_eq!(
        first
            .records
            .as_slice()
            .iter()
            .map(|row| row.artifact_token)
            .collect::<Vec<_>>(),
        vec![token(1), token(2)]
    );
    assert_eq!(first.next_artifact_token, Some(token(2)));

    let second = store
        .scan(&DecoyScan {
            tenant_id: tenant_id.clone(),
            after_artifact_token: first.next_artifact_token,
            limit: 2,
        })
        .test_unwrap();
    assert_eq!(
        second
            .records
            .as_slice()
            .iter()
            .map(|row| row.artifact_token)
            .collect::<Vec<_>>(),
        vec![token(3), token(4)]
    );
    assert_eq!(second.next_artifact_token, Some(token(4)));

    let third = store
        .scan(&DecoyScan {
            tenant_id: tenant_id.clone(),
            after_artifact_token: second.next_artifact_token,
            limit: 2,
        })
        .test_unwrap();
    assert_eq!(
        third
            .records
            .as_slice()
            .iter()
            .map(|row| row.artifact_token)
            .collect::<Vec<_>>(),
        vec![token(5)]
    );
    assert_eq!(third.next_artifact_token, None);

    for limit in [0, 257] {
        assert_error_kind(
            store.scan(&DecoyScan {
                tenant_id: tenant_id.clone(),
                after_artifact_token: None,
                limit,
            }),
            PortErrorKind::InvalidData,
        );
    }
}

#[test]
fn watermark_sequence_reservation_is_durable_monotonic_and_exactly_idempotent() {
    let temp = tempfile::tempdir().test_expect("temporary directory");
    let path = database(&temp, "watermark-sequence-durable");
    let tenant_id = tenant("tenant-a");
    let first = sequence_reservation(&tenant_id, "a", 90, 1, "sequence-operation-a");
    {
        let store = open(&path);
        assert_eq!(
            store.reserve(&first).test_unwrap(),
            WatermarkSequenceReservationResult::Reserved
        );
    }

    let reopened = open(&path);
    assert_eq!(
        reopened.reserve(&first).test_unwrap(),
        WatermarkSequenceReservationResult::ExactRetry
    );

    let mut reused_operation = first.clone();
    reused_operation.sequence = 2;
    assert_error_kind(reopened.reserve(&reused_operation), PortErrorKind::Conflict);
    assert_error_kind(
        reopened.reserve(&sequence_reservation(
            &tenant_id,
            "a",
            90,
            1,
            "sequence-operation-b",
        )),
        PortErrorKind::Conflict,
    );
    assert_error_kind(
        reopened.reserve(&sequence_reservation(
            &tenant_id,
            "a",
            90,
            0,
            "sequence-operation-zero",
        )),
        PortErrorKind::InvalidData,
    );
    assert_eq!(
        reopened
            .reserve(&sequence_reservation(
                &tenant_id,
                "a",
                90,
                2,
                "sequence-operation-c",
            ))
            .test_unwrap(),
        WatermarkSequenceReservationResult::Reserved
    );
    assert_error_kind(
        reopened.reserve(&sequence_reservation(
            &tenant_id,
            "a",
            90,
            1,
            "sequence-operation-d",
        )),
        PortErrorKind::Conflict,
    );
    drop(reopened);

    assert_eq!(
        open(&path)
            .reserve(&sequence_reservation(
                &tenant_id,
                "a",
                90,
                3,
                "sequence-operation-e",
            ))
            .test_unwrap(),
        WatermarkSequenceReservationResult::Reserved
    );
    assert_eq!(
        open(&path).reserve(&first).test_unwrap(),
        WatermarkSequenceReservationResult::ExactRetry
    );
}

#[test]
fn watermark_sequence_operation_ids_are_tenant_wide() {
    let temp = tempfile::tempdir().test_expect("temporary directory");
    let store = open(&database(&temp, "watermark-sequence-operation-scope"));
    let tenant_a = tenant("tenant-a");
    let tenant_b = tenant("tenant-b");
    let first = sequence_reservation(&tenant_a, "a", 90, 1, "shared-operation");
    assert_eq!(
        store.reserve(&first).test_unwrap(),
        WatermarkSequenceReservationResult::Reserved
    );
    assert_error_kind(
        store.reserve(&sequence_reservation(
            &tenant_a,
            "different-key",
            91,
            1,
            "shared-operation",
        )),
        PortErrorKind::Conflict,
    );
    assert_eq!(
        store
            .reserve(&sequence_reservation(
                &tenant_b,
                "different-key",
                91,
                1,
                "shared-operation",
            ))
            .test_unwrap(),
        WatermarkSequenceReservationResult::Reserved
    );
}

#[test]
fn concurrent_watermark_sequence_writers_have_one_winner() {
    const WRITERS: usize = 8;

    let temp = tempfile::tempdir().test_expect("temporary directory");
    let path = database(&temp, "watermark-sequence-concurrent");
    open(&path);
    let barrier = Arc::new(Barrier::new(WRITERS));
    let mut threads = Vec::with_capacity(WRITERS);
    for writer in 0..WRITERS {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            let store = open(&path);
            let request = sequence_reservation(
                &tenant("tenant-a"),
                "shared",
                90,
                1,
                &format!("writer-{writer}"),
            );
            barrier.wait();
            let result = store.reserve(&request);
            (request, result)
        }));
    }

    let mut results = Vec::with_capacity(WRITERS);
    for thread in threads {
        match thread.join() {
            Ok(result) => results.push(result),
            Err(_) => panic!("watermark sequence writer panicked"),
        }
    }
    assert_eq!(
        results
            .iter()
            .filter(|(_, result)| matches!(
                result,
                Ok(WatermarkSequenceReservationResult::Reserved)
            ))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|(_, result)| result
                .as_ref()
                .is_err_and(|error| error.kind() == PortErrorKind::Conflict))
            .count(),
        WRITERS - 1
    );
    let winner = results
        .into_iter()
        .find_map(|(request, result)| {
            matches!(result, Ok(WatermarkSequenceReservationResult::Reserved)).then_some(request)
        })
        .test_expect("one winning reservation");
    let store = open(&path);
    assert_eq!(
        store.reserve(&winner).test_unwrap(),
        WatermarkSequenceReservationResult::ExactRetry
    );
    assert_eq!(
        store
            .reserve(&sequence_reservation(
                &tenant("tenant-a"),
                "shared",
                90,
                2,
                "next-writer",
            ))
            .test_unwrap(),
        WatermarkSequenceReservationResult::Reserved
    );
}

#[test]
fn concurrent_identical_sequence_retries_are_exactly_idempotent() {
    const WRITERS: usize = 8;

    let temp = tempfile::tempdir().test_expect("temporary directory");
    let path = database(&temp, "watermark-sequence-identical-concurrent");
    open(&path);
    let barrier = Arc::new(Barrier::new(WRITERS));
    let request = Arc::new(sequence_reservation(
        &tenant("tenant-a"),
        "shared",
        90,
        1,
        "shared-operation",
    ));
    let mut threads = Vec::with_capacity(WRITERS);
    for _ in 0..WRITERS {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        let request = Arc::clone(&request);
        threads.push(std::thread::spawn(move || {
            let store = open(&path);
            barrier.wait();
            store.reserve(request.as_ref())
        }));
    }

    let mut results = Vec::with_capacity(WRITERS);
    for thread in threads {
        match thread.join() {
            Ok(result) => results.push(result),
            Err(_) => panic!("identical sequence retry writer panicked"),
        }
    }
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Ok(WatermarkSequenceReservationResult::Reserved)))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Ok(WatermarkSequenceReservationResult::ExactRetry)))
            .count(),
        WRITERS - 1
    );
}

#[test]
fn watermark_observation_retry_preserves_first_attribution_and_rejects_mutation() {
    let temp = tempfile::tempdir().test_expect("temporary directory");
    let path = database(&temp, "watermark-observation-durable");
    let first = observation(
        &tenant("source-tenant"),
        &tenant("observing-tenant"),
        90,
        "observation-a",
    );
    {
        let store = open(&path);
        assert_eq!(
            store.record_first(&first).test_unwrap(),
            WatermarkObservationResult::Recorded
        );
    }

    let reopened = open(&path);
    assert_eq!(
        reopened.record_first(&first).test_unwrap(),
        WatermarkObservationResult::Duplicate {
            first_payload_digest: first.payload_digest,
            first_token_digest: first.token_digest,
            first_evidence_ref: first.evidence_ref.clone(),
            first_observed_at_unix_ms: first.observed_at_unix_ms,
        }
    );

    let mutations = [
        {
            let mut value = first.clone();
            value.observing_tenant_id = tenant("other-observer");
            value
        },
        {
            let mut value = first.clone();
            value.payload_digest = token(50);
            value
        },
        {
            let mut value = first.clone();
            value.token_digest = token(51);
            value
        },
        {
            let mut value = first.clone();
            value.evidence_ref = record_id("evidence-b");
            value
        },
        {
            let mut value = first.clone();
            value.observed_at_unix_ms = 2_000;
            value
        },
    ];
    for mutation in mutations {
        assert_error_kind(reopened.record_first(&mutation), PortErrorKind::Conflict);
    }
}

#[test]
fn concurrent_distinct_watermark_observations_never_misreport_duplicates() {
    const WRITERS: usize = 8;

    let temp = tempfile::tempdir().test_expect("temporary directory");
    let path = database(&temp, "watermark-observation-concurrent");
    open(&path);
    let barrier = Arc::new(Barrier::new(WRITERS));
    let mut threads = Vec::with_capacity(WRITERS);
    for writer in 0..WRITERS {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            let store = open(&path);
            let mut value = observation(
                &tenant("source-tenant"),
                &tenant("observing-tenant"),
                90,
                "shared-observation",
            );
            value.payload_digest = token(60_u8.saturating_add(writer as u8));
            value.token_digest = token(80_u8.saturating_add(writer as u8));
            barrier.wait();
            let result = store.record_first(&value);
            (value, result)
        }));
    }

    let mut results = Vec::with_capacity(WRITERS);
    for thread in threads {
        match thread.join() {
            Ok(result) => results.push(result),
            Err(_) => panic!("watermark observation writer panicked"),
        }
    }
    assert_eq!(
        results
            .iter()
            .filter(|(_, result)| matches!(result, Ok(WatermarkObservationResult::Recorded)))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|(_, result)| result
                .as_ref()
                .is_err_and(|error| error.kind() == PortErrorKind::Conflict))
            .count(),
        WRITERS - 1
    );
    assert!(results
        .iter()
        .all(|(_, result)| !matches!(result, Ok(WatermarkObservationResult::Duplicate { .. }))));

    let winner = results
        .into_iter()
        .find_map(|(value, result)| {
            matches!(result, Ok(WatermarkObservationResult::Recorded)).then_some(value)
        })
        .test_expect("one first observation");
    assert_eq!(
        open(&path).record_first(&winner).test_unwrap(),
        WatermarkObservationResult::Duplicate {
            first_payload_digest: winner.payload_digest,
            first_token_digest: winner.token_digest,
            first_evidence_ref: winner.evidence_ref.clone(),
            first_observed_at_unix_ms: winner.observed_at_unix_ms,
        }
    );
}

#[test]
fn concurrent_identical_observations_preserve_one_first_attribution() {
    const WRITERS: usize = 8;

    let temp = tempfile::tempdir().test_expect("temporary directory");
    let path = database(&temp, "watermark-observation-identical-concurrent");
    open(&path);
    let barrier = Arc::new(Barrier::new(WRITERS));
    let first = Arc::new(observation(
        &tenant("source-tenant"),
        &tenant("observing-tenant"),
        90,
        "shared-observation",
    ));
    let mut threads = Vec::with_capacity(WRITERS);
    for _ in 0..WRITERS {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        let first = Arc::clone(&first);
        threads.push(std::thread::spawn(move || {
            let store = open(&path);
            barrier.wait();
            store.record_first(first.as_ref())
        }));
    }

    let mut results = Vec::with_capacity(WRITERS);
    for thread in threads {
        match thread.join() {
            Ok(result) => results.push(result),
            Err(_) => panic!("identical observation writer panicked"),
        }
    }
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Ok(WatermarkObservationResult::Recorded)))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Ok(WatermarkObservationResult::Duplicate { .. })))
            .count(),
        WRITERS - 1
    );
    let expected_duplicate = WatermarkObservationResult::Duplicate {
        first_payload_digest: first.payload_digest,
        first_token_digest: first.token_digest,
        first_evidence_ref: first.evidence_ref.clone(),
        first_observed_at_unix_ms: first.observed_at_unix_ms,
    };
    assert!(results.iter().all(|result| {
        matches!(result, Ok(WatermarkObservationResult::Recorded))
            || result.as_ref() == Ok(&expected_duplicate)
    }));
}

#[test]
fn watermark_observation_identity_is_source_tenant_scoped() {
    let temp = tempfile::tempdir().test_expect("temporary directory");
    let store = open(&database(&temp, "watermark-observation-tenant-scope"));
    let first = observation(
        &tenant("source-a"),
        &tenant("observing-tenant"),
        90,
        "shared-observation",
    );
    let second = observation(
        &tenant("source-b"),
        &tenant("observing-tenant"),
        90,
        "shared-observation",
    );
    assert_eq!(
        store.record_first(&first).test_unwrap(),
        WatermarkObservationResult::Recorded
    );
    assert_eq!(
        store.record_first(&second).test_unwrap(),
        WatermarkObservationResult::Recorded
    );
}

#[test]
fn malformed_watermark_state_fails_closed() {
    let temp = tempfile::tempdir().test_expect("temporary directory");
    let sequence_path = database(&temp, "malformed-watermark-sequence");
    let tenant_id = tenant("tenant-a");
    let reservation = sequence_reservation(&tenant_id, "a", 90, 1, "sequence-operation-a");
    let sequence_store = open(&sequence_path);
    sequence_store.reserve(&reservation).test_unwrap();
    let raw = Connection::open(&sequence_path).test_expect("open raw sequence database");
    raw.execute_batch("PRAGMA ignore_check_constraints = ON;")
        .test_expect("disable sequence checks for corruption fixture");
    raw.execute(
        "UPDATE watermark_sequence_heads_v1 SET last_sequence = 0 WHERE tenant_id = ?1",
        [tenant_id.as_str()],
    )
    .test_expect("corrupt sequence head");
    assert_error_kind(
        sequence_store.reserve(&reservation),
        PortErrorKind::IntegrityFailure,
    );
    raw.execute(
        "UPDATE watermark_sequence_heads_v1 SET last_sequence = 1 WHERE tenant_id = ?1",
        [tenant_id.as_str()],
    )
    .test_expect("restore sequence head");
    raw.execute(
        "UPDATE watermark_sequence_operations_v1 SET request_hash = zeroblob(31) \
         WHERE tenant_id = ?1",
        [tenant_id.as_str()],
    )
    .test_expect("corrupt sequence operation hash");
    assert_error_kind(
        sequence_store.reserve(&reservation),
        PortErrorKind::IntegrityFailure,
    );

    let observation_path = database(&temp, "malformed-watermark-observation");
    let observation_store = open(&observation_path);
    let first = observation(
        &tenant("source-tenant"),
        &tenant("observing-tenant"),
        90,
        "observation-a",
    );
    observation_store.record_first(&first).test_unwrap();
    let raw = Connection::open(&observation_path).test_expect("open raw observation database");
    raw.execute_batch("PRAGMA ignore_check_constraints = ON;")
        .test_expect("disable observation checks for corruption fixture");
    raw.execute(
        "UPDATE watermark_observations_v1 SET token_digest = zeroblob(31) \
         WHERE source_tenant_id = ?1",
        [first.source_tenant_id.as_str()],
    )
    .test_expect("corrupt observation digest");
    assert_error_kind(
        observation_store.record_first(&first),
        PortErrorKind::IntegrityFailure,
    );
}

#[test]
fn malformed_record_and_transition_rows_fail_closed() {
    let temp = tempfile::tempdir().test_expect("temporary directory");
    let record_path = database(&temp, "malformed-record");
    let tenant_id = tenant("tenant-a");
    let stored = record(&tenant_id, 1, DecoySurface::BrowserCookie, 2, 3, 0, (4, 5));
    let store = open(&record_path);
    store
        .compare_and_swap(&request(stored.clone(), None, 6, 7))
        .test_unwrap();
    let raw = Connection::open(&record_path).test_expect("open raw record database");
    raw.execute_batch("PRAGMA ignore_check_constraints = ON;")
        .test_expect("disable checks for corruption fixture");
    raw.execute(
        "UPDATE sealed_decoy_records_v1 SET nonce = zeroblob(11) \
         WHERE tenant_id = ?1 AND artifact_token = ?2",
        params![tenant_id.as_str(), token(1).as_bytes().as_slice()],
    )
    .test_expect("corrupt record nonce");
    assert_error_kind(
        store.load_by_id(&DecoyArtifactLookup {
            tenant_id: tenant_id.clone(),
            artifact_token: token(1),
        }),
        PortErrorKind::IntegrityFailure,
    );

    let transition_path = database(&temp, "malformed-transition");
    let transition_store = open(&transition_path);
    let transition_request = request(stored, None, 8, 9);
    transition_store
        .compare_and_swap(&transition_request)
        .test_unwrap();
    let raw = Connection::open(&transition_path).test_expect("open raw transition database");
    raw.execute_batch("PRAGMA ignore_check_constraints = ON;")
        .test_expect("disable transition checks for corruption fixture");
    raw.execute(
        "UPDATE sealed_decoy_transitions_v1 SET result_ciphertext = zeroblob(0) \
         WHERE tenant_id = ?1 AND transition_token = ?2",
        params![tenant_id.as_str(), token(9).as_bytes().as_slice()],
    )
    .test_expect("corrupt transition result");
    assert_error_kind(
        transition_store.compare_and_swap(&transition_request),
        PortErrorKind::IntegrityFailure,
    );
}

#[test]
fn sqlite_fixture_contains_tokens_and_ciphertext_but_no_raw_secrets() {
    let temp = tempfile::tempdir().test_expect("temporary directory");
    let path = database(&temp, "secret-absence");
    let raw_artifact = b"raw-artifact-id-never-persist";
    let raw_marker = b"raw-marker-material-never-persist";
    let raw_operation = b"raw-operation-id-never-persist";
    let raw_transition = b"raw-transition-id-never-persist";
    let raw_public_ref = b"raw-public-marker-ref-never-persist";
    let tenant_id = tenant("tenant-secret-fixture");
    let artifact_token = hashed_token(b"artifact:", raw_artifact);
    let marker_token = hashed_token(b"marker:", raw_marker);
    let operation_token = hashed_token(b"operation:", raw_operation);
    let transition_token = hashed_token(b"transition:", raw_transition);
    let public_ref_token = hashed_token(b"public-ref:", raw_public_ref);
    let sealed = SealedDecoyRecord {
        tenant_id: tenant_id.clone(),
        artifact_token,
        public_ref_token: Some(public_ref_token),
        surface: DecoySurface::SignedWatermark,
        marker_token,
        version_hash: token(88),
        generation: 0,
        nonce: DecoyAeadNonce::new([77; 12]),
        encrypted_envelope: EncryptedDecoyEnvelope::new(vec![66; 32])
            .test_expect("fixture envelope"),
    };
    {
        let store = open(&path);
        store
            .compare_and_swap(&SealedDecoyCasRequest {
                record: sealed,
                expected_generation: None,
                operation_token,
                transition_token,
            })
            .test_unwrap();
        store
            .reserve(&WatermarkSequenceReservation {
                key: WatermarkSequenceKey {
                    tenant_id: tenant_id.clone(),
                    application_id: record_id("fixture-application"),
                    session_id: record_id("fixture-session"),
                    tool_id: record_id("fixture-tool"),
                    public_ref_token,
                },
                sequence: 1,
                operation_id: record_id("fixture-sequence-operation"),
            })
            .test_unwrap();
        store
            .record_first(&WatermarkObservation {
                source_tenant_id: tenant_id.clone(),
                observing_tenant_id: tenant("fixture-observer"),
                public_ref_token,
                observation_id: record_id("fixture-observation"),
                payload_digest: token(61),
                token_digest: token(62),
                evidence_ref: record_id("fixture-evidence"),
                observed_at_unix_ms: 5_000,
            })
            .test_unwrap();
    }

    let raw = Connection::open(&path).test_expect("open raw fixture database");
    let record_columns = table_columns(&raw, RECORDS_TABLE);
    assert_eq!(
        record_columns,
        vec![
            "tenant_id",
            "artifact_token",
            "public_ref_token",
            "surface",
            "marker_token",
            "version_hash",
            "generation",
            "nonce",
            "ciphertext",
        ]
    );
    assert_eq!(
        table_columns(&raw, OPERATIONS_TABLE),
        vec!["tenant_id", "operation_token", "artifact_token"]
    );
    assert_eq!(
        table_columns(&raw, TRANSITIONS_TABLE),
        vec![
            "tenant_id",
            "transition_token",
            "request_hash",
            "operation_token",
            "result_artifact_token",
            "result_public_ref_token",
            "result_surface",
            "result_marker_token",
            "result_version_hash",
            "result_generation",
            "result_nonce",
            "result_ciphertext",
        ]
    );
    assert_eq!(
        table_columns(&raw, SEQUENCE_HEADS_TABLE),
        vec![
            "tenant_id",
            "application_id",
            "session_id",
            "tool_id",
            "public_ref_token",
            "last_sequence",
        ]
    );
    assert_eq!(
        table_columns(&raw, SEQUENCE_OPERATIONS_TABLE),
        vec![
            "tenant_id",
            "operation_id",
            "request_hash",
            "application_id",
            "session_id",
            "tool_id",
            "public_ref_token",
            "reserved_sequence",
        ]
    );
    assert_eq!(
        table_columns(&raw, OBSERVATIONS_TABLE),
        vec![
            "source_tenant_id",
            "public_ref_token",
            "observation_id",
            "observing_tenant_id",
            "payload_digest",
            "token_digest",
            "evidence_ref",
            "observed_at_unix_ms",
        ]
    );
    let storage_shape: (String, i64, i64, i64, i64, i64, i64) = raw
        .query_row(
            "SELECT typeof(artifact_token), length(artifact_token), length(public_ref_token), \
             length(marker_token), \
             length(version_hash), length(nonce), length(ciphertext) \
             FROM sealed_decoy_records_v1 WHERE tenant_id = ?1",
            [tenant_id.as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .test_expect("read storage shape");
    assert_eq!(storage_shape, ("blob".to_owned(), 32, 32, 32, 32, 12, 32));
    raw.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .test_expect("checkpoint fixture");
    drop(raw);

    for candidate in database_files(&path) {
        if !candidate.exists() {
            continue;
        }
        let bytes = std::fs::read(&candidate).test_expect("read raw SQLite fixture");
        for secret in [
            raw_artifact.as_slice(),
            raw_marker.as_slice(),
            raw_operation.as_slice(),
            raw_transition.as_slice(),
            raw_public_ref.as_slice(),
        ] {
            assert!(
                !bytes.windows(secret.len()).any(|window| window == secret),
                "raw secret found in {}",
                candidate.display()
            );
        }
    }
}

fn table_columns(connection: &Connection, table: &str) -> Vec<String> {
    let sql = format!("PRAGMA table_info({table})");
    let mut statement = connection
        .prepare(&sql)
        .test_expect("prepare table info query");
    statement
        .query_map([], |row| row.get(1))
        .test_expect("query table info")
        .collect::<Result<Vec<String>, _>>()
        .test_expect("collect table columns")
}

fn database_files(path: &Path) -> Vec<PathBuf> {
    ["", "-wal", "-shm"]
        .into_iter()
        .map(|suffix| {
            let mut value = path.as_os_str().to_os_string();
            value.push(suffix);
            PathBuf::from(value)
        })
        .collect()
}
