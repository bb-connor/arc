//! The published service: extension, recertification, read leases and
//! leaf-bound fetch.
use std::time::{Duration, Instant};

use chio_kernel::receipt_query::{
    ReceiptQuery, ReceiptQuerySnapshotError, ReceiptReadContext, ReceiptSnapshotWatermark,
};
use chio_kernel::ReceiptStoreError;

use super::super::db::SnapshotDbError;
use super::super::service::{
    ReceiptQuerySnapshotConfig, ReceiptQuerySnapshotState, ReceiptQuerySnapshots,
};
use super::support::{keypair, per_call, substitute, Fixture, Spec};
use crate::receipt_store::support::receipt_signature_verifications;

fn config() -> ReceiptQuerySnapshotConfig {
    ReceiptQuerySnapshotConfig {
        step_rows: 3,
        insert_rows: 2,
        checkpoint_page: 2,
        extension_tick: Duration::from_millis(20),
        invalid_retry_backoff: Duration::from_millis(20),
        walker_busy_timeout: Duration::from_millis(50),
        ..ReceiptQuerySnapshotConfig::default()
    }
}

fn wait_for(
    service: &ReceiptQuerySnapshots,
    what: &str,
    mut done: impl FnMut(&ReceiptQuerySnapshotState) -> bool,
) -> ReceiptQuerySnapshotState {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let state = service.status().state;
        if done(&state) {
            return state;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {what}: {state:?}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn ready(fixture: &Fixture, config: ReceiptQuerySnapshotConfig) -> ReceiptQuerySnapshots {
    let service = ReceiptQuerySnapshots::start(fixture.store.clone(), config).unwrap();
    wait_for(&service, "ready", |state| {
        *state == ReceiptQuerySnapshotState::Ready
    });
    service
}

fn mixed_fixture() -> Fixture {
    let fixture = Fixture::new(4);
    fixture.append_varied(0..12);
    fixture.append_child("child-1", 1_700_000_100);
    assert!(fixture.rotate(1_700_000_000 + 6 * 600) > 0);
    fixture.append_varied(12..18);
    fixture
}

fn admin(limit: usize) -> ReceiptQuery {
    ReceiptQuery {
        limit,
        ..ReceiptQuery::default().local_operator_admin()
    }
}

fn snapshot_error(error: ReceiptStoreError) -> ReceiptQuerySnapshotError {
    match error {
        ReceiptStoreError::QuerySnapshot(error) => error,
        other => panic!("expected a typed snapshot outcome, got {other}"),
    }
}

#[test]
fn served_pages_match_the_per_call_path_and_carry_a_watermark() {
    let fixture = mixed_fixture();
    let service = ready(&fixture, config());
    for query in [
        admin(200),
        admin(4),
        ReceiptQuery {
            limit: 3,
            cursor: Some(5),
            ..ReceiptQuery::default().authenticated_tenant("tenant-a")
        },
        ReceiptQuery {
            outcome: Some("deny".into()),
            ..admin(50)
        },
    ] {
        let served = service.query_receipts(&query).unwrap();
        let seqs: Vec<u64> = served.receipts.iter().map(|row| row.seq).collect();
        assert_eq!(
            (seqs, served.total_count, served.next_cursor),
            per_call(&fixture.store, &query),
            "{query:?}"
        );
        let watermark = served.snapshot.unwrap();
        assert_eq!(watermark.through_entry_seq, 19);
        assert_eq!(watermark.checkpoint_seq, Some(4));
        assert!(watermark.recertified_at_unix_ms > 0);
    }
    service.shutdown();
}

#[test]
fn a_page_verifies_only_the_receipts_it_returns() {
    let fixture = mixed_fixture();
    let service = ready(&fixture, config());
    let mut query = ReceiptQuery {
        limit: 2,
        ..ReceiptQuery::default().authenticated_tenant("tenant-a")
    };
    let mut pages = 0;
    loop {
        let before = receipt_signature_verifications();
        let page = service.query_receipts(&query).unwrap();
        let verified = receipt_signature_verifications() - before;
        assert_eq!(verified, u64::try_from(page.receipts.len()).unwrap());
        pages += 1;
        match page.next_cursor {
            Some(cursor) => query.cursor = Some(cursor),
            None => break,
        }
    }
    assert!(pages >= 3);
    service.shutdown();
}

#[test]
fn extension_serves_new_receipts_and_accepts_new_checkpoints() {
    let fixture = mixed_fixture();
    let service = ready(&fixture, config());
    fixture.append_varied(18..26);
    let served = service.query_receipts(&admin(200)).unwrap();
    assert_eq!(served.total_count, 26);
    assert_eq!(served.snapshot.unwrap().through_entry_seq, 27);
    let deadline = Instant::now() + Duration::from_secs(30);
    while service
        .status()
        .watermark
        .and_then(|watermark| watermark.checkpoint_seq)
        < Some(6)
    {
        assert!(Instant::now() < deadline, "checkpoint 6 was not accepted");
        std::thread::sleep(Duration::from_millis(10));
    }
    service.shutdown();
}

#[test]
fn a_version_older_than_the_staleness_bound_is_refused_until_extension_resumes() {
    let fixture = mixed_fixture();
    let service = ready(
        &fixture,
        ReceiptQuerySnapshotConfig {
            head_wait: Duration::from_millis(100),
            max_staleness: Duration::ZERO,
            ..config()
        },
    );
    service.pause_extension_for_test(true);
    fixture.append(&Spec::varied(18));
    fixture.flush();
    let error = service.query_receipts(&admin(10)).unwrap_err();
    assert_eq!(snapshot_error(error), ReceiptQuerySnapshotError::Stale);
    service.pause_extension_for_test(false);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(page) = service.query_receipts(&admin(200)) {
            assert_eq!(page.total_count, 19);
            break;
        }
        assert!(Instant::now() < deadline, "extension did not resume");
        std::thread::sleep(Duration::from_millis(10));
    }
    service.shutdown();
}

#[test]
fn a_regressed_claim_log_invalidates_the_snapshot() {
    let fixture = mixed_fixture();
    let service = ready(&fixture, config());
    fixture
        .tamper()
        .execute(
            "DELETE FROM claim_receipt_log_entries WHERE entry_seq = (SELECT MAX(entry_seq) FROM claim_receipt_log_entries)",
            [],
        )
        .unwrap();
    let state = wait_for(&service, "invalid", |state| {
        matches!(state, ReceiptQuerySnapshotState::Invalid { .. })
    });
    assert!(format!("{state:?}").contains("regressed"), "{state:?}");
    let error = service.query_receipts(&admin(10)).unwrap_err();
    assert!(matches!(
        snapshot_error(error),
        ReceiptQuerySnapshotError::Invalid(_)
    ));
    service.shutdown();
}

#[test]
fn an_invalid_snapshot_is_never_revived_and_a_rebuild_starts_a_new_lineage() {
    let fixture = mixed_fixture();
    let service = ready(&fixture, config());
    let first = service.query_receipts(&admin(1)).unwrap().snapshot.unwrap();
    service.invalidate_for_test("test invalidation");
    let rebuilt = (|| {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Ok(page) = service.query_receipts(&admin(1)) {
                return page.snapshot.unwrap();
            }
            assert!(Instant::now() < deadline, "no rebuild");
            std::thread::sleep(Duration::from_millis(10));
        }
    })();
    let lineage = |id: &str| id.split(':').next().unwrap().to_string();
    assert_ne!(lineage(&first.snapshot_id), lineage(&rebuilt.snapshot_id));
    service.shutdown();
}

#[test]
fn a_lease_fails_on_invalidation_but_not_on_a_new_generation() {
    let fixture = mixed_fixture();
    let service = ready(&fixture, config());
    let epoch = service.lease_for_test().unwrap();
    fixture.append_varied(18..20);
    assert_eq!(service.query_receipts(&admin(200)).unwrap().total_count, 20);
    service.recheck_lease_for_test(epoch).unwrap();
    service.invalidate_for_test("tamper detected");
    let error = service.recheck_lease_for_test(epoch).unwrap_err();
    assert!(matches!(
        snapshot_error(error),
        ReceiptQuerySnapshotError::Invalid(_)
    ));
    service.shutdown();
}

/// Replace receipt `index` with a validly signed variant of itself.
fn substitute_varied(fixture: &Fixture, index: u64) {
    let original = Spec::varied(index).sign(&keypair());
    let replacement = {
        let mut spec = Spec::varied(index);
        spec.timestamp += 1;
        spec.sign(&keypair())
    };
    substitute(fixture, &original, &replacement);
}

#[test]
fn an_unreturned_mutation_never_changes_an_answer_and_recertification_detects_it() {
    let fixture = mixed_fixture();
    let service = ready(
        &fixture,
        ReceiptQuerySnapshotConfig {
            recertify_interval: Duration::from_millis(300),
            ..config()
        },
    );
    let query = ReceiptQuery {
        limit: 200,
        ..ReceiptQuery::default().authenticated_tenant("tenant-b")
    };
    let before = service.query_receipts(&query).unwrap();
    // Receipt 13 belongs to tenant-a: a tenant-b page never returns it.
    substitute_varied(&fixture, 13);
    let during = service.query_receipts(&query);
    if let Ok(during) = during {
        assert_eq!(during.total_count, before.total_count);
    }
    let state = wait_for(&service, "invalid", |state| {
        matches!(state, ReceiptQuerySnapshotState::Invalid { .. })
    });
    assert!(format!("{state:?}").contains("entry 15"), "{state:?}");
    service.shutdown();
}

#[test]
fn an_in_place_byte_edit_is_detected_by_recertification() {
    let fixture = mixed_fixture();
    let service = ready(
        &fixture,
        ReceiptQuerySnapshotConfig {
            recertify_interval: Duration::from_millis(300),
            ..config()
        },
    );
    {
        let tamper = fixture.tamper();
        tamper
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
            .unwrap();
    }
    // Rewrite one byte of receipt 14's content hash in the database file, as a
    // disk-level edit that never passes through SQLite.
    let mut bytes = std::fs::read(&fixture.live).unwrap();
    let needle = b"content-rcpt-00014";
    let mut edited = 0;
    let mut offset = 0;
    while let Some(found) = bytes[offset..]
        .windows(needle.len())
        .position(|window| window == needle)
    {
        let at = offset + found + needle.len() - 1;
        bytes[at] = b'9';
        offset = at;
        edited += 1;
    }
    assert!(edited > 0);
    std::fs::write(&fixture.live, &bytes).unwrap();
    let state = wait_for(&service, "invalid", |state| {
        matches!(state, ReceiptQuerySnapshotState::Invalid { .. })
    });
    assert!(matches!(state, ReceiptQuerySnapshotState::Invalid { .. }));
    service.shutdown();
}

#[test]
fn a_substituted_returned_receipt_fails_the_leaf_check() {
    let fixture = mixed_fixture();
    let service = ready(&fixture, config());
    substitute_varied(&fixture, 15);
    let error = service.query_receipts(&admin(200)).unwrap_err();
    assert!(matches!(
        snapshot_error(error),
        ReceiptQuerySnapshotError::Invalid(_)
    ));
    assert!(matches!(
        service.status().state,
        ReceiptQuerySnapshotState::Invalid { .. }
    ));
    service.shutdown();
}

#[test]
fn a_substituted_uncheckpointed_receipt_fails_the_leaf_check() {
    let fixture = mixed_fixture();
    let service = ready(&fixture, config());
    // Receipt 17 is in the uncheckpointed tail, where the per-call path checks
    // only its own signature and serves the substitute.
    substitute_varied(&fixture, 17);
    let error = service.query_receipts(&admin(200)).unwrap_err();
    assert!(matches!(
        snapshot_error(error),
        ReceiptQuerySnapshotError::Invalid(_)
    ));
    service.shutdown();
}

#[test]
fn reads_are_never_served_while_the_build_cannot_complete() {
    let fixture = Fixture::new(8);
    fixture.append_varied(0..8);
    let corrupted = {
        let mut receipt = Spec::varied(6).sign(&keypair());
        receipt.tool_name = "forged".into();
        serde_json::to_string(&receipt).unwrap()
    };
    fixture
        .tamper()
        .execute(
            "UPDATE claim_receipt_log_entries SET raw_json = ?1 WHERE entry_seq = 7",
            [corrupted],
        )
        .unwrap();
    let service = ReceiptQuerySnapshots::start(fixture.store.clone(), config()).unwrap();
    let id = Spec::varied(0).sign(&keypair()).id;
    let context = ReceiptReadContext::admin_service();
    let deadline = Instant::now() + Duration::from_millis(500);
    while Instant::now() < deadline {
        assert!(service.query_receipts(&admin(10)).is_err());
        assert!(service.load_receipt(&id, &context).is_err());
    }
    wait_for(&service, "invalid", |state| {
        matches!(state, ReceiptQuerySnapshotState::Invalid { .. })
    });
    service.shutdown();
}

#[test]
fn reads_stay_correct_while_recertification_runs() {
    let fixture = mixed_fixture();
    let service = ready(
        &fixture,
        ReceiptQuerySnapshotConfig {
            recertify_interval: Duration::ZERO,
            ..config()
        },
    );
    let expected = per_call(&fixture.store, &admin(200));
    for _ in 0..40 {
        let served = service.query_receipts(&admin(200)).unwrap();
        let seqs: Vec<u64> = served.receipts.iter().map(|row| row.seq).collect();
        assert_eq!((seqs, served.total_count, served.next_cursor), expected);
    }
    assert_eq!(service.status().state, ReceiptQuerySnapshotState::Ready);
    service.shutdown();
}

#[test]
fn shutdown_stops_the_walker_and_refuses_reads() {
    let fixture = mixed_fixture();
    let service = ready(&fixture, config());
    service.shutdown();
    assert_eq!(service.status().state, ReceiptQuerySnapshotState::Stopped);
    let error = service.query_receipts(&admin(10)).unwrap_err();
    assert!(matches!(
        snapshot_error(error),
        ReceiptQuerySnapshotError::Unavailable(_)
    ));
}

#[test]
fn rotation_after_publication_moves_rows_without_changing_answers() {
    let fixture = mixed_fixture();
    let service = ready(&fixture, config());
    let before = per_call(&fixture.store, &admin(200));
    assert!(fixture.rotate(1_700_000_000 + 12 * 600) > 0);
    let served = service.query_receipts(&admin(200)).unwrap();
    let seqs: Vec<u64> = served.receipts.iter().map(|row| row.seq).collect();
    assert_eq!((seqs, served.total_count, served.next_cursor), before);
    service.shutdown();
}

#[test]
fn a_byte_limited_page_is_short_and_continues_by_cursor() {
    let fixture = mixed_fixture();
    let service = ready(
        &fixture,
        ReceiptQuerySnapshotConfig {
            page_bytes: 1,
            ..config()
        },
    );
    let (expected, _, _) = per_call(&fixture.store, &admin(200));
    let mut query = admin(10);
    let mut seqs = Vec::new();
    loop {
        let page = service.query_receipts(&query).unwrap();
        assert_eq!(page.receipts.len(), 1);
        seqs.extend(page.receipts.iter().map(|row| row.seq));
        match page.next_cursor {
            Some(cursor) => query.cursor = Some(cursor),
            None => break,
        }
    }
    assert_eq!(seqs, expected);
    service.shutdown();
}

#[test]
fn point_reads_are_scoped_and_negatives_require_the_head() {
    let fixture = mixed_fixture();
    let service = ready(
        &fixture,
        ReceiptQuerySnapshotConfig {
            head_wait: Duration::from_millis(100),
            ..config()
        },
    );
    let admin_context = ReceiptReadContext::admin_service();
    let tenant_b = ReceiptReadContext::authenticated_tenant("tenant-b");
    let archived = Spec::varied(1).sign(&keypair()).id;
    let (found, watermark) = service.load_receipt(&archived, &admin_context).unwrap();
    assert_eq!(found.unwrap().id, archived);
    assert_eq!(watermark.through_entry_seq, 19);
    // Receipt 1 belongs to tenant-a.
    assert!(service
        .load_receipt(&archived, &tenant_b)
        .unwrap()
        .0
        .is_none());
    assert!(service
        .load_receipt("rcpt-missing", &admin_context)
        .unwrap()
        .0
        .is_none());
    service.pause_extension_for_test(true);
    let fresh = Spec::varied(40).sign(&keypair());
    fixture
        .store
        .append_chio_receipt_returning_seq(&fresh)
        .unwrap();
    fixture.flush();
    let error = service.load_receipt(&fresh.id, &admin_context).unwrap_err();
    assert_eq!(snapshot_error(error), ReceiptQuerySnapshotError::Stale);
    service.pause_extension_for_test(false);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok((Some(receipt), _)) = service.load_receipt(&fresh.id, &admin_context) {
            assert_eq!(receipt.id, fresh.id);
            break;
        }
        assert!(Instant::now() < deadline, "extension did not resume");
        std::thread::sleep(Duration::from_millis(10));
    }
    service.shutdown();
}

#[test]
fn a_poisoned_writer_head_invalidates_reads_and_is_never_revived() {
    let fixture = mixed_fixture();
    let service = ready(&fixture, config());
    let published = service
        .query_receipts(&admin(10))
        .unwrap()
        .snapshot
        .unwrap();
    // A read admitted before the poison holds a lease on the published version.
    let in_flight = service.lease_for_test().unwrap();
    // The real writer-poison path: a persisted checkpoint diverges out of band,
    // and the writer's own reseed fails closed and poisons its verified head.
    let original = "\"batch_end_seq\":4";
    let diverged = "\"batch_end_seq\":3";
    fixture
        .tamper()
        .execute(
            "UPDATE kernel_checkpoints SET statement_json = replace(statement_json, ?1, ?2) WHERE checkpoint_seq = 1",
            [original, diverged],
        )
        .unwrap();
    assert!(fixture.store.reseed_verified_head().is_err());
    assert!(fixture.store.writer_serving_closed());
    let admitted = service.query_receipts(&admin(10)).unwrap_err();
    assert!(matches!(
        snapshot_error(admitted),
        ReceiptQuerySnapshotError::Invalid(_)
    ));
    let leased = service.recheck_lease_for_test(in_flight).unwrap_err();
    assert!(matches!(
        snapshot_error(leased),
        ReceiptQuerySnapshotError::Invalid(_)
    ));
    wait_for(&service, "invalid", |state| {
        matches!(state, ReceiptQuerySnapshotState::Invalid { .. })
    });
    // No rebuild is attempted while the head stays poisoned.
    let deadline = Instant::now() + Duration::from_millis(500);
    while Instant::now() < deadline {
        assert!(service.query_receipts(&admin(10)).is_err());
    }
    // Repair the checkpoint and reseed: the service builds a new lineage and
    // never serves the poisoned one again.
    fixture
        .tamper()
        .execute(
            "UPDATE kernel_checkpoints SET statement_json = replace(statement_json, ?1, ?2) WHERE checkpoint_seq = 1",
            [diverged, original],
        )
        .unwrap();
    fixture.store.reseed_verified_head().unwrap();
    assert!(!fixture.store.writer_serving_closed());
    let deadline = Instant::now() + Duration::from_secs(60);
    let rebuilt = loop {
        if let Ok(page) = service.query_receipts(&admin(10)) {
            break page.snapshot.unwrap();
        }
        assert!(Instant::now() < deadline, "no rebuild after the reseed");
        std::thread::sleep(Duration::from_millis(10));
    };
    let lineage = |id: &str| id.split(':').next().unwrap().to_string();
    assert_ne!(
        lineage(&published.snapshot_id),
        lineage(&rebuilt.snapshot_id)
    );
    let stale = service.recheck_lease_for_test(in_flight).unwrap_err();
    assert!(matches!(
        snapshot_error(stale),
        ReceiptQuerySnapshotError::Invalid(_)
    ));
    service.shutdown();
}

/// Pause extension at E = 12, then commit entries 13..=16 (a full checkpoint)
/// and return the newest receipt. A rotation can then archive everything.
fn torn_head_fixture() -> (
    Fixture,
    ReceiptQuerySnapshots,
    chio_core::receipt::body::ChioReceipt,
) {
    let fixture = Fixture::new(4);
    fixture.append_varied(0..12);
    let service = ready(
        &fixture,
        ReceiptQuerySnapshotConfig {
            head_wait: Duration::from_millis(100),
            max_staleness: Duration::ZERO,
            ..config()
        },
    );
    service.pause_extension_for_test(true);
    fixture.append_varied(12..15);
    let newest = Spec::varied(15).sign(&keypair());
    fixture
        .store
        .append_chio_receipt_returning_seq(&newest)
        .unwrap();
    fixture.flush();
    (fixture, service, newest)
}

/// Archive every checkpointed receipt between the two reads of the next head
/// observation on this thread.
fn rotate_between_head_reads(fixture: &Fixture) {
    let store = fixture.store.clone();
    let archive = fixture.archive.to_str().unwrap().to_string();
    super::super::service::head_hook::set(Some(Box::new(move || {
        assert!(
            store
                .archive_receipts_before(1_800_000_000, &archive)
                .unwrap()
                > 0
        );
    })));
}

#[test]
fn head_rotation_between_reads_never_yields_a_false_negative() {
    let (fixture, service, newest) = torn_head_fixture();
    rotate_between_head_reads(&fixture);
    let result = service.load_receipt(&newest.id, &ReceiptReadContext::admin_service());
    super::super::service::head_hook::set(None);
    match result {
        Err(error) => assert_eq!(snapshot_error(error), ReceiptQuerySnapshotError::Stale),
        Ok((found, watermark)) => panic!(
            "a negative lookup at entry {} skipped the committed head: {found:?}",
            watermark.through_entry_seq
        ),
    }
    service.shutdown();
}

#[test]
fn head_rotation_between_reads_never_serves_an_uncovered_page() {
    let (fixture, service, _) = torn_head_fixture();
    rotate_between_head_reads(&fixture);
    let result = service.query_receipts(&admin(200));
    super::super::service::head_hook::set(None);
    match result {
        Err(error) => assert_eq!(snapshot_error(error), ReceiptQuerySnapshotError::Stale),
        Ok(page) => panic!(
            "a page at entry {} was treated as covering the committed head",
            page.snapshot.unwrap().through_entry_seq
        ),
    }
    service.shutdown();
}

/// A snapshot whose whole history (`tail` receipts) is uncheckpointed, then a
/// signer that covers it with one checkpoint.
fn large_tail(tail: u64, config: ReceiptQuerySnapshotConfig) -> (Fixture, ReceiptQuerySnapshots) {
    let fixture = Fixture::new(0);
    fixture.append_varied(0..tail);
    let service = ready(&fixture, config);
    fixture
        .store
        .enable_background_checkpoints(crate::receipt_store::BackgroundCheckpointSigner {
            keypair: std::sync::Arc::new(keypair()),
            max_batch: tail,
        })
        .unwrap();
    fixture.flush();
    (fixture, service)
}

#[test]
fn hold_a_large_checkpoint_settles_in_bounded_holds_while_reads_proceed() {
    let insert_rows = 64;
    let (fixture, service) = large_tail(
        600,
        ReceiptQuerySnapshotConfig {
            insert_rows,
            step_rows: 256,
            ..config()
        },
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        // Reads keep being served while the checkpoint is accepted.
        let page = service.query_receipts(&admin(5)).unwrap();
        if page.snapshot.unwrap().checkpoint_seq == Some(1) {
            break;
        }
        assert!(Instant::now() < deadline, "the checkpoint was not accepted");
    }
    let settled = service.max_settled_per_hold_for_test();
    assert!(
        settled <= u64::try_from(insert_rows).unwrap(),
        "one snapshot hold settled {settled} pending leaves"
    );
    assert_eq!(per_call(&fixture.store, &admin(5)).1, 600);
    service.shutdown();
}

#[test]
fn hold_shutdown_during_a_large_settlement_stops_the_walker() {
    let (_fixture, service) = large_tail(
        600,
        ReceiptQuerySnapshotConfig {
            insert_rows: 16,
            step_rows: 256,
            ..config()
        },
    );
    service.shutdown();
    assert_eq!(service.status().state, ReceiptQuerySnapshotState::Stopped);
}

#[test]
fn a_status_metric_that_cannot_be_read_is_never_reported_as_healthy_zeros() {
    let fixture = mixed_fixture();
    let service = ready(&fixture, config());
    service.pause_extension_for_test(true);
    let healthy = service.status();
    assert_eq!(healthy.state, ReceiptQuerySnapshotState::Ready);
    assert!(healthy.tool_receipts > 0 && healthy.dimensions > 0);
    // A hold that panicked leaves the snapshot in an unknown state.
    service.poison_snapshot_for_test();
    let status = service.status();
    assert!(
        matches!(
            &status.state,
            ReceiptQuerySnapshotState::Invalid { reason } if reason.contains("poisoned")
        ),
        "a failed metric read reported {status:?}"
    );
    assert_eq!(
        (status.tool_receipts, status.dimensions, status.watermark),
        (0, 0, None)
    );
    service.shutdown();
}

/// Fail the walker's next commit hold with `fault` while a read lease is in
/// flight. Returns the state the walker publishes, the in-flight lease's
/// outcome, and whether a new lineage became ready afterwards.
fn walker_storage_failure(
    fault: SnapshotDbError,
) -> (ReceiptQuerySnapshotState, ReceiptQuerySnapshotError, bool) {
    let fixture = mixed_fixture();
    let service = ready(
        &fixture,
        ReceiptQuerySnapshotConfig {
            invalid_retry_backoff: Duration::from_millis(500),
            ..config()
        },
    );
    let first = service.query_receipts(&admin(1)).unwrap().snapshot.unwrap();
    let epoch = service.lease_for_test().unwrap();
    service.fail_next_commit_for_test(fault);
    fixture.append_varied(18..20);
    let state = wait_for(&service, "the failed commit", |state| {
        *state != ReceiptQuerySnapshotState::Ready
    });
    let lease = snapshot_error(service.recheck_lease_for_test(epoch).unwrap_err());
    let rebuilt = match state {
        ReceiptQuerySnapshotState::Unavailable { .. } => {
            wait_for(&service, "a rebuild", |state| {
                *state == ReceiptQuerySnapshotState::Ready
            });
            let rebuilt = service.query_receipts(&admin(1)).unwrap().snapshot.unwrap();
            let lineage = |id: &str| id.split(':').next().unwrap().to_string();
            lineage(&first.snapshot_id) != lineage(&rebuilt.snapshot_id)
        }
        _ => false,
    };
    service.shutdown();
    (state, lease, rebuilt)
}

#[test]
fn a_typed_backing_io_failure_in_a_walker_hold_is_unavailable_never_invalid() {
    let (state, lease, rebuilt) = walker_storage_failure(SnapshotDbError::Store(
        ReceiptQuerySnapshotError::Unavailable("snapshot backing storage I/O failed".into()).into(),
    ));
    assert!(
        matches!(
            &state,
            ReceiptQuerySnapshotState::Unavailable { reason }
                if reason.contains("snapshot backing storage I/O failed")
        ),
        "a backing I/O failure published {state:?}"
    );
    assert!(
        matches!(&lease, ReceiptQuerySnapshotError::Unavailable(_)),
        "an in-flight read across a backing I/O failure refused as {lease:?}"
    );
    assert!(rebuilt, "the walker did not rebuild after an I/O failure");
}

#[test]
fn a_snapshot_storage_io_error_in_a_walker_hold_is_unavailable_never_invalid() {
    let io = rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_IOERR_READ),
        Some("disk I/O error".into()),
    );
    let (state, lease, rebuilt) = walker_storage_failure(SnapshotDbError::Sqlite(io));
    assert!(
        matches!(&state, ReceiptQuerySnapshotState::Unavailable { .. }),
        "a snapshot storage I/O error published {state:?}"
    );
    assert!(
        matches!(&lease, ReceiptQuerySnapshotError::Unavailable(_)),
        "an in-flight read across a storage I/O error refused as {lease:?}"
    );
    assert!(rebuilt, "the walker did not rebuild after an I/O error");
}

#[test]
fn a_custody_mismatch_in_a_walker_hold_stays_invalid() {
    let (state, lease, _) = walker_storage_failure(SnapshotDbError::Store(
        ReceiptQuerySnapshotError::Invalid("snapshot backing file custody mismatch".into()).into(),
    ));
    assert!(
        matches!(
            &state,
            ReceiptQuerySnapshotState::Invalid { reason }
                if reason.contains("custody mismatch")
        ),
        "a custody mismatch published {state:?}"
    );
    assert!(
        matches!(&lease, ReceiptQuerySnapshotError::Invalid(_)),
        "an in-flight read across a custody mismatch refused as {lease:?}"
    );
}

/// Once `refused` reported an integrity failure of the served lineage, that
/// lineage stays dropped although nothing is wrong with it any more, an
/// admitted lease stays refused, and only a new authenticated lineage serves.
fn assert_lineage_dropped(
    service: &ReceiptQuerySnapshots,
    epoch: u64,
    first: &ReceiptSnapshotWatermark,
    refused: ReceiptQuerySnapshotError,
) {
    assert!(
        matches!(refused, ReceiptQuerySnapshotError::Invalid(_)),
        "an integrity failure refused as {refused:?}"
    );
    let state = service.status().state;
    assert!(
        matches!(state, ReceiptQuerySnapshotState::Invalid { .. }),
        "after an integrity failure the lineage is {state:?}"
    );
    let served = service.query_receipts(&admin(1));
    assert!(
        matches!(
            &served,
            Err(ReceiptStoreError::QuerySnapshot(
                ReceiptQuerySnapshotError::Invalid(_)
            ))
        ),
        "the lineage that failed served again: {:?}",
        served.map(|page| page.snapshot)
    );
    let lease = snapshot_error(service.recheck_lease_for_test(epoch).unwrap_err());
    assert!(matches!(lease, ReceiptQuerySnapshotError::Invalid(_)));

    service.pause_extension_for_test(false);
    wait_for(service, "a new lineage", |state| {
        *state == ReceiptQuerySnapshotState::Ready
    });
    let rebuilt = service.query_receipts(&admin(1)).unwrap().snapshot.unwrap();
    let lineage = |id: &str| id.split(':').next().unwrap().to_string();
    assert_ne!(lineage(&first.snapshot_id), lineage(&rebuilt.snapshot_id));
    let lease = snapshot_error(service.recheck_lease_for_test(epoch).unwrap_err());
    assert!(matches!(lease, ReceiptQuerySnapshotError::Invalid(_)));
}

/// A ready service with extension paused, the watermark of its first
/// lineage and a lease admitted under it.
fn paused_with_lease(fixture: &Fixture) -> (ReceiptQuerySnapshots, ReceiptSnapshotWatermark, u64) {
    let service = ready(
        fixture,
        ReceiptQuerySnapshotConfig {
            invalid_retry_backoff: Duration::from_secs(3),
            ..config()
        },
    );
    let first = service.query_receipts(&admin(1)).unwrap().snapshot.unwrap();
    service.pause_extension_for_test(true);
    let epoch = service.lease_for_test().unwrap();
    (service, first, epoch)
}

/// Fail one public read on the published lineage's custody: the backing
/// file's mode is changed for the read and restored afterwards.
#[cfg(target_os = "linux")]
fn custody_failure_drops_the_lineage(
    read: impl FnOnce(&ReceiptQuerySnapshots) -> Result<(), ReceiptQuerySnapshotError>,
) {
    use std::os::unix::fs::PermissionsExt;
    let fixture = mixed_fixture();
    let (service, first, epoch) = paused_with_lease(&fixture);
    let path = service
        .backing_path_for_test()
        .expect("a Linux snapshot has a private backing file");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    let refused = read(&service);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_lineage_dropped(&service, epoch, &first, refused.unwrap_err());
    service.shutdown();
}

/// Project a tenant-a receipt into tenant-b in the owned snapshot, then read
/// it as tenant-b. The receipt itself still verifies and matches its leaf,
/// so only the owned projection is wrong.
fn tenant_projection_tamper_drops_the_lineage(
    read: impl FnOnce(&ReceiptQuerySnapshots, &str) -> Result<(), ReceiptStoreError>,
) {
    let fixture = mixed_fixture();
    let (service, first, epoch) = paused_with_lease(&fixture);
    let tenant_a = Spec::varied(1).sign(&keypair()).id;
    let tenant_b = Spec::varied(3).sign(&keypair()).id;
    let changed = service.execute_on_snapshot_for_test(
        "UPDATE snapshot_tool_receipt \
         SET tenant = (SELECT tenant FROM snapshot_tool_receipt WHERE receipt_id = ?2) \
         WHERE receipt_id = ?1",
        rusqlite::params![tenant_a, tenant_b],
    );
    assert_eq!(changed, 1);
    let refused = read(&service, &tenant_a).unwrap_err();
    let refused = match refused {
        ReceiptStoreError::QuerySnapshot(refused) => refused,
        other => panic!("a tenant projection mismatch surfaced untyped: {other:?}"),
    };
    assert_lineage_dropped(&service, epoch, &first, refused);
    service.shutdown();
}

#[test]
fn a_tenant_projection_mismatch_on_a_page_read_drops_the_lineage() {
    tenant_projection_tamper_drops_the_lineage(|service, _| {
        let tenant_b = ReceiptQuery {
            limit: 100,
            ..ReceiptQuery::default().authenticated_tenant("tenant-b")
        };
        service.query_receipts(&tenant_b).map(drop)
    });
}

#[test]
fn a_tenant_projection_mismatch_on_a_point_read_drops_the_lineage() {
    tenant_projection_tamper_drops_the_lineage(|service, tenant_a| {
        service
            .load_receipt(
                tenant_a,
                &ReceiptReadContext::authenticated_tenant("tenant-b"),
            )
            .map(drop)
    });
}

#[test]
fn the_integrity_backoff_resets_once_a_rebuilt_lineage_serves() {
    let fixture = mixed_fixture();
    let base = Duration::from_millis(50);
    let service = ready(
        &fixture,
        ReceiptQuerySnapshotConfig {
            invalid_retry_backoff: base,
            ..config()
        },
    );
    let lineage = |id: &str| id.split(':').next().unwrap().to_string();
    for _ in 0..4 {
        let before = service.query_receipts(&admin(1)).unwrap().snapshot.unwrap();
        service.invalidate_for_test("integrity failure");
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Ok(page) = service.query_receipts(&admin(1)) {
                let after = page.snapshot.unwrap();
                if lineage(&after.snapshot_id) != lineage(&before.snapshot_id) {
                    break;
                }
            }
            assert!(
                Instant::now() < deadline,
                "no rebuild after an integrity failure"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    // Each failure follows a lineage that served, so none waits longer than
    // the first.
    assert_eq!(service.integrity_waits_for_test(), vec![base; 4]);
    service.shutdown();
}

#[cfg(target_os = "linux")]
#[test]
fn a_custody_failure_on_a_page_read_drops_the_lineage() {
    custody_failure_drops_the_lineage(|service| {
        service
            .query_receipts(&admin(5))
            .map(drop)
            .map_err(snapshot_error)
    });
}

#[cfg(target_os = "linux")]
#[test]
fn a_custody_failure_on_a_point_read_drops_the_lineage() {
    let id = Spec::varied(1).sign(&keypair()).id;
    custody_failure_drops_the_lineage(|service| {
        service
            .load_receipt(&id, &ReceiptReadContext::admin_service())
            .map(drop)
            .map_err(snapshot_error)
    });
}

#[cfg(target_os = "linux")]
#[test]
fn a_custody_failure_on_a_negative_point_read_drops_the_lineage() {
    custody_failure_drops_the_lineage(|service| {
        service
            .load_receipt("rcpt-missing", &ReceiptReadContext::admin_service())
            .map(drop)
            .map_err(snapshot_error)
    });
}

#[cfg(target_os = "linux")]
#[test]
fn a_custody_failure_seen_by_health_drops_the_lineage() {
    custody_failure_drops_the_lineage(|service| match service.status().state {
        ReceiptQuerySnapshotState::Invalid { reason } => {
            Err(ReceiptQuerySnapshotError::Invalid(reason))
        }
        ReceiptQuerySnapshotState::Unavailable { reason } => {
            Err(ReceiptQuerySnapshotError::Unavailable(reason))
        }
        _ => Ok(()),
    });
}

#[test]
fn resource_and_request_refusals_on_a_read_keep_the_lineage() {
    let fixture = mixed_fixture();
    let service = ready(&fixture, config());
    service.pause_extension_for_test(true);
    let first = service.query_receipts(&admin(1)).unwrap().snapshot.unwrap();
    let epoch = service.lease_for_test().unwrap();
    let faults = [
        ReceiptQuerySnapshotError::Unavailable("snapshot backing storage I/O failed".into()),
        ReceiptQuerySnapshotError::WorkBudgetExhausted("receipt query".into()),
    ];
    for fault in faults {
        service.fail_next_read_for_test(fault.clone().into());
        let refused = snapshot_error(service.query_receipts(&admin(1)).unwrap_err());
        assert_eq!(refused, fault);
        service.fail_next_read_for_test(fault.clone().into());
        let refused = snapshot_error(
            service
                .load_receipt("rcpt-missing", &ReceiptReadContext::admin_service())
                .unwrap_err(),
        );
        assert_eq!(refused, fault);
    }
    service.fail_next_status_for_test(SnapshotDbError::Store(
        ReceiptQuerySnapshotError::Unavailable("snapshot backing storage I/O failed".into()).into(),
    ));
    let state = service.status().state;
    assert!(
        matches!(
            &state,
            ReceiptQuerySnapshotState::Unavailable { reason }
                if reason.contains("snapshot backing storage I/O failed")
        ),
        "a resource failure seen by health reported {state:?}"
    );
    let invalid_request = ReceiptQuery {
        outcome: Some("unknown".into()),
        ..admin(1)
    };
    assert!(matches!(
        service.query_receipts(&invalid_request),
        Err(ReceiptStoreError::InvalidOutcome(_))
    ));
    assert_eq!(service.status().state, ReceiptQuerySnapshotState::Ready);
    service.recheck_lease_for_test(epoch).unwrap();
    let served = service.query_receipts(&admin(1)).unwrap().snapshot.unwrap();
    assert_eq!(served.snapshot_id, first.snapshot_id);
    service.shutdown();
}

#[test]
fn an_in_flight_read_racing_a_resource_outcome_refuses_as_unavailable() {
    let fixture = mixed_fixture();
    let service = ready(&fixture, config());
    let epoch = service.lease_for_test().unwrap();
    service.set_unavailable_for_test("walker step exhausted its SQL work budget");
    let error = service.recheck_lease_for_test(epoch).unwrap_err();
    assert_eq!(
        snapshot_error(error),
        ReceiptQuerySnapshotError::Unavailable("walker step exhausted its SQL work budget".into())
    );
    service.shutdown();
}

#[test]
fn an_in_flight_read_racing_shutdown_refuses_as_unavailable() {
    let fixture = mixed_fixture();
    let service = ready(&fixture, config());
    let epoch = service.lease_for_test().unwrap();
    service.shutdown();
    let error = service.recheck_lease_for_test(epoch).unwrap_err();
    assert!(matches!(
        snapshot_error(error),
        ReceiptQuerySnapshotError::Unavailable(_)
    ));
}

#[test]
fn an_in_flight_read_across_a_healthy_rebuild_is_not_called_tamper() {
    let fixture = mixed_fixture();
    let service = ready(&fixture, config());
    let first = service.query_receipts(&admin(1)).unwrap().snapshot.unwrap();
    let epoch = service.lease_for_test().unwrap();
    service.set_unavailable_for_test("walker step exhausted its SQL work budget");
    let deadline = Instant::now() + Duration::from_secs(60);
    let rebuilt = loop {
        if let Ok(page) = service.query_receipts(&admin(1)) {
            break page.snapshot.unwrap();
        }
        assert!(
            Instant::now() < deadline,
            "no rebuild after a resource outcome"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    let lineage = |id: &str| id.split(':').next().unwrap().to_string();
    assert_ne!(lineage(&first.snapshot_id), lineage(&rebuilt.snapshot_id));
    let error = service.recheck_lease_for_test(epoch).unwrap_err();
    assert_eq!(snapshot_error(error), ReceiptQuerySnapshotError::Stale);
    service.shutdown();
}

#[test]
fn zero_or_overflowing_limits_are_refused_before_the_walker_starts() {
    let fixture = mixed_fixture();
    let invalid: Vec<(&str, ReceiptQuerySnapshotConfig)> = vec![
        (
            "step_rows",
            ReceiptQuerySnapshotConfig {
                step_rows: 0,
                ..config()
            },
        ),
        (
            "insert_rows",
            ReceiptQuerySnapshotConfig {
                insert_rows: 0,
                ..config()
            },
        ),
        (
            "checkpoint_page",
            ReceiptQuerySnapshotConfig {
                checkpoint_page: 0,
                ..config()
            },
        ),
        (
            "max_concurrent_reads",
            ReceiptQuerySnapshotConfig {
                max_concurrent_reads: 0,
                ..config()
            },
        ),
        (
            "quota_bytes",
            ReceiptQuerySnapshotConfig {
                quota_bytes: 0,
                ..config()
            },
        ),
        (
            "step_bytes",
            ReceiptQuerySnapshotConfig {
                step_bytes: 0,
                ..config()
            },
        ),
        (
            "page_bytes",
            ReceiptQuerySnapshotConfig {
                page_bytes: 0,
                ..config()
            },
        ),
        (
            "max_receipt_bytes",
            ReceiptQuerySnapshotConfig {
                max_receipt_bytes: 0,
                ..config()
            },
        ),
        (
            "query_sql_steps",
            ReceiptQuerySnapshotConfig {
                query_sql_steps: 0,
                ..config()
            },
        ),
        (
            "fetch_sql_steps",
            ReceiptQuerySnapshotConfig {
                fetch_sql_steps: 0,
                ..config()
            },
        ),
        (
            "walker_sql_steps",
            ReceiptQuerySnapshotConfig {
                walker_sql_steps: 0,
                ..config()
            },
        ),
        (
            "hold_sql_steps",
            ReceiptQuerySnapshotConfig {
                hold_sql_steps: 0,
                ..config()
            },
        ),
        (
            "head_wait",
            ReceiptQuerySnapshotConfig {
                head_wait: Duration::MAX,
                ..config()
            },
        ),
        (
            "max_staleness",
            ReceiptQuerySnapshotConfig {
                max_staleness: Duration::MAX,
                ..config()
            },
        ),
        (
            "extension_tick",
            ReceiptQuerySnapshotConfig {
                extension_tick: Duration::ZERO,
                ..config()
            },
        ),
        (
            "extension_tick",
            ReceiptQuerySnapshotConfig {
                extension_tick: Duration::MAX,
                ..config()
            },
        ),
        (
            "recertify_interval",
            ReceiptQuerySnapshotConfig {
                recertify_interval: Duration::MAX,
                ..config()
            },
        ),
        (
            "invalid_retry_backoff",
            ReceiptQuerySnapshotConfig {
                invalid_retry_backoff: Duration::ZERO,
                ..config()
            },
        ),
        (
            "invalid_retry_backoff",
            ReceiptQuerySnapshotConfig {
                invalid_retry_backoff: Duration::MAX,
                ..config()
            },
        ),
        (
            "walker_busy_timeout",
            ReceiptQuerySnapshotConfig {
                walker_busy_timeout: Duration::MAX,
                ..config()
            },
        ),
    ];
    for (field, config) in invalid {
        match ReceiptQuerySnapshots::start(fixture.store.clone(), config) {
            Ok(service) => {
                service.shutdown();
                panic!("a {field} outside its bounds was accepted");
            }
            Err(error) => match snapshot_error(error) {
                ReceiptQuerySnapshotError::Unavailable(message) => {
                    assert!(message.contains(field), "{field}: {message}");
                }
                other => panic!("{field}: {other:?}"),
            },
        }
    }
}
