//! Tasks 4 and 5: the published service, extension, recertification, leases
//! and leaf-bound fetch (C1, C2, C3, C8b, C10, C11, C12, C13, C14, C15).
use std::time::{Duration, Instant};

use chio_kernel::receipt_query::{ReceiptQuery, ReceiptQuerySnapshotError, ReceiptReadContext};
use chio_kernel::ReceiptStoreError;
use rusqlite::params;

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
fn c1_a_page_verifies_only_the_receipts_it_returns() {
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
fn c10_a_version_older_than_the_staleness_bound_is_refused_until_extension_resumes() {
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
fn c11_a_regressed_claim_log_invalidates_the_snapshot() {
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
fn c12_an_invalid_snapshot_is_never_revived_and_a_rebuild_starts_a_new_lineage() {
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
fn c13_a_lease_fails_on_invalidation_but_not_on_a_new_generation() {
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
fn c2_an_unreturned_mutation_never_changes_an_answer_and_recertification_detects_it() {
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
fn c2_an_in_place_byte_edit_is_detected_by_recertification() {
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
fn c3_a_substituted_returned_receipt_fails_the_leaf_check() {
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
fn c8b_reads_are_never_served_while_the_build_cannot_complete() {
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
fn c14_reads_stay_correct_while_recertification_runs() {
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
fn c15_shutdown_stops_the_walker_and_refuses_reads() {
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
