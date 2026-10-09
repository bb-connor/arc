//! Publication of extension ranges that a checkpoint covers: no row of such
//! a range is served before the checkpoint's signed root is verified over it.
use std::time::{Duration, Instant};

use chio_kernel::receipt_query::{ReceiptQuerySnapshotError, ReceiptReadContext};

use super::super::db::SnapshotDbError;
use super::super::service::{
    GateAction, GatePoint, ReceiptQuerySnapshotConfig, ReceiptQuerySnapshotState,
    ReceiptQuerySnapshots,
};
use super::service::{admin, config, ready, snapshot_error, wait_for};
use super::support::{context, keypair, limits, substitute, target, Fixture, Spec};

/// A ready service over two checkpointed batches of four, with extension
/// paused and a third checkpointed batch appended behind it. Returns once
/// the store's observation covers the third batch with its checkpoint.
fn paused_before_a_checkpointed_batch() -> (Fixture, ReceiptQuerySnapshots) {
    let fixture = Fixture::new(4);
    fixture.append_varied(0..8);
    let service = ready(
        &fixture,
        ReceiptQuerySnapshotConfig {
            head_wait: Duration::from_millis(100),
            invalid_retry_backoff: Duration::from_secs(3),
            ..config()
        },
    );
    service.pause_extension_for_test(true);
    fixture.append_varied(8..12);
    let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ctx = context(&fixture.store, &cancel, limits());
    let deadline = Instant::now() + Duration::from_secs(60);
    while target(&ctx).checkpoint < 3 {
        assert!(
            Instant::now() < deadline,
            "the third batch was never checkpointed"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    (fixture, service)
}

/// Resume extension and wait until it reaches the armed gate.
fn resume_to(service: &ReceiptQuerySnapshots, point: GatePoint, action: GateAction, skip: u32) {
    service.arm_gate_for_test(point, action, skip);
    service.pause_extension_for_test(false);
    assert!(
        service.await_gate_for_test(Duration::from_secs(60)),
        "the extension never reached {point:?}"
    );
}

fn served_ids(service: &ReceiptQuerySnapshots) -> Vec<String> {
    service
        .query_receipts(&admin(100))
        .map(|page| {
            page.receipts
                .into_iter()
                .map(|row| row.receipt.id)
                .collect()
        })
        .unwrap_or_default()
}

fn point(service: &ReceiptQuerySnapshots, id: &str) -> Option<String> {
    match service.load_receipt(id, &ReceiptReadContext::admin_service()) {
        Ok((Some(receipt), _)) => Some(receipt.id),
        _ => None,
    }
}

/// Another validly signed receipt in place of varied receipt `index`, claim
/// entry and source row together, so only the signed checkpoint root can
/// tell.
fn substitute_signed(fixture: &Fixture, index: u64) -> String {
    let original = Spec::varied(index).sign(&keypair());
    let replacement = {
        let mut spec = Spec::varied(index);
        spec.timestamp += 1;
        spec.sign(&keypair())
    };
    substitute(fixture, &original, &replacement);
    replacement.id
}

/// Wait until every receipt of the three batches is served under the third
/// checkpoint.
fn await_verified_batch(service: &ReceiptQuerySnapshots) {
    let last = Spec::varied(11).sign(&keypair()).id;
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok((Some(_), watermark)) =
            service.load_receipt(&last, &ReceiptReadContext::admin_service())
        {
            if watermark.checkpoint_seq.is_some_and(|seq| seq >= 3) {
                break;
            }
        }
        assert!(
            Instant::now() < deadline,
            "the verified batch was never served under its checkpoint"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(served_ids(service).len(), 12);
}

#[test]
fn a_receipt_a_new_checkpoint_covers_is_not_served_before_its_root_is_verified() {
    let (fixture, service) = paused_before_a_checkpointed_batch();
    let replacement = substitute_signed(&fixture, 10);
    resume_to(&service, GatePoint::Settlement, GateAction::Hold, 0);

    assert_eq!(
        point(&service, &replacement),
        None,
        "a receipt in a newly checkpointed range was served before its checkpoint root was verified"
    );
    assert!(
        !served_ids(&service).contains(&replacement),
        "a page served a receipt in a newly checkpointed range before its root was verified"
    );

    service.release_gate_for_test();
    wait_for(&service, "invalid", |state| {
        matches!(state, ReceiptQuerySnapshotState::Invalid { .. })
    });
    let refused = service.load_receipt(&replacement, &ReceiptReadContext::admin_service());
    assert!(matches!(
        refused.map_err(snapshot_error),
        Err(ReceiptQuerySnapshotError::Invalid(_))
    ));
    service.shutdown();
}

#[test]
fn a_valid_checkpointed_batch_is_served_once_its_root_is_verified() {
    let (_fixture, service) = paused_before_a_checkpointed_batch();
    let appended = Spec::varied(10).sign(&keypair()).id;
    resume_to(&service, GatePoint::Settlement, GateAction::Hold, 0);
    // The previous version keeps serving; the new rows wait for the root.
    assert!(!served_ids(&service).contains(&appended));
    assert_eq!(served_ids(&service).len(), 8);
    service.release_gate_for_test();
    await_verified_batch(&service);
    // Leaves were staged in bounded holds.
    let staged = service.max_staged_per_hold_for_test();
    assert!(staged > 0 && staged <= u64::try_from(config().insert_rows).unwrap());
    service.shutdown();
}

#[test]
fn a_receipt_changed_after_its_root_was_verified_is_never_published() {
    let (fixture, service) = paused_before_a_checkpointed_batch();
    resume_to(&service, GatePoint::Publication, GateAction::Hold, 0);
    // The root was verified over the original leaves; the claim entry and
    // source row now hold another validly signed receipt.
    let replacement = substitute_signed(&fixture, 10);
    service.release_gate_for_test();
    let state = wait_for(&service, "invalid", |state| {
        matches!(state, ReceiptQuerySnapshotState::Invalid { .. })
    });
    assert!(
        format!("{state:?}").contains("changed after their checkpoint root was verified"),
        "{state:?}"
    );
    assert_eq!(point(&service, &replacement), None);
    service.shutdown();
}

#[test]
fn an_interrupted_staging_or_publication_resumes_from_the_published_version() {
    for (gate, skip) in [(GatePoint::Settlement, 0), (GatePoint::Publication, 1)] {
        let (_fixture, service) = paused_before_a_checkpointed_batch();
        // The cycle ends after staging, or after publishing the first
        // verified step of the batch.
        resume_to(&service, gate, GateAction::Interrupt, skip);
        await_verified_batch(&service);
        assert_eq!(service.status().state, ReceiptQuerySnapshotState::Ready);
        service.shutdown();
    }
}

#[test]
fn shutdown_while_a_checkpointed_range_is_staged_stops_the_walker() {
    let (_fixture, service) = paused_before_a_checkpointed_batch();
    resume_to(&service, GatePoint::Settlement, GateAction::Hold, 0);
    service.shutdown();
    assert_eq!(service.status().state, ReceiptQuerySnapshotState::Stopped);
}

#[test]
fn quota_exhaustion_while_staging_is_a_resource_outcome() {
    let (_fixture, service) = paused_before_a_checkpointed_batch();
    let appended = Spec::varied(10).sign(&keypair()).id;
    service.fail_next_commit_for_test(SnapshotDbError::Capacity {
        quota_bytes: 1,
        used_bytes: 1,
    });
    service.pause_extension_for_test(false);
    let state = wait_for(&service, "a resource outcome", |state| {
        *state != ReceiptQuerySnapshotState::Ready
    });
    assert!(
        matches!(&state, ReceiptQuerySnapshotState::Unavailable { reason } if reason.contains("quota")),
        "{state:?}"
    );
    assert_eq!(point(&service, &appended), None);
    service.shutdown();
}

/// Move only the unsigned end column of checkpoint `seq` one entry past
/// its signed batch end.
fn move_checkpoint_end(fixture: &Fixture, seq: i64) {
    let changed = fixture
        .tamper()
        .execute(
            "UPDATE kernel_checkpoints SET batch_end_seq = batch_end_seq + 1
             WHERE checkpoint_seq = ?1",
            [seq],
        )
        .unwrap();
    assert_eq!(changed, 1);
}

/// Poll until the snapshot leaves Ready, asserting `id` is never served.
fn never_served_until_refused(service: &ReceiptQuerySnapshots, id: &str, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        assert_eq!(point(service, id), None, "{what}");
        if matches!(
            service.status().state,
            ReceiptQuerySnapshotState::Invalid { .. }
        ) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the moved checkpoint end column was never refused"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn a_checkpoint_with_a_moved_end_column_still_covers_its_batch_in_extension() {
    let (fixture, service) = paused_before_a_checkpointed_batch();
    let replacement = substitute_signed(&fixture, 10);
    move_checkpoint_end(&fixture, 3);
    service.pause_extension_for_test(false);
    never_served_until_refused(
        &service,
        &replacement,
        "a receipt of a checkpointed batch was published as uncheckpointed tail",
    );
    service.shutdown();
}

#[test]
fn a_checkpoint_with_a_moved_end_column_still_covers_its_batch_in_the_build() {
    let fixture = Fixture::new(4);
    fixture.append_varied(0..12);
    let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ctx = context(&fixture.store, &cancel, limits());
    let deadline = Instant::now() + Duration::from_secs(60);
    while target(&ctx).checkpoint < 3 {
        assert!(
            Instant::now() < deadline,
            "the third batch was never checkpointed"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let replacement = substitute_signed(&fixture, 10);
    move_checkpoint_end(&fixture, 3);
    let service = ReceiptQuerySnapshots::start(
        fixture.store.clone(),
        ReceiptQuerySnapshotConfig {
            invalid_retry_backoff: Duration::from_secs(3),
            ..config()
        },
    )
    .unwrap();
    never_served_until_refused(
        &service,
        &replacement,
        "the build published a receipt of a checkpointed batch as uncheckpointed tail",
    );
    service.shutdown();
}

#[test]
fn recertification_refuses_a_checkpoint_whose_end_column_moved() {
    let fixture = Fixture::new(4);
    fixture.append_varied(0..12);
    let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ctx = context(&fixture.store, &cancel, limits());
    let deadline = Instant::now() + Duration::from_secs(60);
    while target(&ctx).checkpoint < 3 {
        assert!(
            Instant::now() < deadline,
            "the third batch was never checkpointed"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let service = ready(
        &fixture,
        ReceiptQuerySnapshotConfig {
            recertify_interval: Duration::from_millis(200),
            invalid_retry_backoff: Duration::from_secs(3),
            ..config()
        },
    );
    move_checkpoint_end(&fixture, 3);
    let state = wait_for(&service, "a refusal", |state| {
        matches!(state, ReceiptQuerySnapshotState::Invalid { .. })
    });
    assert!(format!("{state:?}").contains("checkpoint"), "{state:?}");
    service.shutdown();
}
