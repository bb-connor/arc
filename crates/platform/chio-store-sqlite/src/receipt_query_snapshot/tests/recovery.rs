//! Genuine page quotas and explicit owner recovery. No test fills the host
//! filesystem or raises a budget through a receipt query. Waits block on the
//! service's own notifications; their timeouts only bound a hang, and every
//! claim is asserted on how a backoff wait ended.
use super::super::service::{
    ReceiptQuerySnapshotConfig, ReceiptQuerySnapshotRecovery, ReceiptQuerySnapshotRecoveryError,
    ReceiptQuerySnapshotState, ReceiptQuerySnapshots, WaitEnd, WaitRecord,
};
use super::service::{admin, config};
use super::support::{Fixture, Spec};
use std::time::Duration;

const HANG: Duration = Duration::from_secs(300);
const MIB: u64 = 1024 * 1024;

/// A history larger than the minimum quota, under a one-hour invalid backoff,
/// so the first resource wait is 30 s and every later one doubles to an hour.
fn full_projection() -> (Fixture, ReceiptQuerySnapshots) {
    let fixture = Fixture::new(0);
    for index in 0..192 {
        let mut spec = Spec::varied(index);
        spec.tool_name = format!("{index}-{}", "x".repeat(8192));
        fixture.append(&spec);
    }
    fixture.flush();
    let service = ReceiptQuerySnapshots::start(
        fixture.store.clone(),
        ReceiptQuerySnapshotConfig {
            quota_bytes: MIB,
            step_rows: 32,
            insert_rows: 16,
            invalid_retry_backoff: Duration::from_secs(3_600),
            ..config()
        },
    )
    .unwrap();
    (fixture, service)
}

fn ready(fixture: &Fixture, config: ReceiptQuerySnapshotConfig) -> ReceiptQuerySnapshots {
    let service = ReceiptQuerySnapshots::start(fixture.store.clone(), config).unwrap();
    let status = service.wait_for_recovery(HANG, |status| {
        status.state == ReceiptQuerySnapshotState::Ready
    });
    assert_eq!(status.state, ReceiptQuerySnapshotState::Ready);
    service
}

/// The `index`th backoff wait, once the walker has entered it.
fn entered(service: &ReceiptQuerySnapshots, index: usize) -> WaitRecord {
    let waits = service.await_waits_for_test(HANG, |waits| waits.len() > index);
    waits[index]
}

/// The `index`th backoff wait, once it has ended.
fn ended(service: &ReceiptQuerySnapshots, index: usize) -> WaitRecord {
    let waits = service.await_waits_for_test(HANG, |waits| {
        waits.get(index).is_some_and(|wait| wait.end.is_some())
    });
    waits[index]
}

fn lineage(service: &ReceiptQuerySnapshots) -> String {
    let snapshot = service.query_receipts(&admin(1)).unwrap().snapshot.unwrap();
    snapshot.snapshot_id.split(':').next().unwrap().to_string()
}

#[test]
fn an_owner_quota_increase_recovers_a_real_full_projection_without_restart() {
    let (_fixture, service) = full_projection();
    let wait = entered(&service, 0);
    assert_eq!(
        (wait.wait, wait.answers_retry, wait.end),
        (Duration::from_secs(30), true, None)
    );
    match service.recovery_status().state {
        ReceiptQuerySnapshotState::Unavailable { reason } => {
            assert!(
                reason.contains("backing storage or configured quota"),
                "{reason}"
            );
        }
        other => panic!("wrong quota outcome: {other:?}"),
    }
    assert_eq!(service.status().quota_bytes, MIB);
    service.increase_quota_bytes(8 * MIB).unwrap();
    assert_eq!(ended(&service, 0).end, Some(WaitEnd::QuotaRaised));
    let status = service.wait_for_recovery(HANG, |status| {
        status.state == ReceiptQuerySnapshotState::Ready
    });
    assert_eq!(status.state, ReceiptQuerySnapshotState::Ready);
    assert_eq!(
        (
            status.quota_wakes,
            status.retry_wakes,
            status.deadline_wakes
        ),
        (1, 0, 0)
    );
    let result = service.query_receipts(&admin(1)).unwrap();
    assert_eq!(result.total_count, 192);
    assert_eq!(service.status().quota_bytes, 8 * MIB);
    assert!(service.status().used_bytes <= 8 * MIB);
    service.shutdown();
}

#[test]
fn resource_backoff_doubles_to_its_cap_and_each_retry_wakes_it_by_request() {
    let (_fixture, service) = full_projection();
    let expected = [30, 60, 120, 240, 480, 960, 1_920, 3_600, 3_600];
    for (index, seconds) in expected.into_iter().enumerate() {
        let wait = entered(&service, index);
        assert_eq!(
            (wait.wait, wait.answers_retry),
            (Duration::from_secs(seconds), true),
            "wait {index}"
        );
        let epoch = u64::try_from(index).unwrap() + 1;
        assert_eq!(
            service.request_recovery(None),
            Ok(ReceiptQuerySnapshotRecovery::Scheduled { epoch })
        );
        assert_eq!(
            ended(&service, index).end,
            Some(WaitEnd::RetryRequested),
            "wait {index}"
        );
    }
    entered(&service, expected.len());
    let status = service.recovery_status();
    assert!(
        matches!(status.state, ReceiptQuerySnapshotState::Unavailable { .. }),
        "{status:?}"
    );
    assert_eq!(status.requested_quota_bytes, MIB);
    assert_eq!((status.retry_requested, status.retry_answered), (9, 9));
    assert_eq!(
        (
            status.retry_wakes,
            status.quota_wakes,
            status.deadline_wakes
        ),
        (9, 0, 0)
    );
    service.shutdown();
}

#[test]
fn shutdown_during_a_resource_backoff_stops_cleanly_and_refuses_recovery() {
    let (_fixture, service) = full_projection();
    assert_eq!(entered(&service, 0).end, None);
    service.shutdown();
    assert_eq!(ended(&service, 0).end, Some(WaitEnd::Cancelled));
    assert_eq!(
        service.request_recovery(Some(8 * MIB)),
        Err(ReceiptQuerySnapshotRecoveryError::Stopped)
    );
    assert_eq!(
        service.request_recovery(None),
        Err(ReceiptQuerySnapshotRecoveryError::Stopped)
    );
    let status = service.recovery_status();
    assert_eq!(status.state, ReceiptQuerySnapshotState::Stopped);
    assert_eq!(status.requested_quota_bytes, MIB);
    assert_eq!((status.retry_requested, status.retry_answered), (0, 0));
    assert_eq!(
        (
            status.retry_wakes,
            status.quota_wakes,
            status.deadline_wakes
        ),
        (0, 0, 0)
    );
}

#[test]
fn a_retry_waits_out_an_integrity_backoff_and_the_next_attempt_answers_it() {
    let fixture = Fixture::new(0);
    fixture.append_varied(0..4);
    let service = ready(
        &fixture,
        ReceiptQuerySnapshotConfig {
            quota_bytes: MIB,
            invalid_retry_backoff: Duration::from_secs(3_600),
            ..config()
        },
    );
    service.invalidate_for_test("operator retry control");
    let wait = entered(&service, 0);
    assert_eq!(
        (wait.wait, wait.answers_retry),
        (Duration::from_secs(3_600), false)
    );
    assert_eq!(
        service.request_recovery(None),
        Ok(ReceiptQuerySnapshotRecovery::Scheduled { epoch: 1 })
    );
    let waits = service.await_waits_for_test(HANG, |waits| {
        waits[0].end.is_some() || waits[0].seen_retry >= 1
    });
    assert_eq!(
        (waits[0].seen_retry, waits[0].end),
        (1, None),
        "an integrity backoff must keep waiting after it observed the retry"
    );
    service.increase_quota_bytes(2 * MIB).unwrap();
    assert_eq!(ended(&service, 0).end, Some(WaitEnd::QuotaRaised));
    let status = service.wait_for_recovery(HANG, |status| {
        status.state == ReceiptQuerySnapshotState::Ready
    });
    // The quota increase is itself a second recovery request.
    assert_eq!((status.retry_requested, status.retry_answered), (2, 2));
    assert_eq!(
        (
            status.retry_wakes,
            status.quota_wakes,
            status.deadline_wakes
        ),
        (0, 1, 0)
    );
    assert_eq!(service.query_receipts(&admin(100)).unwrap().total_count, 4);
    service.shutdown();
}

#[test]
fn a_retry_on_a_serving_projection_schedules_no_rebuild_and_refusals_change_nothing() {
    let fixture = Fixture::new(0);
    fixture.append_varied(0..4);
    let service = ready(
        &fixture,
        ReceiptQuerySnapshotConfig {
            quota_bytes: MIB,
            ..config()
        },
    );
    let original = lineage(&service);
    assert_eq!(
        service.request_recovery(None),
        Ok(ReceiptQuerySnapshotRecovery::Serving)
    );
    assert_eq!(
        service.request_recovery(Some(1024)),
        Err(ReceiptQuerySnapshotRecoveryError::QuotaOutOfBounds {
            requested_bytes: 1024
        })
    );
    assert_eq!(
        service.request_recovery(Some(2 * MIB)),
        Ok(ReceiptQuerySnapshotRecovery::Serving)
    );
    assert_eq!(
        service.request_recovery(Some(MIB)),
        Err(ReceiptQuerySnapshotRecoveryError::QuotaBelowCurrent {
            requested_bytes: MIB,
            current_bytes: 2 * MIB,
        })
    );
    fixture.append_varied(4..7);
    assert_eq!(service.query_receipts(&admin(100)).unwrap().total_count, 7);
    assert_eq!(lineage(&service), original);
    let status = service.recovery_status();
    assert_eq!(status.requested_quota_bytes, 2 * MIB);
    assert_eq!((status.retry_requested, status.retry_answered), (0, 0));
    assert!(service
        .await_waits_for_test(Duration::ZERO, |_| true)
        .is_empty());
    service.shutdown();
}

#[test]
fn quota_growth_preserves_a_healthy_projection_and_refuses_budget_reduction() {
    let fixture = Fixture::new(0);
    fixture.append_varied(0..4);
    let service = super::service::ready(
        &fixture,
        ReceiptQuerySnapshotConfig {
            quota_bytes: MIB,
            ..config()
        },
    );
    let first = service.query_receipts(&admin(1)).unwrap().snapshot.unwrap();
    service.increase_quota_bytes(2 * MIB).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while service.status().quota_bytes != 2 * MIB {
        assert!(
            std::time::Instant::now() < deadline,
            "quota increase was not applied"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let after = service.query_receipts(&admin(1)).unwrap().snapshot.unwrap();
    assert_eq!(
        first.snapshot_id.split(':').next(),
        after.snapshot_id.split(':').next()
    );
    assert_eq!(service.query_receipts(&admin(100)).unwrap().total_count, 4);
    let error = service.increase_quota_bytes(MIB).unwrap_err();
    assert!(error.to_string().contains("cannot lower"), "{error}");
    assert_eq!(service.status().quota_bytes, 2 * MIB);
    service.shutdown();
}
