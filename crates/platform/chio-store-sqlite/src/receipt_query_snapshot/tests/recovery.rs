//! Genuine page quotas and explicit owner recovery. No test fills the host
//! filesystem or raises a budget through a receipt query.
use super::super::service::{
    ReceiptQuerySnapshotConfig, ReceiptQuerySnapshotState, ReceiptQuerySnapshots,
};
use super::service::{admin, config, wait_for};
use super::support::{Fixture, Spec};
use std::time::Duration;

#[test]
fn an_owner_quota_increase_recovers_a_real_full_projection_without_restart() {
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
            quota_bytes: 1024 * 1024,
            step_rows: 32,
            insert_rows: 16,
            invalid_retry_backoff: Duration::from_secs(60),
            ..config()
        },
    )
    .unwrap();
    let state = wait_for(&service, "actual quota refusal", |state| {
        matches!(state, ReceiptQuerySnapshotState::Unavailable { .. })
    });
    match state {
        ReceiptQuerySnapshotState::Unavailable { reason } => {
            assert!(
                reason.contains("backing storage or configured quota"),
                "{reason}"
            );
        }
        other => panic!("wrong quota outcome: {other:?}"),
    }
    assert_eq!(service.status().quota_bytes, 1024 * 1024);
    service.increase_quota_bytes(8 * 1024 * 1024).unwrap();
    wait_for(&service, "rebuild under explicit larger quota", |state| {
        *state == ReceiptQuerySnapshotState::Ready
    });
    let result = service.query_receipts(&admin(1)).unwrap();
    assert_eq!(result.total_count, 192);
    assert_eq!(service.status().quota_bytes, 8 * 1024 * 1024);
    assert!(service.status().used_bytes <= 8 * 1024 * 1024);
    service.shutdown();
}

#[test]
fn quota_growth_preserves_a_healthy_projection_and_refuses_budget_reduction() {
    let fixture = Fixture::new(0);
    fixture.append_varied(0..4);
    let service = super::service::ready(
        &fixture,
        ReceiptQuerySnapshotConfig {
            quota_bytes: 1024 * 1024,
            ..config()
        },
    );
    let first = service.query_receipts(&admin(1)).unwrap().snapshot.unwrap();
    service.increase_quota_bytes(2 * 1024 * 1024).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while service.status().quota_bytes != 2 * 1024 * 1024 {
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
    let error = service.increase_quota_bytes(1024 * 1024).unwrap_err();
    assert!(error.to_string().contains("cannot lower"), "{error}");
    assert_eq!(service.status().quota_bytes, 2 * 1024 * 1024);
    service.shutdown();
}
