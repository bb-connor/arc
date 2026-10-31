use super::*;

use std::sync::atomic::{AtomicUsize, Ordering};

use chio_core::receipt::{
    body::ChioReceiptBody, decision::Decision, decision::ToolCallAction, kinds::TrustLevel,
};

struct AppendOnlyStore;

impl ReceiptStore for AppendOnlyStore {
    no_receipt_openings!();
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }
}

#[test]
fn retained_child_lookup_is_unsupported_for_append_only_stores() {
    assert!(matches!(
        AppendOnlyStore.load_retained_child_receipt("unknown-child"),
        Err(ReceiptStoreError::Unsupported(_))
    ));
}

struct CountingAppendStore {
    append_calls: AtomicUsize,
}

impl ReceiptStore for CountingAppendStore {
    no_receipt_openings!();
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        self.append_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }
}

struct AtomicStoreWithoutTimeout {
    append_calls: AtomicUsize,
}

impl ReceiptStore for AtomicStoreWithoutTimeout {
    no_receipt_openings!();
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        self.append_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn atomic_receipt_projection(&self) -> AtomicReceiptProjection {
        AtomicReceiptProjection::SettlementObservationV1
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }
}

fn signed_receipt() -> ChioReceipt {
    let keypair = Keypair::generate();
    let action = match ToolCallAction::from_parameters(serde_json::json!({})) {
        Ok(action) => action,
        Err(error) => panic!("test action construction failed: {error}"),
    };
    let body = ChioReceiptBody {
        id: "receipt-1".to_string(),
        timestamp: 1,
        capability_id: "capability-1".to_string(),
        tool_server: "server".to_string(),
        tool_name: "tool".to_string(),
        action,
        decision: Some(Decision::Allow),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash: "content".to_string(),
        policy_hash: "policy".to_string(),
        evidence: Vec::new(),
        metadata: None,
        trust_level: TrustLevel::default(),
        tenant_id: None,
        kernel_key: keypair.public_key(),
        bbs_projection_version: None,
    };
    match ChioReceipt::sign(body, &keypair) {
        Ok(receipt) => receipt,
        Err(error) => panic!("test receipt signing failed: {error}"),
    }
}

#[test]
fn unsupported_atomic_projection_never_falls_back_to_receipt_only_append() {
    let store = CountingAppendStore {
        append_calls: AtomicUsize::new(0),
    };
    let receipt = signed_receipt();

    assert_eq!(
        store.atomic_receipt_projection(),
        AtomicReceiptProjection::Unsupported
    );
    assert!(!store.supports_atomic_receipt_projection_with_timeout());
    assert_eq!(store.settlement_store_binding(), None);
    let pending = PendingSettlementObservation {
        next_visible_at_ms: 1,
    };
    assert!(matches!(
        store.append_chio_receipt_with_pending_observation_and_timeout(
            &receipt,
            &pending,
            std::time::Duration::from_millis(1),
        ),
        Err(ReceiptStoreError::Unsupported(message))
            if message == "atomic settlement observation projection"
    ));
    assert_eq!(store.append_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn timed_atomic_projection_requires_timeout_support() {
    let store = AtomicStoreWithoutTimeout {
        append_calls: AtomicUsize::new(0),
    };
    let receipt = signed_receipt();
    let pending = PendingSettlementObservation {
        next_visible_at_ms: 1,
    };

    assert_eq!(
        store.atomic_receipt_projection(),
        AtomicReceiptProjection::SettlementObservationV1
    );
    assert!(!store.supports_atomic_receipt_projection_with_timeout());
    assert!(matches!(
        store.append_chio_receipt_with_pending_observation_and_timeout(
            &receipt,
            &pending,
            std::time::Duration::from_millis(1),
        ),
        Err(ReceiptStoreError::Unsupported(message))
            if message == "atomic settlement observation projection"
    ));
    assert_eq!(store.append_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn unsupported_durability_surfaces_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let store = AppendOnlyStore;
    let checkpoint =
        crate::checkpoint::build_checkpoint(1, 1, 1, &[b"receipt".to_vec()], &Keypair::generate())?;

    assert!(matches!(
        store.receipts_canonical_bytes_range(1, 1),
        Err(ReceiptStoreError::Conflict(message))
            if message.contains("receipt canonical byte ranges are not supported")
    ));
    assert!(matches!(
        store.flush_receipt_writes(),
        Err(ReceiptStoreError::Conflict(message))
            if message.contains("receipt writer flush is not supported")
    ));
    assert!(matches!(
        store.flush_receipt_writes_with_timeout(std::time::Duration::from_millis(1)),
        Err(ReceiptStoreError::Conflict(message))
            if message.contains("receipt writer flush is not supported")
    ));
    assert!(matches!(
        store.receipt_store_health(),
        Err(ReceiptStoreError::Conflict(message))
            if message.contains("receipt store health is not supported")
    ));
    assert!(matches!(
        store.latest_committed_entry_seq(),
        Err(ReceiptStoreError::Conflict(message))
            if message.contains("receipt committed sequence reporting is not supported")
    ));
    assert!(matches!(
        store.latest_checkpointed_entry_seq(),
        Err(ReceiptStoreError::Conflict(message))
            if message.contains("receipt checkpoint sequence reporting is not supported")
    ));
    assert!(matches!(
        store.next_checkpoint_range(1),
        Err(ReceiptStoreError::Conflict(message))
            if message.contains("receipt checkpoint ranges are not supported")
    ));
    assert!(matches!(
        store.receipt_checkpoint_status(Some(1)),
        Err(ReceiptStoreError::Conflict(message))
            if message.contains("receipt checkpoint status is not supported")
    ));
    assert!(matches!(
        store.store_checkpoint(&checkpoint),
        Err(ReceiptStoreError::Conflict(message))
            if message.contains("receipt checkpoint storage is not supported")
    ));
    assert!(matches!(
        store.rotate_receipts(&RetentionConfig::default()),
        Err(ReceiptStoreError::Conflict(message))
            if message.contains("receipt retention is not supported")
    ));
    Ok(())
}

/// A store whose background rotation always fails, recording the outcome the
/// maintenance worker hands it and reflecting it in health, so a persistent
/// retention failure is observable rather than silently healthy.
#[derive(Default)]
struct FailingRetentionStore {
    retention_error: std::sync::Mutex<Option<String>>,
    rotations: std::sync::atomic::AtomicU64,
}

impl ReceiptStore for FailingRetentionStore {
    no_receipt_openings!();
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn supports_retention(&self) -> bool {
        true
    }

    fn rotate_receipts(&self, _config: &RetentionConfig) -> Result<u64, ReceiptStoreError> {
        self.rotations
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(ReceiptStoreError::Conflict(
            "archive path is unwritable".to_string(),
        ))
    }

    fn record_retention_rotation_outcome(&self, failure: Option<&str>) {
        if let Ok(mut guard) = self.retention_error.lock() {
            *guard = failure.map(ToString::to_string);
        }
    }

    fn receipt_store_health(&self) -> Result<ReceiptStoreHealthReport, ReceiptStoreError> {
        let retention_error = self.retention_error.lock().ok().and_then(|g| g.clone());
        Ok(ReceiptStoreHealthReport {
            healthy: retention_error.is_none(),
            retention_error,
            ..ReceiptStoreHealthReport::default()
        })
    }
}

#[test]
fn background_retention_failure_surfaces_in_health() {
    let store = std::sync::Arc::new(FailingRetentionStore::default());
    // A store with no rotation attempt yet reports healthy.
    assert!(store.receipt_store_health().expect("health report").healthy);

    let config = RetentionConfig {
        check_interval_secs: 1,
        ..RetentionConfig::default()
    };
    let handle = RetentionMaintenanceHandle::spawn(store.clone(), config).unwrap();

    // The worker sleeps one interval (in 200ms slices) before its first
    // rotation, then records the failure into health. Poll until it appears.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline
        && store
            .receipt_store_health()
            .expect("health report")
            .retention_error
            .is_none()
    {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    let report = store.receipt_store_health().expect("health report");
    drop(handle);
    assert!(
        store.rotations.load(std::sync::atomic::Ordering::SeqCst) > 0,
        "the maintenance worker never attempted a rotation"
    );
    assert!(
        !report.healthy,
        "a persistently failing background rotation must mark the store unhealthy"
    );
    let message = report
        .retention_error
        .expect("the background rotation failure must surface in health");
    assert!(
        message.contains("archive path is unwritable"),
        "unexpected retention error: {message}"
    );
}
