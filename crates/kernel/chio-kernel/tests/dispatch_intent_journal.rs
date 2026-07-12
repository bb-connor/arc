//! Kernel-surface tests for the durable dispatch-intent journal: fail-closed
//! trait defaults, the class gate, same-transaction consume, the money-path
//! rail reference, and boot reconciliation.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_core::crypto::Keypair;
use chio_core::receipt::{
    body::{ChioReceipt, ChioReceiptBody},
    decision::{Decision, ToolCallAction},
};
use chio_kernel::receipt_store::{
    DispatchIntentKey, DispatchIntentReconciler, DispatchIntentRecord, DispatchIntentResolution,
    ReceiptStore, ReceiptStoreError, SideEffectClass,
};

/// A minimal append-only store: every journal method must fail closed (or
/// no-op empty for reconciliation and counts) by default, so a store that
/// never opted into the journal can never silently accept an intent.
struct UnsupportedStore;

impl ReceiptStore for UnsupportedStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &chio_core::receipt::lineage::ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }
}

struct DeadLetterEverything;

impl DispatchIntentReconciler for DeadLetterEverything {
    fn resolve(
        &self,
        _intent: &DispatchIntentRecord,
    ) -> Result<DispatchIntentResolution, ReceiptStoreError> {
        Ok(DispatchIntentResolution::DeadLetter {
            detail: "outcome unknown".to_string(),
        })
    }
}

fn sample_intent_record(request_id: &str) -> DispatchIntentRecord {
    DispatchIntentRecord {
        request_id: request_id.to_string(),
        capability_id: "cap-1".to_string(),
        tool_server: "srv".to_string(),
        tool_name: "tool".to_string(),
        parameter_hash: "hash".to_string(),
        side_effect_class: SideEffectClass::SideEffecting,
        monetary: false,
        rail: None,
        rail_authorization_id: None,
        tenant_id: None,
        created_at_unix_ms: 1,
    }
}

fn sample_receipt() -> ChioReceipt {
    let keypair = Keypair::from_seed(&[0x17; 32]);
    let action =
        ToolCallAction::from_parameters(serde_json::json!({"k": "v"})).expect("hash parameters");
    ChioReceipt::sign(
        ChioReceiptBody {
            id: "rcpt-journal-default".to_string(),
            timestamp: 1,
            capability_id: "cap-1".to_string(),
            tool_server: "srv".to_string(),
            tool_name: "tool".to_string(),
            action,
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: "content-1".to_string(),
            policy_hash: "policy-1".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        &keypair,
    )
    .expect("sign receipt")
}

#[test]
fn journal_trait_methods_fail_closed_by_default() {
    let store = UnsupportedStore;

    let record = sample_intent_record("req-1");
    assert!(store.record_dispatch_intent(&record).is_err());
    assert!(store
        .record_dispatch_intent_with_timeout(&record, std::time::Duration::from_millis(50))
        .is_err());

    let key = DispatchIntentKey {
        request_id: "req-1".to_string(),
        parameter_hash: "hash".to_string(),
        tenant_id: None,
    };
    let receipt = sample_receipt();
    assert!(store
        .append_chio_receipt_consuming_intent(&receipt, &key)
        .is_err());
    assert!(store
        .append_chio_receipt_consuming_intent_with_timeout(
            &receipt,
            &key,
            std::time::Duration::from_millis(50),
        )
        .is_err());
    assert!(store
        .attach_dispatch_intent_rail_ref("req-1", "auth-1")
        .is_err());

    // Reconcile is a no-op default: a store without the journal has no orphans.
    let report = store
        .reconcile_dispatch_intents(&DeadLetterEverything)
        .expect("default reconcile is a no-op");
    assert_eq!(report.open, 0);
    assert_eq!(report.dead_lettered, 0);
    assert_eq!(report.replayed, 0);
    assert_eq!(report.monetary_reconciled, 0);
    assert_eq!(store.open_dispatch_intent_count().unwrap_or(0), 0);
    assert_eq!(store.dead_letter_dispatch_intent_count().unwrap_or(0), 0);
}
