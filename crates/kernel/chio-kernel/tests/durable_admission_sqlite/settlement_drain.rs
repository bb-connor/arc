use super::*;
use chio_core::receipt::{
    body::{ChioReceipt, ChioReceiptBody},
    decision::{Decision, ToolCallAction},
    economics::{FinancialReceiptMetadata, SettlementStatus},
    kinds::{BoundaryClass, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel},
};
use chio_kernel::{PendingSettlementObservation, SettlementDrainTrust};
use chio_settle_types::{
    RetryPolicy, SettlementHook, SettlementHookError, SettlementObservation, SettlementOutcome,
    SettlementOutcomeStore,
};
use chio_store_sqlite::{SqliteReceiptStore, SqliteSettlementOutcomeStore};

struct CountingHook(AtomicU64);

impl SettlementHook for CountingHook {
    fn observe(
        &self,
        _observation: &SettlementObservation,
        _idempotency_key: &chio_settle_types::SettlementIdempotencyKey,
    ) -> Result<SettlementOutcome, SettlementHookError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(SettlementOutcome::accepted("sqlite-drain"))
    }
}

#[test]
fn settlement_drain_completes_257_persisted_claims() -> Result<(), Box<dyn Error>> {
    let _clock = chio_test_support::clock::scope_unix_secs(1_900_000_000);
    let root = tempfile::tempdir()?;
    secure_directory(root.path())?;
    let receipts = Arc::new(SqliteReceiptStore::open(
        root.path().join("receipts.sqlite3"),
    )?);
    let outcomes = Arc::new(SqliteSettlementOutcomeStore::open_alongside(&receipts)?);
    let keypair = Keypair::from_seed(&[117; 32]);
    let mut kernel = ChioKernel::new_with_clock(
        kernel_config(keypair.clone()),
        chio_test_support::clock::clock(),
    );
    kernel.set_receipt_store_handle(receipts.clone())?;
    let hook = Arc::new(CountingHook(AtomicU64::new(0)));
    kernel.set_settlement_observer_runtime(
        hook.clone(),
        outcomes.clone(),
        RetryPolicy::default(),
        SettlementDrainTrust::from(kernel.public_key()),
    )?;
    for sequence in 0..257_u64 {
        let body = ChioReceiptBody {
            id: format!("sqlite-drain-{sequence}"),
            timestamp: 1_900_000_000,
            capability_id: format!("cap-{sequence}"),
            tool_server: "settlement-test".to_string(),
            tool_name: "charge".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({"sequence": sequence}))?,
            decision: Some(Decision::Allow),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: format!("{sequence:064x}"),
            policy_hash: sha256_hex(b"sqlite-drain-policy"),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({"financial": FinancialReceiptMetadata {
                grant_index: 0,
                cost_charged: 100,
                currency: "USD".to_string(),
                budget_remaining: Some(900),
                budget_total: Some(1000),
                delegation_depth: 0,
                root_budget_holder: "sqlite-drain-agent".to_string(),
                payment_reference: None,
                settlement_status: SettlementStatus::Settled,
                cost_breakdown: None,
                oracle_evidence: None,
                attempted_cost: None,
            }})),
            trust_level: TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        };
        let receipt = ChioReceipt::sign(body, &keypair)?;
        assert!(receipt.verify_integrity_embedded_key()?);
        receipts.append_chio_receipt_with_pending_observation_and_timeout(
            &receipt,
            &PendingSettlementObservation {
                next_visible_at_ms: 0,
            },
            std::time::Duration::from_secs(5),
        )?;
    }
    let report = kernel.drain_settlement_attempts(257)?;
    assert_eq!(report.completed, 257);
    assert_eq!(report.lost_leases, 0);
    assert_eq!(hook.0.load(Ordering::SeqCst), 257);
    assert_eq!(kernel.drain_settlement_attempts(257)?.completed, 0);
    assert!(outcomes
        .claim_due("probe", 1_900_000_001_000, 30_000, 257)?
        .is_empty());
    assert_eq!(hook.0.load(Ordering::SeqCst), 257);
    Ok(())
}
