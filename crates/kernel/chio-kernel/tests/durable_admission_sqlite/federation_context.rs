use super::*;
use chio_core::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core::receipt::decision::{Decision, ToolCallAction};
use chio_federation::bilateral::{
    BilateralCoSigningError, BilateralCoSigningProtocol, CoSigningRequest, CoSigningResponse,
    InProcessCoSigner,
};
use chio_federation::trust_establishment::{KernelTrustExchange, PeerHandshakeEnvelope};
use chio_kernel::{
    FederationTreatyAdmissionBinding, FederationTreatyVerification,
    QualifiedAdmissionProjectionStore, RuntimeAdmissionContext, RuntimeAdmissionDecision,
    RuntimeAdmissionHook, VerifiedFederationTreatyMaterial,
};
use chio_store_sqlite::SqliteReceiptStore;

include!("../support/treaty_dsse.rs");

struct UnavailableCosigner;

impl BilateralCoSigningProtocol for UnavailableCosigner {
    fn request_cosignature(
        &self,
        _: &CoSigningRequest,
    ) -> Result<CoSigningResponse, BilateralCoSigningError> {
        Err(BilateralCoSigningError::PeerRejected(
            "injected outage after local completion".into(),
        ))
    }
}

struct RejectNewRuntimeAdmission(Arc<AtomicU64>);

impl RuntimeAdmissionHook for RejectNewRuntimeAdmission {
    fn name(&self) -> &str {
        "no-new-admission-during-recovery"
    }

    fn evaluate(
        &self,
        _: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(RuntimeAdmissionDecision::deny(
            "fresh admission is deliberately unavailable",
            None,
        ))
    }
}

#[test]
fn sqlite_retained_federation_context_survives_owner_restart_without_redispatch(
) -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    secure_directory(directory.path())?;
    let lock_root = directory.path().join("locks");
    create_private_directory(&lock_root)?;
    let database = directory.path().join("authority.db");
    let receipts = directory.path().join("receipts.db");
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let keypair = Keypair::generate();
    let origin_keypair = Keypair::generate();
    let trust = KernelTrustExchange::new("kernel.org-b", keypair.clone())
        .with_trusted_peer("kernel.org-a", origin_keypair.public_key());
    let now = now_unix_ms()? / 1_000;
    let envelope = PeerHandshakeEnvelope::sign(
        "kernel.org-a",
        "kernel.org-b",
        "retained-federation-sqlite",
        now,
        &origin_keypair,
    )?;
    let peer = trust.accept_envelope(&envelope, "kernel.org-a", now)?;
    let invocations = Arc::new(AtomicU64::new(0));

    let (request, operation_id, raw_before) = {
        let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
        let operations = Arc::new(authority.admission_operation_store());
        let outcomes = Arc::new(authority.tool_outcome_store());
        let mut kernel = ChioKernel::new(kernel_config(keypair.clone()))
            .with_federation_peers(vec![peer.clone()]);
        kernel.set_federation_local_kernel_id("kernel.org-b");
        let receipt_store = SqliteReceiptStore::open(&receipts)?;
        receipt_store.flush_receipt_writes()?;
        kernel.set_receipt_store(Box::new(receipt_store))?;
        kernel.set_durable_admission_store(
            operations.clone(),
            outcomes.clone(),
            authority.mutation_fence(),
        )?;
        kernel.set_budget_store_handle(Arc::new(authority.budget_store()));
        kernel.set_runtime_admission_hook(Arc::new(TreatyDsseAdmissionHook::new(
            origin_keypair.clone(),
            keypair.clone(),
        )));
        kernel.set_federation_cosigner(Arc::new(UnavailableCosigner));
        kernel.register_tool_server(Box::new(MutationServer {
            invocations: invocations.clone(),
        }));
        let mut scope = scope();
        scope.grants[0].max_invocations = Some(2);
        let capability = kernel.issue_capability(&Keypair::generate().public_key(), scope, 300)?;
        let mut request = request(&capability);
        request.federated_origin_kernel_id = Some("kernel.org-a".into());
        let result = kernel.evaluate_tool_call_blocking(&request);
        assert!(
            matches!(result, Err(KernelError::Internal(reason)) if reason.contains("bilateral co-sign failed"))
        );
        assert_eq!(invocations.load(Ordering::SeqCst), 1);
        let projected = operations.list_admission_receipts_after(None, 10)?;
        assert_eq!(projected.len(), 1);
        let metadata: AdmissionReceiptMetadataV1 = serde_json::from_value(
            projected[0].metadata.as_ref().ok_or("receipt metadata")?
                [ADMISSION_RECEIPT_METADATA_KEY]
                .clone(),
        )?;
        assert_eq!(metadata.projected_state, AdmissionOperationState::Completed);
        let operation_id = metadata.operation_id;
        let raw = outcomes
            .load_raw_invocation_by_operation(&operation_id)?
            .ok_or("raw outcome")?;
        let raw_before = raw.canonical_blob()?.bytes().to_vec();
        assert!(raw.to_persisted().federation_context_json.is_some());
        assert_eq!(
            authority
                .budget_store()
                .get_usage(&capability.id, 0)?
                .ok_or("usage")?
                .invocation_count,
            1
        );
        (request, operation_id, raw_before)
    };

    // Drop every old owner handle before reopening the physical authority.
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let outcomes = Arc::new(authority.tool_outcome_store());
    let mut kernel =
        ChioKernel::new(kernel_config(keypair.clone())).with_federation_peers(vec![peer]);
    kernel.set_federation_local_kernel_id("kernel.org-b");
    let receipt_store = Arc::new(SqliteReceiptStore::open(&receipts)?);
    // Wait on the actor's verification barrier, not a timing-dependent sleep.
    receipt_store.flush_receipt_writes()?;
    kernel.set_receipt_store_handle(receipt_store.clone())?;
    assert!(
        !receipt_store.writer_serving_closed(),
        "{:?}",
        receipt_store.receipt_store_health()?
    );
    kernel.set_durable_admission_store(
        Arc::new(authority.admission_operation_store()),
        outcomes.clone(),
        authority.mutation_fence(),
    )?;
    kernel.set_budget_store_handle(Arc::new(authority.budget_store()));
    kernel.register_tool_server(Box::new(MutationServer {
        invocations: invocations.clone(),
    }));
    let admissions = Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(Arc::new(RejectNewRuntimeAdmission(admissions.clone())));
    kernel.set_federation_cosigner(Arc::new(InProcessCoSigner::new(
        "kernel.org-a",
        origin_keypair,
        keypair.public_key(),
    )));
    // Public replay still requires a registered target, live peer and valid capability.
    // The already executed operation must not reacquire runtime admission.
    let response = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(admissions.load(Ordering::SeqCst), 0);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    let raw = outcomes
        .load_raw_invocation_by_operation(&operation_id)?
        .ok_or("raw after restart")?;
    assert_eq!(raw.canonical_blob()?.bytes(), raw_before.as_slice());
    assert_eq!(
        authority
            .budget_store()
            .get_usage(&request.capability.id, 0)?
            .ok_or("usage")?
            .invocation_count,
        1
    );
    assert!(kernel.dual_signed_receipt(&response.receipt.id).is_some());
    assert!(kernel
        .federation_dsse_envelope(&response.receipt.id)
        .is_some());
    assert!(response.receipt.verify_signature()?);
    let repeated = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(
        canonical_json_bytes(&repeated.receipt)?,
        canonical_json_bytes(&response.receipt)?
    );
    assert_eq!(admissions.load(Ordering::SeqCst), 0);
    Ok(())
}
