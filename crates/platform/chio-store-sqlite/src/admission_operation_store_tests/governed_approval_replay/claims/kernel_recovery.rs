use super::*;
use chio_kernel::{ChioKernel, KernelConfig};

fn kernel(fixture: &Fixture) -> AnchoredTestResult<ChioKernel> {
    kernel_with_signer(fixture, Keypair::generate())
}

pub(super) fn kernel_with_signer(
    fixture: &Fixture,
    signer: Keypair,
) -> AnchoredTestResult<ChioKernel> {
    let mut kernel = ChioKernel::new(KernelConfig {
        keypair: signer,
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: sha256_hex(b"approval-custody-recovery"),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
    });
    kernel.set_durable_admission_store(
        Arc::new(fixture.store.clone()),
        Arc::new(fixture.authority.tool_outcome_store()),
        fixture.fence.clone(),
    )?;
    kernel.set_budget_store_handle(Arc::new(fixture.authority.budget_store()));
    Ok(kernel)
}

#[test]
fn kernel_restart_releases_expired_approval_custody_from_original_history() -> AnchoredTestResult {
    for phase in [
        GovernedApprovalClaimPhase::NoncePreflight,
        GovernedApprovalClaimPhase::Dispatch,
    ] {
        let fixture = fixture();
        let source = Source::new(&fixture, true)?;
        let binding = activate(&fixture, &source)?;
        let (operation, lease, mut credential) =
            setup_for_phase(&fixture, "kernel-recovery", phase)?;
        let expires = now_ms() / 1000 + 60;
        credential.expires_at_unix_secs = expires;
        let mut intent =
            serde_json::to_value(candidate(&operation, &binding, "owned", credential)?)?;
        intent["phase"] = serde_json::to_value(phase)?;
        let intent = serde_json::from_value(intent)?;
        let port: &dyn AdmissionOperationStore = &fixture.store;
        let (operation, reference) =
            port.claim_governed_approval(&operation, &lease, &intent, now_ms())?;
        drop(source);
        let Fixture {
            _temp,
            database,
            lock_root,
            authority,
            store,
            ..
        } = fixture;
        drop(store);
        drop(authority);
        let _clock =
            chio_kernel::scope_fixed_runtime_for_current_thread(expires + 1, std::iter::empty());
        let now = (expires + 1) * 1000;
        let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
        let fixture = Fixture {
            store: authority.admission_operation_store(),
            fence: authority.mutation_fence(),
            authority,
            _temp,
            database,
            lock_root,
        };
        let kernel = kernel(&fixture)?;
        assert_eq!(kernel.reconcile_durable_admission_startup()?, 1);
        assert_eq!(kernel.reconcile_recoverable_admissions()?, 0);
        let (operation, history) = fixture
            .store
            .load_governed_approval_claim_history(
                operation.binding().operation_id(),
                &fixture.fence,
                now,
            )?
            .ok_or("history missing")?;
        assert_eq!(
            operation.state(),
            AdmissionOperationState::CompensatedBeforeDispatch
        );
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].reference, reference);
        assert_eq!(history[0].intent, intent);
        assert_eq!(
            history[0].disposition,
            GovernedApprovalClaimDisposition::ReleasedBeforeDispatch
        );
    }
    Ok(())
}
