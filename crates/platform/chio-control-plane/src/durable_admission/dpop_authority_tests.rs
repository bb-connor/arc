use super::*;
use chio_kernel::admission_operation::{
    AdmissionIdentifier, AdmissionOperationStoreError, AdmissionRecoveryError,
};
use chio_kernel::dpop::authority::DpopReplayAuthority;
use chio_kernel::{
    DpopConfig, KernelConfig, KernelError, DEFAULT_CHECKPOINT_BATCH_SIZE,
    DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_security_types::clock::{Clock, FixedClock};
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn unattached_kernel(runtime: &DurableAdmissionRuntime, clock: Arc<dyn Clock>) -> ChioKernel {
    ChioKernel::new_with_clock(
        KernelConfig {
            keypair: runtime.kernel_keypair(),
            ca_public_keys: vec![runtime.kernel_keypair().public_key()],
            max_delegation_depth: 5,
            policy_hash: chio_core::crypto::sha256_hex(b"dpop-attach-test-policy"),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: true,
            allow_ephemeral_revocation_store: true,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
            deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        },
        clock,
    )
}

#[test]
fn attach_refuses_mismatched_dpop_descriptor_without_replacing_activation() -> TestResult {
    let directory = private_tempdir()?;
    let clock: Arc<dyn Clock> = Arc::new(FixedClock::new(1_800_000_000));
    let runtime = DurableAdmissionRuntime::open_with_clock(
        &directory.path().join("authority.db"),
        clock.clone(),
    )?;
    let authority = runtime
        .local_authority_store()
        .ok_or("missing local authority")?;
    let authority_id = AdmissionIdentifier::try_new("dpop_authority", "attach-dpop")?;
    let domain = crate::initialize_local_dpop_authority(
        &authority,
        &authority_id,
        &DpopConfig::default(),
        clock.clone(),
    )?;
    let operations = authority.admission_operation_store();
    let fence = authority.mutation_fence();
    let now = clock.read()?.unix_millis().get();
    let active = operations
        .load_dpop_replay_migration(&authority_id, &fence, now)?
        .ok_or("missing activated record")?;
    assert!(active.is_active());
    assert_eq!(active.authority(), Some(&domain));

    let policy_refusal = "DPoP authority is not activated with the exact configured policy";
    for (field, replacement, expected_reason) in [
        (
            "destination_store_uuid",
            json!("018f9878-7047-7abc-8c98-120dc65700ea"),
            policy_refusal,
        ),
        (
            "expectation_id",
            json!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            policy_refusal,
        ),
        (
            "dpop_authority_id",
            json!("unregistered-attach-dpop"),
            "DPoP authority is not registered",
        ),
        ("proof_ttl_secs", json!(301), policy_refusal),
        ("max_clock_skew_secs", json!(31), policy_refusal),
    ] {
        let mut configured = serde_json::to_value(&domain)?;
        configured[field] = replacement;
        let configured: DpopReplayAuthority = serde_json::from_value(configured)?;
        assert_ne!(configured, domain, "{field}");
        let mut kernel = unattached_kernel(&runtime, clock.clone());
        let error = runtime
            .attach(&mut kernel, Some(&configured))
            .err()
            .ok_or_else(|| format!("attach accepted mismatched {field}"))?;
        let CliError::Kernel(KernelError::AdmissionRecovery(error)) = error else {
            return Err(format!("{field}: unexpected attach error: {error}").into());
        };
        let AdmissionRecoveryError::Store(error) = *error else {
            return Err(format!("{field}: unexpected recovery error: {error}").into());
        };
        assert_eq!(
            error,
            AdmissionOperationStoreError::Invariant(expected_reason.into()),
            "{field}"
        );
        assert_eq!(kernel.operation_owned_dpop_authority(), None, "{field}");
        assert_eq!(
            operations.load_dpop_replay_migration(&authority_id, &fence, now)?,
            Some(active.clone()),
            "{field}: startup refusal changed the persisted activation"
        );
        if configured.dpop_authority_id() != &authority_id {
            assert_eq!(
                operations.load_dpop_replay_migration(
                    configured.dpop_authority_id(),
                    &fence,
                    now,
                )?,
                None,
                "{field}: startup refusal registered another authority"
            );
        }
    }

    let mut kernel = unattached_kernel(&runtime, clock);
    runtime.attach(&mut kernel, Some(&domain))?;
    assert_eq!(kernel.operation_owned_dpop_authority(), Some(&domain));
    assert_eq!(
        operations.load_dpop_replay_migration(&authority_id, &fence, now)?,
        Some(active)
    );
    Ok(())
}
