use std::error::Error;
use std::sync::Arc;

use chio_core::crypto::{sha256_hex, Keypair};
use chio_kernel::admission_operation::{
    AdmissionOperationStore, AdmissionReplayKey, DurableAdmissionMode,
};
use chio_kernel::recovery::RecoveryOriginalRequestError;
use chio_kernel::{
    ChioKernel, KernelConfig, ToolCallRequest, DEFAULT_CHECKPOINT_BATCH_SIZE,
    DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_security_types::recovery::{AuthorityDomainId, RecoveryScopeV1, RecoveryTenantId};
use chio_store_sqlite::SqliteAuthorityStore;

fn kernel() -> ChioKernel {
    ChioKernel::new_with_clock(
        KernelConfig {
            keypair: Keypair::from_seed(&[37; 32]),
            ca_public_keys: Vec::new(),
            max_delegation_depth: 5,
            policy_hash: sha256_hex(b"original-scope-test-policy"),
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
        chio_test_support::clock::clock(),
    )
}

fn vector() -> Result<(RecoveryScopeV1, ToolCallRequest), Box<dyn Error>> {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../spec/vectors/recovery/v1/authority-positive.json"
    ))?;
    let scope = serde_json::from_value(fixture["action"]["scope"].clone())?;
    let mut request = fixture["request"].clone();
    request
        .as_object_mut()
        .ok_or("request fixture must be an object")?
        .remove("declassification_grant")
        .ok_or("request fixture must carry recovery authority")?;
    Ok((scope, serde_json::from_value(request)?))
}

#[test]
fn public_original_scope_uses_the_installed_sqlite_authority_without_admission(
) -> Result<(), Box<dyn Error>> {
    let (mut scope, seed) = vector()?;
    let mut kernel = kernel();
    kernel.configure_durable_admission(DurableAdmissionMode::All, false)?;
    assert!(matches!(
        kernel.recovery_process_original_request_scope(&scope, &seed),
        Err(RecoveryOriginalRequestError::Refused)
    ));

    let directory = tempfile::tempdir()?;
    let lock_root = directory.path().join("locks");
    std::fs::create_dir(&lock_root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        std::fs::set_permissions(&lock_root, std::fs::Permissions::from_mode(0o700))?;
    }
    let database = directory.path().join("authority.db");
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let authority = SqliteAuthorityStore::open_serving_with_clock(
        &database,
        &lock_root,
        chio_test_support::clock::clock(),
    )?;
    let operations = Arc::new(authority.admission_operation_store());
    kernel.set_durable_admission_store(
        operations.clone(),
        Arc::new(authority.tool_outcome_store()),
        authority.mutation_fence(),
    )?;
    let installed = kernel
        .durable_admission_store_uuid()
        .ok_or("installed authority is absent")?;
    scope.authority_domain = AuthorityDomainId::new(installed)?;
    let original = kernel.recovery_process_original_request_scope(&scope, &seed)?;
    assert_eq!(original.request_id().as_str(), seed.request_id);
    assert!(original.matches(&scope, &seed));
    assert!(original.clone().matches(&scope, &seed));

    let mut tenant_scope = scope.clone();
    tenant_scope.tenant_id = RecoveryTenantId::new("tenant:other")?;
    let tenant_original = kernel.recovery_process_original_request_scope(&tenant_scope, &seed)?;
    assert_eq!(original.namespace(), tenant_original.namespace());
    assert!(tenant_original.matches(&tenant_scope, &seed));
    assert!(!original.matches(&tenant_scope, &seed));

    let mut changed_seed = seed.clone();
    changed_seed.arguments = serde_json::json!({"changed": true});
    assert!(!original.matches(&scope, &changed_seed));
    let replay_key = AdmissionReplayKey {
        request_namespace_digest: original.namespace().clone(),
        request_id: original.request_id().clone(),
    };
    assert_eq!(operations.load_by_replay_key(&replay_key)?, None);

    let mut foreign = scope.clone();
    foreign.authority_domain = AuthorityDomainId::new("authority:foreign")?;
    assert!(matches!(
        kernel.recovery_process_original_request_scope(&foreign, &seed),
        Err(RecoveryOriginalRequestError::Refused)
    ));
    for mode in [
        DurableAdmissionMode::Off,
        DurableAdmissionMode::Monetary,
        DurableAdmissionMode::SideEffecting,
    ] {
        kernel.configure_durable_admission(mode, mode == DurableAdmissionMode::Off)?;
        assert!(
            matches!(
                kernel.recovery_process_original_request_scope(&scope, &seed),
                Err(RecoveryOriginalRequestError::Refused)
            ),
            "{mode:?}"
        );
    }
    assert_eq!(operations.load_by_replay_key(&replay_key)?, None);
    Ok(())
}
