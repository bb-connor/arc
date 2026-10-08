//! Real Process source entry. It cannot fabricate a funding or capture role.
use super::*;
use crate::{ProcessLimits, ProcessRuntime};
use chio_core_types::capability::attenuation::scope_hash;
use chio_core_types::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_kernel::admission_operation::DurableAdmissionMode;
use chio_kernel::{ChioKernel, KernelConfig};
use chio_store_sqlite::{SqliteAuthorityStore, SqliteReceiptStore};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn admitted_call_prepares_its_actual_process_return_source() -> TestResult {
    let directory = tempfile::tempdir()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    let locks = directory.path().join("locks");
    std::fs::create_dir(&locks)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&locks, std::fs::Permissions::from_mode(0o700))?;
    }
    let native_path = directory.path().join("authority.db");
    SqliteAuthorityStore::provision(&native_path, &locks)?;
    let authority = SqliteAuthorityStore::open_serving(&native_path, &locks)?;
    let issuer = Keypair::from_seed(&[29; 32]);
    let mut kernel = ChioKernel::new(KernelConfig {
        keypair: issuer.clone(),
        ca_public_keys: Vec::new(),
        max_delegation_depth: 8,
        policy_hash: sha256_hex(b"Process original return source test policy"),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: 30,
        max_stream_total_bytes: 1_048_576,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: false,
        allow_ephemeral_revocation_store: false,
        checkpoint_batch_size: 0,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: Default::default(),
    });
    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "tools".into(),
            tool_name: "append".into(),
            operations: vec![Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..Default::default()
    };
    kernel.set_capability_trust_root(issuer.public_key(), scope_hash(&scope)?);
    let receipts = SqliteReceiptStore::open(directory.path().join("receipts.db"))?;
    receipts.wait_for_writer_ready(std::time::Duration::from_secs(30))?;
    kernel.set_receipt_store(Box::new(receipts))?;
    kernel.set_revocation_store(Box::new(authority.revocation_store()));
    kernel.set_budget_store(Box::new(authority.budget_store()));
    kernel.set_durable_admission_store(
        std::sync::Arc::new(authority.admission_operation_store()),
        std::sync::Arc::new(authority.tool_outcome_store()),
        authority.mutation_fence(),
    )?;
    kernel.configure_durable_admission(DurableAdmissionMode::All, false)?;
    kernel.reconcile_durable_admission_startup()?;
    // This source test enters no Kernel dispatch and grants no native funding.
    let kernel = std::sync::Arc::new(kernel);
    let runtime = ProcessRuntime::open(directory.path().join("process.db"), kernel.clone())?;
    let capability =
        kernel.issue_capability(&Keypair::from_seed(&[30; 32]).public_key(), scope, 3600)?;
    runtime.create_root(
        "root",
        &capability,
        ProcessLimits {
            max_processes: 2,
            max_depth: 1,
            max_calls: 2,
            state: Default::default(),
        },
    )?;
    let request = runtime.tool_request(
        "root",
        "publish",
        "tools",
        "append",
        serde_json::json!({"value": 1}),
    )?;
    let binding = runtime.derive_call_binding("root", "publish", &request, false)?;
    runtime.with_store(|store| store.admit("root", "publish", &request, &binding.binding_hash))?;
    let result = runtime.with_store(|store| {
        store.prepare_native_return_source(
            &runtime, "root", "publish", &request, &binding, false, None,
        )
    });
    assert!(
        result.is_ok(),
        "the actual admitted source was not prepared: {result:?}"
    );
    let source = result?;
    assert_eq!(source.data().process_id, "root");
    assert_eq!(source.data().operation_key, "publish");
    assert_eq!(source.data().attempt, 1);
    assert_eq!(source.data().call_binding_digest, binding.binding_hash);
    assert_eq!(runtime.process("root")?.tree_calls, 1);
    assert_eq!(source.data().journal_namespace, runtime.namespace);
    assert!(source.canonical_bytes().len() <= MAX_SOURCE_BYTES);
    Ok(())
}
