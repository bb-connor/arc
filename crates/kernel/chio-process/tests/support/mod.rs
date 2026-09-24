#![allow(dead_code)]

pub mod supplemental;

use std::path::Path;
use std::sync::Arc;

use chio_core_types::capability::attenuation::{
    compute_attenuation_witness, delegate, scope_hash, AttenuationProof,
};
use chio_core_types::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core_types::capability::token::{
    CapabilityToken, CapabilityTokenAttenuationBody, CapabilityTokenBody,
};
use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_core_types::ScopeAttenuation;
use chio_kernel::admission_operation::DurableAdmissionMode;
use chio_kernel::{ChioKernel, KernelConfig, ToolServerConnection};
use chio_process::{ProcessLimits, ProcessRuntime};
use chio_store_sqlite::{SqliteAuthorityStore, SqliteReceiptStore};

pub type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

// Fixed test credentials only. Never used by a serving product.
pub fn issuer() -> Keypair {
    Keypair::from_seed(&[31; 32])
}
pub fn parent_key() -> Keypair {
    Keypair::from_seed(&[32; 32])
}

pub fn private_dir(path: &Path) -> Result {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub fn config() -> KernelConfig {
    KernelConfig {
        keypair: issuer(),
        ca_public_keys: Vec::new(),
        max_delegation_depth: 8,
        policy_hash: sha256_hex(b"process-test-policy"),
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
    }
}

pub fn kernel(path: &Path, server: Box<dyn ToolServerConnection>) -> Result<Arc<ChioKernel>> {
    kernel_with_payment(path, server, false)
}

pub fn kernel_with_payment(
    path: &Path,
    server: Box<dyn ToolServerConnection>,
    payment: bool,
) -> Result<Arc<ChioKernel>> {
    kernel_with_artifacts(path, server, payment, false, false)
}

pub fn kernel_with_artifacts(
    path: &Path,
    server: Box<dyn ToolServerConnection>,
    payment: bool,
    nonce: bool,
    supplemental: bool,
) -> Result<Arc<ChioKernel>> {
    private_dir(path)?;
    let locks = path.join("locks");
    private_dir(&locks)?;
    let database = path.join("authority.db");
    if !database.exists() {
        SqliteAuthorityStore::provision(&database, &locks)?;
    }
    let authority = SqliteAuthorityStore::open_serving(&database, &locks)?;
    let mut kernel = ChioKernel::new(config());
    kernel.set_capability_trust_root(
        issuer().public_key(),
        scope_hash(&scope(&["append", "read"]))?,
    );
    let receipts = SqliteReceiptStore::open(path.join("receipts.db"))?;
    // Match the production host's startup barrier. A reopened writer verifies
    // its persisted head asynchronously and must stay closed until that ends.
    receipts.wait_for_writer_ready(std::time::Duration::from_secs(30))?;
    kernel.set_receipt_store(Box::new(receipts))?;
    kernel.set_revocation_store(Box::new(authority.revocation_store()));
    kernel.set_budget_store(Box::new(authority.budget_store()));
    kernel.set_durable_admission_store(
        Arc::new(authority.admission_operation_store()),
        Arc::new(authority.tool_outcome_store()),
        authority.mutation_fence(),
    )?;
    kernel.configure_durable_admission(DurableAdmissionMode::All, false)?;
    kernel.set_governed_approval_replay_store(Box::new(
        chio_kernel::InMemoryGovernedApprovalReplayStore::new(64),
    ));
    if nonce {
        let config = chio_kernel::execution_nonce::ExecutionNonceConfig {
            nonce_ttl_secs: 300,
            nonce_store_capacity: 64,
            require_nonce: true,
        };
        kernel.set_execution_nonce_store(
            config.clone(),
            Box::new(
                chio_kernel::execution_nonce::InMemoryExecutionNonceStore::from_config(&config),
            ),
        );
    }
    if payment {
        kernel.set_payment_adapter(Box::new(
            chio_store_sqlite::SqliteFindingOperatorPaymentAdapter::open(path.join("payments.db"))?,
        ));
    }
    if supplemental {
        kernel.set_supplemental_quota_verifier(
            Arc::new(supplemental::Verifier),
            chio_kernel::supplemental_quota::SupplementalQuotaVerifierBinding {
                verifier_identity: "process-test-signed-supplemental".into(),
                configuration_digest: sha256_hex(b"process-test-supplemental-v1"),
            },
        )?;
    }
    kernel.register_tool_server(server);
    kernel.reconcile_durable_admission_startup()?;
    Ok(Arc::new(kernel))
}

pub fn scope(tools: &[&str]) -> ChioScope {
    ChioScope {
        grants: tools
            .iter()
            .map(|tool| ToolGrant {
                server_id: "tools".to_owned(),
                tool_name: (*tool).to_owned(),
                operations: vec![Operation::Invoke, Operation::Delegate],
                constraints: Vec::new(),
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            })
            .collect(),
        ..Default::default()
    }
}

pub fn root(
    runtime: &ProcessRuntime,
    kernel: &ChioKernel,
    max_calls: u32,
) -> Result<CapabilityToken> {
    let capability =
        kernel.issue_capability(&parent_key().public_key(), scope(&["append", "read"]), 3600)?;
    runtime.create_root("root", &capability, limits(max_calls))?;
    Ok(capability)
}

pub fn limits(max_calls: u32) -> ProcessLimits {
    ProcessLimits {
        max_processes: 100,
        max_depth: 8,
        max_calls,
        state: Default::default(),
    }
}

pub fn child(
    parent: &CapabilityToken,
    parent_key: &Keypair,
    id: &str,
    child_key: &Keypair,
    scope: ChioScope,
) -> Result<CapabilityToken> {
    let receipt = delegate(
        parent,
        &scope,
        parent_key,
        &child_key.public_key(),
        ScopeAttenuation {
            budget_share_bps: Some(parent.budget_share_bps.unwrap_or(10_000).min(1_000)),
            ..Default::default()
        },
        parent.issued_at,
        [11; 16],
    )?;
    Ok(CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body: CapabilityTokenBody {
                id: id.to_owned(),
                issuer: issuer().public_key(),
                subject: child_key.public_key(),
                issued_at: parent.issued_at,
                expires_at: parent.expires_at,
                delegation_chain: receipt.complete_chain(),
                aggregate_invocation_budget: parent.aggregate_invocation_budget.clone(),
                scope: scope.clone(),
            },
            caveats: Vec::new(),
            scope_attenuations: Vec::new(),
            attenuation_proof: AttenuationProof {
                parent_scope_hash: scope_hash(&parent.scope)?,
                child_scope_hash: scope_hash(&scope)?,
                normalized_subset_proof: compute_attenuation_witness(&parent.scope, &scope)?,
            },
            budget_share_bps: Some(parent.budget_share_bps.unwrap_or(10_000).min(1_000)),
        },
        &issuer(),
    )?)
}
