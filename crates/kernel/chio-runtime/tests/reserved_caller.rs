#![cfg(unix)]

use chio_core_types::capability::governance::GovernedTransactionIntent;
use chio_core_types::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core_types::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_kernel::admission_operation::runtime_participant::{
    RuntimeParticipantAuthorityBindingV1, RuntimeParticipantClaimHistoryV1,
    RuntimeParticipantDisposition,
};
use chio_kernel::admission_operation::{AdmissionIdentifier, AdmissionOperationStore};
use chio_kernel::execution_nonce::{ExecutionNonceConfig, InMemoryExecutionNonceStore};
use chio_kernel::{
    BlockingToolServerAdapter, BlockingToolServerConnection, ChioKernel, KernelConfig, KernelError,
    RuntimeAdmissionContext, RuntimeAdmissionHook, ToolCallRequest, Verdict,
};
use chio_runtime::{
    ChioRuntimeAdmissionHook, RuntimeAdmissionBundle, RuntimeAdmissionProfile,
    RuntimeRequestBinding, SqliteRuntimeOrchestrationStore, CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA,
    CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA,
};
use chio_runtime_core::runtime_admission_bundle_sha256;
use chio_store_sqlite::SqliteAuthorityStore;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const NOW: u64 = 1_800_000_001_000;

struct Tool(Arc<AtomicUsize>);

impl BlockingToolServerConnection for Tool {
    fn server_id(&self) -> &str {
        "vendor-ledger"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["read_account".into()]
    }

    fn invoke_blocking(
        &self,
        _name: &str,
        _arguments: serde_json::Value,
    ) -> Result<serde_json::Value, KernelError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"closed": true}))
    }
}

struct Fixture {
    directory: tempfile::TempDir,
    authority: SqliteAuthorityStore,
    binding: RuntimeParticipantAuthorityBindingV1,
    request: ToolCallRequest,
    calls: Arc<AtomicUsize>,
}

fn profile() -> RuntimeAdmissionProfile {
    RuntimeAdmissionProfile {
        schema: CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA.into(),
        profile_id: "reserved-facade-profile".into(),
        local_kernel_id: "kernel.vendor-b".into(),
        verifier_id: "did:chio:verifier".into(),
        issued_at_unix_ms: NOW - 1000,
        expires_at_unix_ms: NOW + 3_600_000,
    }
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let capability = CapabilityToken::sign(
            CapabilityTokenBody {
                id: "cap-reserved-facade".into(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: ChioScope {
                    grants: vec![ToolGrant {
                        server_id: "vendor-ledger".into(),
                        tool_name: "read_account".into(),
                        operations: vec![Operation::Invoke],
                        constraints: Vec::new(),
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    }],
                    resource_grants: Vec::new(),
                    prompt_grants: Vec::new(),
                },
                issued_at: NOW / 1000 - 1,
                expires_at: NOW / 1000 + 3600,
                delegation_chain: Vec::new(),
                aggregate_invocation_budget: None,
            },
            &issuer,
        )?;
        let mut request = ToolCallRequest {
            request_id: "req-reserved-facade".into(),
            capability: capability.clone(),
            tool_name: "read_account".into(),
            server_id: "vendor-ledger".into(),
            agent_id: capability.subject.to_hex(),
            arguments: serde_json::json!({"account": "7"}),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
            declassification_grant: None,
        };
        let bundle = RuntimeAdmissionBundle {
            schema: CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA.into(),
            admission_id: "adm-reserved-facade".into(),
            binding: RuntimeRequestBinding::from_tool_call_request(&request, "kernel.vendor-b")?,
            workflow_id: "workflow-reserved-facade".into(),
            workflow_grant_id: "grant-reserved-facade".into(),
            step_index: 1,
            destructive: false,
            lease_id: None,
            governance_receipt_id: None,
            trust_bundle_sha256: "b".repeat(64),
            verification_context_sha256: "c".repeat(64),
        };
        request.governed_intent = Some(GovernedTransactionIntent {
            id: "intent-reserved-facade".into(),
            server_id: request.server_id.clone(),
            tool_name: request.tool_name.clone(),
            purpose: "read governed account".into(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: Some(serde_json::json!({"chioAdmission": {
                "admissionId": bundle.admission_id,
                "bundleSha256": runtime_admission_bundle_sha256(&bundle)?
            }})),
            body: Default::default(),
        });
        let directory = tempfile::tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let database = directory.path().join("authority.sqlite3");
        let locks = directory.path().join("locks");
        std::fs::DirBuilder::new().mode(0o700).create(&locks)?;
        SqliteAuthorityStore::provision(&database, &locks)?;
        let authority = SqliteAuthorityStore::open_serving_with_clock(
            &database,
            &locks,
            chio_test_support::clock::clock(),
        )?;
        let source =
            SqliteRuntimeOrchestrationStore::open(directory.path().join("runtime.sqlite3"))?;
        source.insert_bundle(bundle.clone())?;
        let store = authority.admission_operation_store();
        let fence = authority.mutation_fence();
        let source_id = AdmissionIdentifier::try_new("source_id", "facade-source")?;
        let runtime_id = AdmissionIdentifier::try_new("runtime_id", "facade-runtime")?;
        let expected =
            store.expect_runtime_replay_source(&source_id, &runtime_id, &source, &fence, NOW)?;
        store.import_runtime_replay_source(
            &runtime_id,
            expected.expectation_id(),
            &source,
            &fence,
            NOW,
        )?;
        let binding = RuntimeParticipantAuthorityBindingV1::new(
            runtime_id,
            expected.expectation_id().clone(),
        );
        store.activate_runtime_replay_source(&binding, &source, &fence, NOW)?;
        Ok(Self {
            directory,
            authority,
            binding,
            request,
            calls: Arc::new(AtomicUsize::new(0)),
        })
    }

    fn hook(
        &self,
        binding: RuntimeParticipantAuthorityBindingV1,
    ) -> TestResult<ChioRuntimeAdmissionHook<SqliteRuntimeOrchestrationStore>> {
        Ok(ChioRuntimeAdmissionHook::new(
            profile(),
            SqliteRuntimeOrchestrationStore::open(self.directory.path().join("runtime.sqlite3"))?,
        )
        .with_operation_owned_runtime_replay(binding))
    }

    fn kernel(&self) -> TestResult<ChioKernel> {
        let mut kernel = ChioKernel::new_with_clock(
            KernelConfig {
                keypair: Keypair::generate(),
                ca_public_keys: vec![self.request.capability.issuer.clone()],
                max_delegation_depth: 5,
                policy_hash: sha256_hex(b"reserved-facade-test"),
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
            },
            chio_test_support::clock::clock(),
        );
        kernel.set_durable_admission_store(
            Arc::new(self.authority.admission_operation_store()),
            Arc::new(self.authority.tool_outcome_store()),
            self.authority.mutation_fence(),
        )?;
        kernel.set_budget_store_handle(Arc::new(self.authority.budget_store()));
        kernel.set_federation_local_kernel_id("kernel.vendor-b");
        kernel.set_runtime_admission_hook(Arc::new(self.hook(self.binding.clone())?));
        kernel.register_tool_server(Box::new(BlockingToolServerAdapter::new(Arc::new(Tool(
            Arc::clone(&self.calls),
        )))?));
        let config = ExecutionNonceConfig {
            nonce_ttl_secs: 30,
            nonce_store_capacity: 64,
            require_nonce: true,
        };
        kernel.set_execution_nonce_store(
            config.clone(),
            Box::new(InMemoryExecutionNonceStore::from_config(&config)),
        );
        Ok(kernel)
    }

    fn history(&self) -> TestResult<Vec<RuntimeParticipantClaimHistoryV1>> {
        let store = self.authority.admission_operation_store();
        let fence = self.authority.mutation_fence();
        let selector = AdmissionIdentifier::try_new("request", &self.request.request_id)?;
        let (operation, _) = store
            .load_unambiguous_retained_tool_request(&selector, &fence, NOW)?
            .ok_or("reserved operation missing")?;
        Ok(store
            .load_runtime_participant_history(operation.binding().operation_id(), &fence, NOW)?
            .ok_or("reserved history missing")?
            .1)
    }

    fn context<'a>(&self, request: &'a ToolCallRequest) -> RuntimeAdmissionContext<'a> {
        RuntimeAdmissionContext {
            request,
            extra_metadata: None,
            now_unix_secs: NOW / 1000,
            now_unix_ms: NOW,
            matched_grant_index: Some(0),
            local_kernel_id: "kernel.vendor-b".into(),
        }
    }
}

#[test]
fn public_facade_revalidates_reserved_caller_without_replacing_custody() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(NOW / 1000);
    let fixture = Fixture::new()?;
    let kernel = fixture.kernel()?;
    let reserved = kernel.reserve_caller_execution_blocking(&fixture.request)?;
    assert_eq!(
        reserved.verdict,
        Verdict::Allow,
        "{:?} {:?}",
        reserved.reason,
        reserved.receipt.metadata
    );
    let nonce = reserved
        .execution_nonce
        .ok_or("reserved caller nonce missing")?;
    let before = fixture.history()?;
    assert_eq!(before.len(), 2);
    assert_eq!(
        before[0].disposition,
        RuntimeParticipantDisposition::ReleasedBeforeDispatch
    );
    assert_eq!(
        before[1].disposition,
        RuntimeParticipantDisposition::ReservedBeforeDispatch
    );
    let mut retry = fixture.request.clone();
    retry.execution_nonce = Some(nonce.as_ref().clone());
    let replay = kernel.reserve_caller_execution_blocking(&retry)?;
    assert_eq!(
        replay.verdict,
        Verdict::Allow,
        "{:?} {:?}",
        replay.reason,
        replay.receipt.metadata
    );
    assert_eq!(replay.execution_nonce.as_deref(), Some(nonce.as_ref()));
    assert_eq!(
        fixture.history()?,
        before,
        "retry must retain the exact existing episode and disposition"
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn public_facade_reserved_revalidation_preserves_binding_and_source_refusals() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(NOW / 1000);
    let fixture = Fixture::new()?;
    let kernel = fixture.kernel()?;
    let reserved = kernel.reserve_caller_execution_blocking(&fixture.request)?;
    assert_eq!(
        reserved.verdict,
        Verdict::Allow,
        "{:?} {:?}",
        reserved.reason,
        reserved.receipt.metadata
    );
    let before = fixture.history()?;
    let claim = before.last().ok_or("dispatch claim missing")?;
    let source = fixture
        .authority
        .admission_operation_store()
        .load_runtime_participant_activation(
            &fixture.binding,
            &fixture.authority.mutation_fence(),
            NOW,
        )?;
    let wrong_binding = RuntimeParticipantAuthorityBindingV1::new(
        fixture.binding.runtime_authority_id().clone(),
        AdmissionIdentifier::try_new("expectation_id", "different-expectation")?,
    );
    let error = match fixture.hook(wrong_binding)?.revalidate_reserved_operation(
        &fixture.context(&fixture.request),
        &source,
        claim,
    ) {
        Ok(decision) => return Err(format!("changed binding accepted: {decision:?}").into()),
        Err(error) => error,
    };
    assert!(
        matches!(&error, KernelError::DurableAdmission(reason) if reason == "native runtime artifacts differ from the physically owned plan"),
        "{error:?}"
    );
    let other =
        SqliteRuntimeOrchestrationStore::open(fixture.directory.path().join("other.sqlite3"))?;
    other.seal_legacy_replay_source(&chio_runtime::RuntimeReplaySourceBinding::new(
        source.source_id(),
        source.runtime_authority_id(),
        source.destination_authority_id(),
    )?)?;
    let hook = ChioRuntimeAdmissionHook::new(profile(), other)
        .with_operation_owned_runtime_replay(fixture.binding.clone());
    let error = match hook.revalidate_reserved_operation(
        &fixture.context(&fixture.request),
        &source,
        claim,
    ) {
        Ok(decision) => return Err(format!("different source accepted: {decision:?}").into()),
        Err(error) => error,
    };
    let expected =
        match chio_runtime::ChioRuntimeAdmissionStore::verify_operation_owned_replay_source(
            &SqliteRuntimeOrchestrationStore::open(fixture.directory.path().join("other.sqlite3"))?,
            &source,
        ) {
            Ok(()) => return Err("different source unexpectedly verified".into()),
            Err(error) => {
                assert_eq!(error.code(), "runtime_replay_source_invalid");
                error.to_string()
            }
        };
    assert!(
        matches!(&error, KernelError::DurableAdmission(reason) if reason == &expected),
        "{error:?}"
    );
    assert_eq!(fixture.history()?, before);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn public_facade_reserved_revalidation_rejects_changed_prepared_plan() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(NOW / 1000);
    let fixture = Fixture::new()?;
    let kernel = fixture.kernel()?;
    let reserved = kernel.reserve_caller_execution_blocking(&fixture.request)?;
    assert_eq!(
        reserved.verdict,
        Verdict::Allow,
        "{:?} {:?}",
        reserved.reason,
        reserved.receipt.metadata
    );
    let before = fixture.history()?;
    let claim = before.last().ok_or("dispatch claim missing")?;
    let source = fixture
        .authority
        .admission_operation_store()
        .load_runtime_participant_activation(
            &fixture.binding,
            &fixture.authority.mutation_fence(),
            NOW,
        )?;
    let mut changed_profile = profile();
    changed_profile.profile_id = "different-prepared-profile".into();
    let hook = ChioRuntimeAdmissionHook::new(
        changed_profile,
        SqliteRuntimeOrchestrationStore::open(fixture.directory.path().join("runtime.sqlite3"))?,
    )
    .with_operation_owned_runtime_replay(fixture.binding.clone());
    let error = match hook.revalidate_reserved_operation(
        &fixture.context(&fixture.request),
        &source,
        claim,
    ) {
        Ok(decision) => return Err(format!("changed plan accepted: {decision:?}").into()),
        Err(error) => error,
    };
    assert!(
        matches!(&error, KernelError::DurableAdmission(reason) if reason == "native runtime artifacts differ from the physically owned plan"),
        "{error:?}"
    );
    assert_eq!(fixture.history()?, before);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    Ok(())
}
