//! Live kernel admission against a physically sealed runtime source and a
//! separately qualified SQLite authority. No legacy replay adapter is used.

use super::*;
use chio_kernel::admission_operation::runtime_participant::{
    RuntimeParticipantAuthorityBindingV1, RuntimeParticipantDisposition,
};
use chio_kernel::admission_operation::AdmissionIdentifier;
use chio_kernel::{ChioKernel, KernelConfig, Verdict};
use chio_store_sqlite::SqliteAuthorityStore;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const NOW: u64 = 1_800_000_001_000;

#[path = "operation_owned/faults.rs"]
mod faults;
#[path = "operation_owned/grant_fallback.rs"]
mod grant_fallback;
#[path = "operation_owned/nonce.rs"]
mod nonce;

#[path = "operation_owned/combined.rs"]
mod combined;

struct Fixture {
    _directory: FixtureDirectory,
    authority: SqliteAuthorityStore,
    source: SqliteRuntimeOrchestrationStore,
    binding: RuntimeParticipantAuthorityBindingV1,
    request: ToolCallRequest,
    invocations: Arc<AtomicU64>,
}

// A crash worker borrows its parent's private directory. Only the parent owns
// cleanup, so abrupt termination cannot remove the evidence under examination.
enum FixtureDirectory {
    Owned(tempfile::TempDir),
    Existing(std::path::PathBuf),
}

impl FixtureDirectory {
    fn path(&self) -> &std::path::Path {
        match self {
            Self::Owned(directory) => directory.path(),
            Self::Existing(path) => path,
        }
    }
}

struct CountingTool {
    invocations: Arc<AtomicU64>,
    read_only: bool,
}

#[async_trait::async_trait]
impl chio_kernel::ToolServerConnection for CountingTool {
    fn server_id(&self) -> &str {
        "vendor-ledger"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["close_account".into()]
    }
    fn tool_is_read_only(&self, _tool_name: &str) -> bool {
        self.read_only
    }
    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<serde_json::Value, chio_kernel::KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"closed": true}))
    }
}

impl Fixture {
    fn new(activate: bool) -> TestResult<Self> {
        Self::with_request(activate, |source| {
            let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
            let mut admission_bundle = bundle();
            admission_bundle.binding.origin_kernel_id = None;
            admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
            let mut request = treaty_runtime_request(
                args,
                runtime_admission_bundle_sha256(&admission_bundle)?,
                serde_json::json!({}),
            )?;
            request.federated_origin_kernel_id = None;
            request
                .governed_intent
                .as_mut()
                .and_then(|intent| intent.context.as_mut())
                .and_then(serde_json::Value::as_object_mut)
                .ok_or("request context")?
                .remove("chioTreaty");
            source.insert_bundle(admission_bundle)?;
            Ok(request)
        })
    }

    fn with_request(
        activate: bool,
        prepare: impl FnOnce(&SqliteRuntimeOrchestrationStore) -> TestResult<ToolCallRequest>,
    ) -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let database = directory.path().join("authority.sqlite3");
        let locks = directory.path().join("locks");
        std::fs::DirBuilder::new().mode(0o700).create(&locks)?;
        SqliteAuthorityStore::provision(&database, &locks)?;
        let authority = SqliteAuthorityStore::open_serving(&database, &locks)?;
        let source =
            SqliteRuntimeOrchestrationStore::open(directory.path().join("runtime.sqlite3"))?;
        let request = prepare(&source)?;
        let store = authority.admission_operation_store();
        let fence = authority.mutation_fence();
        let source_id = AdmissionIdentifier::try_new("source_id", "live-runtime-source")?;
        let runtime_id = AdmissionIdentifier::try_new("runtime_id", "live-runtime-authority")?;
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
        if activate {
            let active = store.activate_runtime_replay_source(&binding, &source, &fence, NOW)?;
            assert!(active.is_active());
            assert_eq!(active.event_sequence(), 3);
        }
        Ok(Self {
            _directory: FixtureDirectory::Owned(directory),
            authority,
            source,
            binding,
            request,
            invocations: Arc::new(AtomicU64::new(0)),
        })
    }

    fn hook(&self) -> TestResult<ChioRuntimeAdmissionHook<SqliteRuntimeOrchestrationStore>> {
        let (trust, keys, report, policy, weights) = signed_policy_inputs(0.1)?;
        Ok(ChioRuntimeAdmissionHook::new(
            profile(),
            SqliteRuntimeOrchestrationStore::open(self._directory.path().join("runtime.sqlite3"))?,
        )
        .with_runtime_trust_input(trust, keys)
        .with_pheromone_query_report(report)
        .with_runtime_pheromone_policy(policy, weights)
        .with_operation_owned_runtime_replay(self.binding.clone()))
    }

    fn kernel(
        &self,
        hook: impl RuntimeAdmissionHook + 'static,
        durable: bool,
        read_only: bool,
    ) -> TestResult<ChioKernel> {
        self.kernel_with_key(hook, durable, read_only, Keypair::generate())
    }

    fn kernel_with_key(
        &self,
        hook: impl RuntimeAdmissionHook + 'static,
        durable: bool,
        read_only: bool,
        keypair: Keypair,
    ) -> TestResult<ChioKernel> {
        let mut kernel = ChioKernel::new(KernelConfig {
            keypair,
            ca_public_keys: vec![self.request.capability.issuer.clone()],
            max_delegation_depth: 5,
            policy_hash: sha256_hex(b"live-runtime-custody-test"),
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
        if durable {
            kernel.set_durable_admission_store(
                Arc::new(self.authority.admission_operation_store()),
                Arc::new(self.authority.tool_outcome_store()),
                self.authority.mutation_fence(),
            )?;
            kernel.set_budget_store_handle(Arc::new(self.authority.budget_store()));
        }
        kernel.set_federation_local_kernel_id("kernel.vendor-b");
        kernel.set_runtime_admission_hook(Arc::new(hook));
        kernel.register_tool_server(Box::new(CountingTool {
            invocations: self.invocations.clone(),
            read_only,
        }));
        Ok(kernel)
    }
}

#[test]
fn live_owned_runtime_dispatch_retains_claim_and_real_trust_floor() -> TestResult {
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(NOW / 1000, []);
    let fixture = Fixture::new(true)?;
    let kernel = fixture.kernel(fixture.hook()?, true, false)?;
    let response = kernel.evaluate_tool_call_blocking(&fixture.request)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    assert!(response.receipt.verify_signature()?);
    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .ok_or("receipt metadata")?;
    let reference: chio_kernel::admission_operation::runtime_participant::RuntimeParticipantClaimReferenceV1 =
        serde_json::from_value(metadata["chio_runtime"]["operation_owned_replay"]["reference"].clone())?;
    let (operation, history) = fixture
        .authority
        .admission_operation_store()
        .load_runtime_participant_history(
            reference.operation_id(),
            &fixture.authority.mutation_fence(),
            NOW,
        )?
        .ok_or("physical runtime history")?;
    assert!(operation.dispatch_commit().is_some());
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].reference, reference);
    assert_eq!(
        history[0].disposition,
        RuntimeParticipantDisposition::RetainedAfterDispatchCommit
    );
    assert_eq!(history[0].intent.resources().len(), 1);
    assert!(fixture
        .source
        .runtime_trust_floor("did:chio:buyer-verifier", "verifier-key-1")?
        .is_some());
    assert!(metadata["chio_runtime"]
        .get("reserved_destructive_lease_id")
        .is_none());
    assert!(fixture
        .source
        .consume_destructive_lease("lease-live-1", "adm-live-1")
        .is_err());
    assert!(fixture
        .source
        .release_destructive_lease("lease-live-1", "adm-live-1")
        .is_err());
    Ok(())
}

#[test]
fn owned_runtime_denies_inactive_source_and_ephemeral_read_only_fallback() -> TestResult {
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(NOW / 1000, []);
    for (activate, durable, read_only) in [(false, true, false), (true, false, true)] {
        let fixture = Fixture::new(activate)?;
        let kernel = fixture.kernel(fixture.hook()?, durable, read_only)?;
        let response = kernel.evaluate_tool_call_blocking(&fixture.request)?;
        assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
        assert!(fixture
            .source
            .runtime_trust_floor("did:chio:buyer-verifier", "verifier-key-1")?
            .is_none());
    }
    Ok(())
}

#[test]
fn owned_runtime_denies_fixed_clock_override_and_wrong_physical_source() -> TestResult {
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(NOW / 1000, []);
    for wrong_source in [false, true] {
        let fixture = Fixture::new(true)?;
        let hook = if wrong_source {
            let other = SqliteRuntimeOrchestrationStore::open(
                fixture._directory.path().join("other-runtime.sqlite3"),
            )?;
            ChioRuntimeAdmissionHook::new(profile(), other)
                .with_operation_owned_runtime_replay(fixture.binding.clone())
        } else {
            fixture.hook()?.with_fixed_now_unix_ms(NOW)
        };
        let kernel = fixture.kernel(hook, true, false)?;
        let response = kernel.evaluate_tool_call_blocking(&fixture.request)?;
        assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    }
    Ok(())
}
