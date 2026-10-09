//! Native recovery fixture bootstrap. Uses the production serving authority, receipt
//! writer, capability verifier and manifest resolver. The external effect server
//! is installed by the fixture, with independent durable effect accounting.
use super::*;
use chio_flow::CategoryLabelMap;
use chio_kernel::KernelConfig;
use chio_manifest::{
    sign_manifest, AuthoritativeToolPolicy, RuntimeToolTopology, ToolAnnotations, ToolDefinition,
    ToolFlowDeclaration, ToolManifest, VerifiedManifestRegistry, TOOL_MANIFEST_SCHEMA,
};
use chio_security_kernel::SecurityClock;
use chio_security_types::flow::Compartment;
use chio_security_types::ports::{
    ClassificationPort, ClassificationRequest, ClassificationResult, ClassifierId,
    ClassifierVersion, PortError, PortResult,
};
use chio_store_sqlite::SqliteReceiptStore;
use std::collections::BTreeSet;
pub(super) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
pub(super) fn open_kernel(
    directory: &std::path::Path,
    authority: &SqliteAuthorityStore,
    signer: &Keypair,
) -> TestResult<(ChioKernel, Arc<AtomicUsize>)> {
    let mut ca_public_keys = vec![signer.public_key()];
    if directory.join("legacy-near-capacity").exists()
        && directory.join("current-recovery-receipt-signer").exists()
    {
        // The old35 consumer retains the original public trust root while
        // its current boot constructs only the independent replacement key.
        ca_public_keys.push(chio_core::PublicKey::from_hex(
            "fcbe38632417bb5b875d49a3c02270633917c6093fd01ebb59ff6416e37afe0c",
        )?);
    }
    let mut kernel = ChioKernel::new(KernelConfig {
        ca_public_keys,
        keypair: signer.clone(),
        max_delegation_depth: 5,
        policy_hash: authority_history::fixture_policy_hash(directory)?,
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: false,
        allow_ephemeral_revocation_store: false,
        checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
    });
    let receipts = SqliteReceiptStore::open(directory.join("receipts.db"))?;
    receipts.wait_for_writer_ready(std::time::Duration::from_secs(30))?;
    kernel.set_receipt_store_handle(Arc::new(receipts))?;
    kernel.set_durable_admission_store(
        Arc::new(authority.admission_operation_store()),
        Arc::new(authority.tool_outcome_store()),
        authority.mutation_fence(),
    )?;
    kernel.set_budget_store_handle(Arc::new(authority.budget_store()));
    kernel.set_revocation_store_handle(Arc::new(authority.revocation_store()));
    let invocations = Arc::new(AtomicUsize::new(0));
    Ok((kernel, invocations))
}

pub(super) fn now_ms() -> PortResult<u64> {
    if SYNCHRONOUS_FIXTURE_CLOCK.with(std::cell::Cell::get) {
        return chio_kernel::fixed_runtime_unix_secs_for_current_thread()
            .and_then(|seconds| seconds.checked_mul(1_000))
            .ok_or_else(PortError::unavailable);
    }
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| PortError::unavailable())?
        .as_millis()
        .try_into()
        .map_err(|_| PortError::unavailable())
}

thread_local! {
    static SYNCHRONOUS_FIXTURE_CLOCK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Share the existing kernel clock with synchronous fixture setup, native
/// resolver and direct Store calls. The kernel guard is thread-bound and does
/// not select or reset receipt IDs. Ordinary fixtures retain wall-clock time.
pub(super) struct SynchronousFixtureClockScope {
    previous_opt_in: bool,
    _kernel_clock: chio_kernel::FixedRuntimeClockScope,
}

impl Drop for SynchronousFixtureClockScope {
    fn drop(&mut self) {
        SYNCHRONOUS_FIXTURE_CLOCK.with(|enabled| enabled.set(self.previous_opt_in));
    }
}

pub(super) fn scope_synchronous_fixture_clock(seconds: u64) -> SynchronousFixtureClockScope {
    let kernel_clock = chio_kernel::scope_fixed_runtime_clock_for_current_thread(seconds);
    SynchronousFixtureClockScope {
        previous_opt_in: SYNCHRONOUS_FIXTURE_CLOCK.with(|enabled| enabled.replace(true)),
        _kernel_clock: kernel_clock,
    }
}

#[test]
fn synchronous_fixture_clock_is_thread_local_and_restores_nested_scopes() -> TestResult {
    let prior_clock = chio_kernel::fixed_runtime_unix_secs_for_current_thread();
    assert!(!SYNCHRONOUS_FIXTURE_CLOCK.with(std::cell::Cell::get));
    let before = now_ms()?;
    {
        let _kernel_only = chio_kernel::scope_fixed_runtime_clock_for_current_thread(7);
        assert!(now_ms()? >= before, "ordinary fixture time does not opt in");
    }
    {
        let _outer = scope_synchronous_fixture_clock(11);
        assert_eq!(now_ms()?, 11_000);
        assert_eq!(Clock::default().now_unix_ms()?, 11_000);
        {
            let _inner = scope_synchronous_fixture_clock(22);
            assert_eq!(now_ms()?, 22_000);
        }
        assert_eq!(now_ms()?, 11_000);
        let isolated = std::thread::spawn(|| {
            assert!(!SYNCHRONOUS_FIXTURE_CLOCK.with(std::cell::Cell::get));
            assert_eq!(
                chio_kernel::fixed_runtime_unix_secs_for_current_thread(),
                None
            );
            now_ms()
        })
        .join()
        .map_err(|_| "isolated fixture clock thread panicked")??;
        assert!(isolated >= before);
    }
    assert!(!SYNCHRONOUS_FIXTURE_CLOCK.with(std::cell::Cell::get));
    assert_eq!(
        chio_kernel::fixed_runtime_unix_secs_for_current_thread(),
        prior_clock
    );
    assert!(now_ms()? >= before);
    Ok(())
}

#[test]
fn synchronous_fixture_clock_restores_opt_in_and_kernel_time_after_unwind() -> TestResult {
    let prior_clock = chio_kernel::fixed_runtime_unix_secs_for_current_thread();
    let outer = scope_synchronous_fixture_clock(33);
    let unwound = std::panic::catch_unwind(|| {
        let _inner = scope_synchronous_fixture_clock(44);
        assert_eq!(now_ms().ok(), Some(44_000));
        panic!("unwind fixture clock scope");
    });
    assert!(unwound.is_err());
    assert_eq!(now_ms()?, 33_000);
    assert_eq!(
        chio_kernel::fixed_runtime_unix_secs_for_current_thread(),
        Some(33)
    );
    drop(outer);
    let unwound = std::panic::catch_unwind(|| {
        let _outer = scope_synchronous_fixture_clock(55);
        panic!("unwind outer fixture clock scope");
    });
    assert!(unwound.is_err());
    assert!(!SYNCHRONOUS_FIXTURE_CLOCK.with(std::cell::Cell::get));
    assert_eq!(
        chio_kernel::fixed_runtime_unix_secs_for_current_thread(),
        prior_clock
    );
    Ok(())
}

#[derive(Default)]
pub(super) struct Clock {
    pub mode: AtomicUsize,
}

impl SecurityClock for Clock {
    fn now_unix_ms(&self) -> PortResult<u64> {
        match self.mode.load(Ordering::SeqCst) {
            0 => now_ms(),
            1 => Ok(0),
            2 => Ok((1_u64 << 53) - 1),
            3 => panic!("native policy clock panic"),
            _ => Err(PortError::unavailable()),
        }
    }
}

pub(super) struct CountingEmptyClassifier {
    calls: AtomicUsize,
}

impl CountingEmptyClassifier {
    pub(super) fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
        }
    }
}

impl ClassificationPort for CountingEmptyClassifier {
    fn classify(&self, request: &ClassificationRequest) -> PortResult<ClassificationResult> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(ClassificationResult {
            tenant_id: request.tenant_id.clone(),
            request_id: request.request_id.clone(),
            payload_digest: request.payload_digest,
            classifier_id: ClassifierId::new("classifier.empty").map_err(PortError::from)?,
            classifier_version: ClassifierVersion::new("1").map_err(PortError::from)?,
            findings: chio_security_types::ports::BoundedVec::new(Vec::new())
                .map_err(|_| PortError::invalid_data())?,
        })
    }
}

pub(super) fn restricted_label() -> InformationLabel {
    InformationLabel::try_known(
        BTreeMap::new(),
        BTreeSet::from([
            Compartment::new("restricted").unwrap_or_else(|error| panic!("compartment: {error}"))
        ]),
    )
    .unwrap_or_else(|error| panic!("label: {error}"))
}

pub(super) fn declassification_registry(
    purpose: &DeclassificationPurpose,
) -> Arc<VerifiedManifestRegistry> {
    declassification_registry_with_output_floor(purpose, InformationLabel::bottom())
}

pub(super) fn declassification_registry_with_output_floor(
    purpose: &DeclassificationPurpose,
    output_floor: InformationLabel,
) -> Arc<VerifiedManifestRegistry> {
    let signer = Keypair::from_seed(&[73; 32]);
    let flow = ToolFlowDeclaration::new(
        (output_floor != InformationLabel::bottom()).then(|| output_floor.clone()),
        Some(InformationLabel::bottom()),
        true,
        BTreeSet::from([purpose.clone()]),
    )
    .unwrap_or_else(|error| panic!("flow: {error}"));
    let manifest = ToolManifest {
        schema: TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "server-a".to_string(),
        name: "Flow server".to_string(),
        description: None,
        version: "1.0.0".to_string(),
        tools: vec![ToolDefinition {
            name: "send".to_string(),
            description: "Send".to_string(),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: Some(serde_json::json!({"type": "object"})),
            pricing: None,
            annotations: ToolAnnotations {
                read_only: false,
                destructive: false,
                idempotent: true,
                requires_approval: false,
            },
            latency_hint: None,
            flow: Some(flow),
        }],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: signer.public_key().to_hex(),
    };
    let signed =
        sign_manifest(&manifest, &signer).unwrap_or_else(|error| panic!("sign manifest: {error}"));
    let policy = AuthoritativeToolPolicy::new(
        vec![InformationLabel::bottom()],
        output_floor,
        BTreeSet::from([purpose.clone()]),
    )
    .unwrap_or_else(|error| panic!("policy: {error}"));
    let mut registry = VerifiedManifestRegistry::default();
    registry
        .register(
            signed,
            &signer.public_key(),
            &BTreeMap::from([("send".to_string(), policy)]),
            &BTreeMap::from([("send".to_string(), RuntimeToolTopology::remote())]),
        )
        .unwrap_or_else(|error| panic!("register manifest: {error}"));
    Arc::new(registry)
}

pub(super) fn category_labels() -> CategoryLabelMap {
    CategoryLabelMap::new(
        ClassifierId::new("classifier.empty").unwrap_or_else(|error| panic!("classifier: {error}")),
        ClassifierVersion::new("1").unwrap_or_else(|error| panic!("classifier version: {error}")),
        BTreeMap::new(),
    )
    .unwrap_or_else(|error| panic!("category map: {error}"))
}

/// Only the extended setup-validity fixture follows the fixed owning clock.
/// The ordinary fixture keeps its real-time clock and 600-second capability.
pub(super) fn fixture_native_clock(path: &std::path::Path) -> Arc<dyn SecurityClock> {
    struct OwningRuntimeClock;
    impl SecurityClock for OwningRuntimeClock {
        fn now_unix_ms(&self) -> PortResult<u64> {
            if let Some(seconds) = chio_kernel::fixed_runtime_unix_secs_for_current_thread() {
                return seconds
                    .checked_mul(1_000)
                    .ok_or_else(PortError::unavailable);
            }
            now_ms()
        }
    }
    if path.join("extended-setup-validity").exists() {
        Arc::new(OwningRuntimeClock)
    } else {
        Arc::new(Clock::default())
    }
}
