// Native M2 process matrix. Only disposable test stores are provisioned here.
use super::*;
use chio_kernel::DurableFinalizationCutpoint as Finalization;
use chio_store_sqlite::admission_operation_store::NativeDispatchCaptureTransactionTestCutpoint as TransactionPoint;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

mod restart {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/security/adapters/native_flow_process_restart.rs"
    ));
}

mod races {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/security/adapters/native_flow_process_races.rs"
    ));
}

mod caller {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/security/adapters/native_flow_caller_process_tests.rs"
    ));
}

#[derive(Clone, Copy)]
enum RecoveryMode {
    Serial,
    CompetingWorkers,
    LateCallerReport,
}

const CHILD: &str = "CHIO_NATIVE_M2_PROCESS_CHILD";
const ROOT: &str = "CHIO_NATIVE_M2_PROCESS_ROOT";

pub(super) fn fixture_directory() -> std::io::Result<tempfile::TempDir> {
    match std::env::var_os(ROOT) {
        Some(root) if std::env::var_os(CHILD).is_some() => tempfile::tempdir_in(root),
        _ => tempfile::tempdir(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Profile {
    Baseline,
    Combined,
    Nonce,
    Declassification,
    Cumulative,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Point {
    BeforeParticipants,
    Reserved,
    BeforeCommit,
    CommittedBeforeAnchor,
    CapturedBeforeConnector,
    EffectStarted,
    OutputJoined,
    Finalization(FinalizationName),
}

// Keep the witness format local to this test, not a production wire extension.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum FinalizationName {
    Returned,
    Evaluating,
    Resolved,
    Acknowledged,
    Checkpointed,
    Terminal,
}
impl FinalizationName {
    fn point(self) -> Finalization {
        match self {
            Self::Returned => Finalization::ToolReturnRecorded,
            Self::Evaluating => Finalization::PostReturnEvaluationBegun,
            Self::Resolved => Finalization::PostReturnResolved,
            Self::Acknowledged => Finalization::SecurityReleaseAcknowledged,
            Self::Checkpointed => Finalization::SecurityReleaseCheckpointed,
            Self::Terminal => Finalization::TerminalProjected,
        }
    }
}
impl Point {
    fn captured(self) -> bool {
        !matches!(
            self,
            Self::BeforeParticipants | Self::Reserved | Self::BeforeCommit
        )
    }
    fn effected(self) -> bool {
        matches!(
            self,
            Self::EffectStarted | Self::OutputJoined | Self::Finalization(_)
        )
    }
    fn released(self) -> bool {
        matches!(
            self,
            Self::Finalization(FinalizationName::Checkpointed | FinalizationName::Terminal)
        )
    }
}

#[derive(Serialize, Deserialize)]
pub(super) struct Witness {
    directory: PathBuf,
    signer: String,
    binding: NativeSecurityAuthorityBindingV1,
    request: ToolCallRequest,
    context: SecurityInvocationContext,
    fence: chio_core_types::StoreMutationFence,
    declassification_signer: Option<String>,
}

pub(super) fn caller_restart_witness(fixture: &Fixture, disclosure: Option<&Keypair>) -> Witness {
    Witness {
        directory: fixture._directory.path().to_path_buf(),
        signer: fixture.signer.seed_hex(),
        binding: fixture.binding.clone(),
        request: fixture.request.clone(),
        context: fixture.context.clone(),
        fence: fixture.authority.mutation_fence(),
        declassification_signer: disclosure.map(Keypair::seed_hex),
    }
}

pub(super) fn configure_caller_restart(
    kernel: &mut ChioKernel,
    original: &chio_kernel::admission_operation::RetainedToolAdmissionRequestV1,
    witness: &Witness,
) -> TestResult {
    restart::configure_original_selection(kernel, original, witness)
}

struct ProcessHook {
    resolver: NativeFlowResolver,
    point: Point,
}

fn terminate_at(point: Point) -> ! {
    eprintln!("native process cutpoint: {point:?}");
    std::process::abort()
}
impl SecurityPreDispatchHook for ProcessHook {
    fn name(&self) -> &str {
        "native-process-cutpoint"
    }
    fn supports_native_dispatch(&self) -> bool {
        true
    }
    fn native_authority_binding(
        &self,
    ) -> Result<Option<NativeSecurityAuthorityBindingV1>, KernelError> {
        self.resolver.native_authority_binding()
    }
    fn prepare_native_admission(
        &self,
        context: &NativeSecurityAdmissionContext<'_>,
        authority: &NativeSecurityFlowJoinAuthority<'_>,
    ) -> Result<(), KernelError> {
        if self.point == Point::BeforeParticipants {
            terminate_at(self.point);
        }
        self.resolver.prepare_native_admission(context, authority)
    }
    fn prepare_native_nonce_preflight(
        &self,
        context: &NativeSecurityAdmissionContext<'_>,
        authority: &chio_kernel::NativeSecurityNoncePreflightJoinAuthority<'_>,
    ) -> Result<(), KernelError> {
        self.resolver
            .prepare_native_nonce_preflight(context, authority)
    }
    fn commit_native_dispatch(
        &self,
        authority: &mut chio_kernel::NativeSecurityDispatchCaptureAuthority<'_, '_>,
    ) -> Result<(), KernelError> {
        if self.point == Point::Reserved {
            terminate_at(self.point);
        }
        self.resolver.commit_native_dispatch(authority)?;
        if self.point == Point::CapturedBeforeConnector {
            terminate_at(self.point);
        }
        Ok(())
    }
    fn prepare_native_output(
        &self,
        context: &chio_kernel::tool_outcome::DurableSecurityReleaseContext<'_>,
        authority: &chio_kernel::NativeSecurityOutputJoinAuthority<'_>,
    ) -> Result<(), KernelError> {
        self.resolver.prepare_native_output(context, authority)?;
        if self.point == Point::OutputJoined {
            terminate_at(self.point);
        }
        Ok(())
    }
    fn commit(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        Err(KernelError::Internal(
            "native process test reached legacy dispatch".into(),
        ))
    }
}

struct EffectServer {
    path: PathBuf,
    point: Point,
}
#[async_trait::async_trait]
impl ToolServerConnection for EffectServer {
    fn server_id(&self) -> &str {
        "server-a"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["send".into()]
    }
    async fn invoke(
        &self,
        _: &str,
        arguments: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        sync_write(&self.path, b"effect\n", true)
            .map_err(|error| KernelError::Internal(error.to_string()))?;
        if self.point == Point::EffectStarted {
            terminate_at(self.point);
        }
        Ok(arguments)
    }
}

fn sync_write(path: &Path, bytes: &[u8], append: bool) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .append(append)
        .truncate(!append)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::File::open(
        path.parent()
            .ok_or_else(|| std::io::Error::other("missing parent"))?,
    )?
    .sync_all()
}

fn resolver(
    binding: NativeSecurityAuthorityBindingV1,
    disclosure: Option<&Keypair>,
) -> TestResult<NativeFlowResolver> {
    let (registry, config) = match disclosure {
        Some(key) => (
            declassification_registry(&DeclassificationPurpose::new("approved-disclosure")?),
            FlowResolverConfig::new(
                restricted_label(),
                flow_config().category_labels,
                BTreeMap::from([(
                    RecordId::new("native-disclosure-authority")?,
                    key.public_key(),
                )]),
                60_000,
            )?,
        ),
        None => (
            super::super::registry(true, InformationLabel::bottom())?,
            flow_config(),
        ),
    };
    Ok(NativeFlowResolver::new(
        binding,
        registry,
        Arc::new(CountingEmptyClassifier::new()),
        Arc::new(Clock::default()),
        config,
    )?
    .with_captured_lifecycle())
}

fn run_child(profile: Profile, point: Point) -> TestResult {
    let (mut fixture, disclosure) = match profile {
        Profile::Combined => (Fixture::combined_native_credentials()?, None),
        Profile::Declassification => {
            let (fixture, key) = declassification::profile(false, 300)?;
            (fixture, Some(key))
        }
        Profile::Baseline | Profile::Nonce | Profile::Cumulative => {
            (super::super::public_fixture()?, None)
        }
    };
    if profile == Profile::Cumulative {
        use chio_core::capability::governance::GovernedTransactionIntent;
        use chio_core::capability::scope::{Constraint, MonetaryAmount};
        let mut scope = fixture.request.capability.body().scope;
        scope.grants[0]
            .constraints
            .push(Constraint::RequireCumulativeApprovalAbove {
                threshold: MonetaryAmount {
                    units: 100,
                    currency: "USD".into(),
                },
                approval_budget_id: "native-restart-budget".into(),
                approval_budget_epoch: 1,
                cumulative_approval_root_binding: None,
            });
        // Issue the constrained capability through the real authority. Re-signing
        // an already registered identity with a different scope is not valid.
        fixture.request.capability =
            fixture
                .kernel
                .issue_capability(&fixture.agent.public_key(), scope, 600)?;
        let context = fixture.context.as_v1();
        fixture.context = SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
            context.tenant_id().clone(),
            context.session_id().clone(),
            context.principal_id().clone(),
            context.isolation_epoch_id().clone(),
            LineageId::new(&fixture.request.capability.id)?,
            1,
        ));
        fixture.request.governed_intent = Some(GovernedTransactionIntent {
            id: "native-restart-intent".into(),
            server_id: fixture.request.server_id.clone(),
            tool_name: fixture.request.tool_name.clone(),
            purpose: "bounded cumulative invocation".into(),
            max_amount: Some(MonetaryAmount {
                units: 60,
                currency: "USD".into(),
            }),
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: None,
            body: Default::default(),
        });
    }
    fixture
        .kernel
        .set_security_pre_dispatch_hook(Arc::new(resolver(
            fixture.binding.clone(),
            disclosure.as_ref(),
        )?));
    if profile == Profile::Nonce {
        nonce::execution::install_nonce(&mut fixture, 120);
        nonce::execution::issue(&mut fixture)?;
    }
    let root = PathBuf::from(std::env::var_os(ROOT).ok_or("missing process root")?);
    sync_write(
        &root.join("witness.json"),
        &chio_core::canonical_json_bytes(&Witness {
            directory: fixture._directory.path().to_path_buf(),
            signer: fixture.signer.seed_hex(),
            binding: fixture.binding.clone(),
            request: fixture.request.clone(),
            context: fixture.context.clone(),
            fence: fixture.authority.mutation_fence(),
            declassification_signer: disclosure.as_ref().map(Keypair::seed_hex),
        })?,
        false,
    )?;
    match point {
        Point::BeforeCommit | Point::CommittedBeforeAnchor => {
            fixture
                .authority
                .admission_operation_store()
                .install_native_capture_transaction_cutpoint_for_test(
                    if point == Point::BeforeCommit {
                        TransactionPoint::BeforeCommit
                    } else {
                        TransactionPoint::CommittedBeforeAnchor
                    },
                )?;
        }
        Point::Finalization(name) => {
            fixture
                .kernel
                .install_durable_finalization_cutpoint(Arc::new(move |actual| {
                    if actual == name.point() {
                        terminate_at(point);
                    }
                }))
        }
        _ => {}
    }
    fixture
        .kernel
        .set_security_pre_dispatch_hook(Arc::new(ProcessHook {
            resolver: resolver(fixture.binding.clone(), disclosure.as_ref())?,
            point,
        }));
    fixture.kernel.register_tool_server(Box::new(EffectServer {
        path: root.join("effect.log"),
        point,
    }));
    let response = fixture
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.context)?;
    Err(format!(
        "child missed {profile:?}/{point:?}: {:?}: {:?}",
        response.verdict, response.reason
    )
    .into())
}

fn matrix(name: &str, profile: Profile, point: Point) -> TestResult {
    matrix_with_recovery(name, profile, point, RecoveryMode::Serial)
}

fn matrix_with_recovery(
    name: &str,
    profile: Profile,
    point: Point,
    recovery: RecoveryMode,
) -> TestResult {
    if std::env::var_os(CHILD).is_some() {
        return run_child(profile, point);
    }
    let root = tempfile::tempdir()?;
    let output_path = root.path().join("child.log");
    let output = std::fs::File::create(&output_path)?;
    let mut child = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            &format!("security::adapters::tests::native_flow::support::process_recovery::{name}"),
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, "1")
        .env(ROOT, root.path())
        .stdout(output.try_clone()?)
        .stderr(output)
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(180);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            return Err(format!("native process cutpoint timed out: {profile:?}/{point:?}").into());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let child_log = std::fs::read_to_string(output_path)?;
    assert_eq!(
        status.signal(),
        Some(6),
        "child missed {profile:?}/{point:?}: {child_log}"
    );
    let marker = match point {
        Point::BeforeCommit => "native capture transaction cutpoint: BeforeCommit".to_owned(),
        Point::CommittedBeforeAnchor => {
            "native capture transaction cutpoint: CommittedBeforeAnchor".to_owned()
        }
        _ => format!("native process cutpoint: {point:?}"),
    };
    assert!(
        child_log.lines().any(|line| line.ends_with(&marker)),
        "child aborted outside the selected cutpoint: {child_log}"
    );
    let witness: Witness =
        serde_json::from_slice(&std::fs::read(root.path().join("witness.json"))?)?;
    assert_eq!(
        witness.directory.parent(),
        Some(root.path()),
        "only the owned disposable store may be reopened"
    );
    restart::verify(root.path(), &witness, profile, point, recovery)
}

#[test]
fn competing_native_recovery_workers_converge_on_original_terminalization() -> TestResult {
    matrix_with_recovery(
        "competing_native_recovery_workers_converge_on_original_terminalization",
        Profile::Baseline,
        Point::Finalization(FinalizationName::Checkpointed),
        RecoveryMode::CompetingWorkers,
    )
}

#[test]
fn late_caller_report_cannot_replace_native_unknown_outcome() -> TestResult {
    matrix_with_recovery(
        "late_caller_report_cannot_replace_native_unknown_outcome",
        Profile::Nonce,
        Point::EffectStarted,
        RecoveryMode::LateCallerReport,
    )
}

macro_rules! case {
    ($name:ident, $profile:ident, $point:expr) => {
        #[test]
        fn $name() -> TestResult {
            matrix(stringify!($name), Profile::$profile, $point)
        }
    };
}
case!(
    baseline_before_participants,
    Baseline,
    Point::BeforeParticipants
);
case!(baseline_reversible_reservation, Baseline, Point::Reserved);
case!(
    baseline_capture_transaction_rollback,
    Baseline,
    Point::BeforeCommit
);
case!(
    baseline_database_commit_before_anchor,
    Baseline,
    Point::CommittedBeforeAnchor
);
case!(
    baseline_capture_before_connector,
    Baseline,
    Point::CapturedBeforeConnector
);
case!(baseline_effect_started, Baseline, Point::EffectStarted);
case!(
    baseline_return_persisted,
    Baseline,
    Point::Finalization(FinalizationName::Returned)
);
case!(
    baseline_evaluation_started,
    Baseline,
    Point::Finalization(FinalizationName::Evaluating)
);
case!(
    baseline_output_resolved,
    Baseline,
    Point::Finalization(FinalizationName::Resolved)
);
case!(
    baseline_release_acknowledged,
    Baseline,
    Point::Finalization(FinalizationName::Acknowledged)
);
case!(
    baseline_release_checkpointed,
    Baseline,
    Point::Finalization(FinalizationName::Checkpointed)
);
case!(
    baseline_terminal_projected,
    Baseline,
    Point::Finalization(FinalizationName::Terminal)
);
case!(combined_reversible_reservation, Combined, Point::Reserved);
case!(
    combined_capture_transaction_rollback,
    Combined,
    Point::BeforeCommit
);
case!(
    combined_database_commit_before_anchor,
    Combined,
    Point::CommittedBeforeAnchor
);
case!(combined_effect_started, Combined, Point::EffectStarted);
case!(
    combined_release_checkpointed,
    Combined,
    Point::Finalization(FinalizationName::Checkpointed)
);
case!(
    cumulative_capture_transaction_rollback,
    Cumulative,
    Point::BeforeCommit
);
case!(
    cumulative_database_commit_before_anchor,
    Cumulative,
    Point::CommittedBeforeAnchor
);
case!(
    cumulative_release_checkpointed,
    Cumulative,
    Point::Finalization(FinalizationName::Checkpointed)
);
case!(
    nonce_capture_transaction_rollback,
    Nonce,
    Point::BeforeCommit
);
case!(
    nonce_database_commit_before_anchor,
    Nonce,
    Point::CommittedBeforeAnchor
);
case!(nonce_effect_started, Nonce, Point::EffectStarted);
case!(
    nonce_release_checkpointed,
    Nonce,
    Point::Finalization(FinalizationName::Checkpointed)
);
case!(
    declassification_capture_transaction_rollback,
    Declassification,
    Point::BeforeCommit
);
case!(
    declassification_database_commit_before_anchor,
    Declassification,
    Point::CommittedBeforeAnchor
);
case!(
    declassification_effect_started,
    Declassification,
    Point::EffectStarted
);
case!(
    declassification_output_joined,
    Declassification,
    Point::OutputJoined
);
case!(
    declassification_release_checkpointed,
    Declassification,
    Point::Finalization(FinalizationName::Checkpointed)
);
