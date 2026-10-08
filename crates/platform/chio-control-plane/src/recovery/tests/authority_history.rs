//! Real captured-operation crash recovery across trusted deployment rotations.
use super::*;
use crate::recovery::RecoveryRuntimeError;
use ::chio_core_types::recovery::RecoveryDigestDomain;
use chio_kernel::{RevocationStore, SecurityPreDispatchHook};
use std::path::Path;

#[path = "authority_holds.rs"]
mod authority_holds;

#[path = "authority_begin.rs"]
mod authority_begin;

#[path = "workflow_quota_heads.rs"]
mod workflow_quota_heads;

#[path = "authority_terminal.rs"]
mod authority_terminal;

#[cfg(all(unix, feature = "pq"))]
#[path = "authority_history/near_capacity_historical_signing.rs"]
mod near_capacity_historical_signing;

#[cfg(all(unix, feature = "pq"))]
#[path = "authority_history/near_capacity_private_kernel_continuation.rs"]
mod near_capacity_private_kernel_continuation;

#[cfg(all(unix, feature = "pq"))]
#[path = "authority_history/retained_digest_denial.rs"]
mod retained_digest_denial;

#[path = "authority_history/host_port_replay.rs"]
pub(super) mod host_port_replay;

pub(super) fn configure_fixture_history_hooks(
    kernel: &mut ChioKernel,
    path: &Path,
    flow: Arc<NativeFlowResolver>,
    authority: &SqliteAuthorityStore,
    control: &CapabilityToken,
) -> TestResult {
    #[cfg(feature = "pq")]
    if path.join("current-recovery-receipt-signer").exists()
        || path.join("original-recovery-receipt-signer").exists()
    {
        let verifier = FixtureSigningQuote(kernel.public_key());
        kernel.with_hybrid_signing_backend(
            &chio_kernel::HybridSigningConfig {
                crypto_floor: chio_kernel::KernelCryptoFloor::AllowHybrid,
                pq_signing_seed: Some(if path.join("current-recovery-receipt-signer").exists() {
                    [206; 32]
                } else {
                    [205; 32]
                }),
            },
            b"recovery-current-receipt-signer-quote",
            &verifier,
        )?;
    }
    if path.join("current-recovery-post-return-hook").exists()
        || path
            .join("current-recovery-post-return-unavailable")
            .exists()
    {
        kernel.add_post_invocation_hook(Box::new(CurrentPostReturnHook {
            unavailable: path
                .join("current-recovery-post-return-unavailable")
                .exists(),
        }));
    }
    let fault = if path
        .join("current-recovery-classifier-unavailable")
        .exists()
    {
        Some(CurrentResultHookFault::Unavailable)
    } else if path
        .join("revoke-current-recovery-actor-during-classification")
        .exists()
    {
        Some(CurrentResultHookFault::Revoke)
    } else {
        None
    };
    if let Some(fault) = fault {
        kernel.set_security_pre_dispatch_hook(Arc::new(CurrentResultHook {
            flow,
            revocation: authority.revocation_store(),
            capability: control.id.clone(),
            fault,
        }));
    } else {
        flow.install_captured_on_kernel(kernel)?;
        if path.join("setup-capture-clock-checkpoint").exists() {
            let selected_clock = path.join("setup-capture-selected-seconds");
            let observed = path.join("setup-capture-checkpoint-observed");
            let final_expiry = path.join("setup-capture-final-expiry");
            let final_observed = path.join("setup-capture-final-cutpoint-observed");
            let checkpoint_store = authority.admission_operation_store();
            let checkpoint_flow = flow.clone();
            kernel.install_native_capture_checkpoint_hook(Arc::new(move |authority| {
                let selected_seconds = if selected_clock.exists() {
                    Some(
                        std::fs::read_to_string(&selected_clock)
                            .map_err(|_| {
                                chio_kernel::KernelError::Internal(
                                    "setup capture fixture clock unavailable".into(),
                                )
                            })?
                            .parse::<u64>()
                            .map_err(|_| {
                                chio_kernel::KernelError::Internal(
                                    "setup capture fixture clock invalid".into(),
                                )
                            })?,
                    )
                } else {
                    None
                };
                // This clock-only RAII guard preserves receipt IDs and spans
                // BOTH genuine preparation and physical capture, then restores.
                let _clock =
                    selected_seconds.map(chio_kernel::scope_fixed_runtime_clock_for_current_thread);
                let result = (|| -> Result<(), String> {
                    let egress = authority
                        .prepare_egress()
                        .map_err(|error| error.to_string())?;
                    let inject_final_clock = final_expiry.exists();
                    if inject_final_clock {
                        checkpoint_store
                            .inject_native_capture_setup_expiry_for_test(
                                egress.operation_id(),
                                &final_observed,
                            )
                            .map_err(|error| {
                                format!("setup final capture phase=exact marker: {error}")
                            })?;
                    }
                    let captured = (|| -> Result<(), String> {
                        let prepared = checkpoint_flow
                            .prepare_dispatch(egress)
                            .map_err(|error| error.to_string())?;
                        prepared
                            .capture_invocation(authority)
                            .map_err(|error| error.to_string())?;
                        Ok(())
                    })();
                    if inject_final_clock {
                        if let Err(error) =
                            checkpoint_store.clear_native_capture_setup_expiry_for_test()
                        {
                            return Err(format!(
                                "setup final capture phase=marker cleanup: {error}; capture={:?}",
                                captured.as_ref().err(),
                            ));
                        }
                    }
                    captured
                })();
                let observation = match &result {
                    Ok(()) => "captured".to_owned(),
                    Err(error) => format!("refused:{error}"),
                };
                std::fs::write(&observed, observation).map_err(|_| {
                    chio_kernel::KernelError::Internal(
                        "setup capture fixture observation unavailable".into(),
                    )
                })?;
                // The existing checkpoint contract ALWAYS stops before any
                // connector call, including after authentic successful capture.
                result.map_err(|_| {
                    chio_kernel::KernelError::Internal(
                        "setup capture fixture checkpoint refused".into(),
                    )
                })
            }));
        }
    }
    Ok(())
}

#[cfg(feature = "pq")]
struct FixtureSigningQuote(chio_core::PublicKey);
#[cfg(feature = "pq")]
impl chio_kernel::boot::KernelSelfQuoteVerifier for FixtureSigningQuote {
    fn verify_self_quote(
        &self,
        quote: &[u8],
        key: &chio_core::PublicKey,
    ) -> chio_kernel::boot::KernelSelfQuoteOutcome {
        if quote == b"recovery-current-receipt-signer-quote" && key == &self.0 {
            chio_kernel::boot::KernelSelfQuoteOutcome::accepted()
        } else {
            chio_kernel::boot::KernelSelfQuoteOutcome::rejected("fixture signing quote changed")
        }
    }
}

pub(super) fn fixture_classifier(
    path: &Path,
) -> Arc<dyn chio_security_types::ports::ClassificationPort> {
    if path.join("current-recovery-classifier-panic").exists() {
        Arc::new(PanickingResultClassifier {
            marker: path.join("classifier-panic-observed"),
        })
    } else {
        Arc::new(CountingEmptyClassifier::new())
    }
}
struct PanickingResultClassifier {
    marker: std::path::PathBuf,
}
impl chio_security_types::ports::ClassificationPort for PanickingResultClassifier {
    fn classify(
        &self,
        _: &chio_security_types::ports::ClassificationRequest,
    ) -> chio_security_types::ports::PortResult<chio_security_types::ports::ClassificationResult>
    {
        std::fs::write(&self.marker, b"nested-classifier-entered")
            .map_err(|_| chio_security_types::ports::PortError::unavailable())?;
        panic!("recovery fixture nested classifier panic");
    }
}

struct CurrentPostReturnHook {
    unavailable: bool,
}
impl chio_kernel::PostInvocationHook for CurrentPostReturnHook {
    fn name(&self) -> &str {
        "current-recovery-post-return-hook"
    }
    fn inspect(
        &self,
        _: &chio_kernel::PostInvocationContext<'_>,
        _: &Value,
    ) -> chio_kernel::PostInvocationVerdict {
        chio_kernel::PostInvocationVerdict::Allow
    }
    fn durable_identity(&self) -> Result<Option<chio_kernel::PostInvocationHookIdentity>, String> {
        if self.unavailable {
            return Ok(None);
        }
        chio_kernel::PostInvocationHookIdentity::from_canonical_config(
            self.name(),
            "2",
            "current-recovery-post-return-hook.v2",
            &(),
        )
        .map(Some)
    }
}

enum CurrentResultHookFault {
    Unavailable,
    Revoke,
}
struct CurrentResultHook {
    flow: Arc<NativeFlowResolver>,
    revocation: chio_store_sqlite::SqliteRevocationStore,
    capability: String,
    fault: CurrentResultHookFault,
}
impl SecurityPreDispatchHook for CurrentResultHook {
    fn name(&self) -> &str {
        "current-recovery-result-hook"
    }
    fn supports_native_dispatch(&self) -> bool {
        self.flow.supports_native_dispatch()
    }
    fn native_authority_binding(
        &self,
    ) -> Result<
        Option<chio_kernel::admission_operation::NativeSecurityAuthorityBindingV1>,
        KernelError,
    > {
        self.flow.native_authority_binding()
    }
    fn commit_native_dispatch(
        &self,
        authority: &mut chio_kernel::NativeSecurityDispatchCaptureAuthority<'_, '_>,
    ) -> Result<(), KernelError> {
        self.flow.commit_native_dispatch(authority)
    }
    fn prepare_native_admission(
        &self,
        context: &chio_kernel::NativeSecurityAdmissionContext<'_>,
        authority: &chio_kernel::NativeSecurityFlowJoinAuthority<'_>,
    ) -> Result<(), KernelError> {
        self.flow.prepare_native_admission(context, authority)
    }
    fn prepare_native_nonce_preflight(
        &self,
        context: &chio_kernel::NativeSecurityAdmissionContext<'_>,
        authority: &chio_kernel::NativeSecurityNoncePreflightJoinAuthority<'_>,
    ) -> Result<(), KernelError> {
        self.flow.prepare_native_nonce_preflight(context, authority)
    }
    fn prepare_native_output(
        &self,
        context: &chio_kernel::tool_outcome::DurableSecurityReleaseContext<'_>,
        authority: &chio_kernel::NativeSecurityOutputJoinAuthority<'_>,
    ) -> Result<(), KernelError> {
        self.flow.prepare_native_output(context, authority)
    }
    fn classify_recovery_result(
        &self,
        context: &RecoveryResultClassificationContext<'_>,
    ) -> Result<InformationLabel, RecoveryResultClassificationError> {
        match self.fault {
            CurrentResultHookFault::Unavailable => {
                Err(RecoveryResultClassificationError::Unavailable)
            }
            CurrentResultHookFault::Revoke => {
                let label = self.flow.classify_recovery_result(context)?;
                self.revocation
                    .revoke(&self.capability)
                    .map_err(|_| RecoveryResultClassificationError::Refused)?;
                Ok(label)
            }
        }
    }
    fn commit(
        &self,
        context: &chio_kernel::SecurityPreDispatchContext<'_>,
    ) -> Result<Option<chio_kernel::SecurityDispatchOutcomeHandle>, KernelError> {
        self.flow.commit(context)
    }
}

pub(super) fn fixture_approval_key(path: &Path) -> Keypair {
    Keypair::from_seed(
        &[if path.join("current-recovery-actor").exists() {
            202
        } else {
            142
        }; 32],
    )
}

pub(super) fn fixture_aggregate_key(path: &Path) -> Keypair {
    Keypair::from_seed(
        &[if path.join("current-recovery-aggregate").exists() {
            203
        } else {
            143
        }; 32],
    )
}

pub(super) fn fixture_policy_hash(path: &Path) -> TestResult<String> {
    let marker = path.join("current-recovery-policy");
    if marker.exists() {
        Ok(std::fs::read_to_string(marker)?)
    } else {
        Ok(chio_core::sha256_hex(b"native-flow-policy-test"))
    }
}

pub(super) fn fixture_output_floor(path: &Path) -> TestResult<InformationLabel> {
    let marker = path.join("current-recovery-output-floor.json");
    if marker.exists() {
        Ok(serde_json::from_slice(&std::fs::read(marker)?)?)
    } else {
        Ok(InformationLabel::bottom())
    }
}

pub(super) fn fixture_effect_contract(path: &Path) -> TestResult<RecoveryEffectContractV1> {
    let marker = path.join("current-recovery-effect-contract.json");
    if marker.exists() {
        Ok(serde_json::from_slice(&std::fs::read(marker)?)?)
    } else {
        Ok(RecoveryEffectContractV1 {
            schema: RecoveryEffectContractSchema::V1,
            provider: RecoveryEffectProviderId::new("fixture-provider")?,
            account: RecoveryEffectAccountId::new("fixture-account")?,
            resource: ProtectedText::new("https://fixture.invalid/issues")?,
            observation_key: Keypair::from_seed(&[143; 32]).public_key(),
            max_response_bytes: SafeInteger::new(65536)?,
        })
    }
}

fn output_only_label() -> TestResult<InformationLabel> {
    Ok(InformationLabel::try_known(
        BTreeMap::new(),
        std::collections::BTreeSet::from([chio_security_types::flow::Compartment::new(
            "output-only",
        )?]),
    )?)
}

fn set_output_floor(path: &Path, label: &InformationLabel) -> TestResult {
    std::fs::write(
        path.join("current-recovery-output-floor.json"),
        chio_core::canonical_json_bytes(label)?,
    )?;
    Ok(())
}

#[cfg(unix)]
async fn crash_after_capture(point: &str) -> TestResult<tempfile::TempDir> {
    Box::pin(crash_after_capture_with_output_floor(point, None)).await
}

#[cfg(unix)]
async fn crash_after_capture_with_output_floor(
    point: &str,
    output_floor: Option<InformationLabel>,
) -> TestResult<tempfile::TempDir> {
    Box::pin(crash_after_capture_with_profile(
        point,
        output_floor,
        false,
        false,
    ))
    .await
}

#[cfg(all(unix, feature = "pq"))]
async fn crash_after_capture_with_original_receipt_signer(
    point: &str,
) -> TestResult<tempfile::TempDir> {
    Box::pin(crash_after_capture_with_profile(point, None, true, false)).await
}

#[cfg(all(unix, feature = "pq"))]
async fn crash_after_digest_rejection_with_original_receipt_signer(
    point: &str,
) -> TestResult<tempfile::TempDir> {
    Box::pin(crash_after_capture_with_profile(point, None, true, true)).await
}

#[cfg(unix)]
async fn crash_after_capture_with_profile(
    point: &str,
    output_floor: Option<InformationLabel>,
    original_receipt_signer: bool,
    mismatched_output_digest: bool,
) -> TestResult<tempfile::TempDir> {
    use std::os::unix::process::ExitStatusExt;
    use std::time::{Duration, Instant};

    let directory = tempfile::tempdir()?;
    if original_receipt_signer {
        std::fs::write(
            directory.path().join("original-recovery-receipt-signer"),
            b"1",
        )?;
    }
    if mismatched_output_digest {
        std::fs::write(directory.path().join("mismatched-output-digest"), b"1")?;
    }
    if let Some(floor) = output_floor {
        set_output_floor(directory.path(), &floor)?;
    }
    eprintln!("historical capture phase: {point} original seed open");
    let original = RecoveryFixture::open(directory.path().to_path_buf(), None, false)?;
    Box::pin(original.denied_seed_named("ticket-1")).await?;
    assert_eq!(original.process.process("root")?.tree_calls, 1);
    drop(original);
    let log = std::fs::File::create(directory.path().join("authority-history-child.log"))?;
    let mut child = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "recovery::tests::recovery_crash_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("CHIO_RECOVERY_CRASH_CHILD", "1")
        .env("CHIO_RECOVERY_CRASH_ROOT", directory.path())
        .env("CHIO_RECOVERY_CRASH_POINT", point)
        .stdout(log.try_clone()?)
        .stderr(log)
        .spawn()?;
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() > Duration::from_secs(90) {
            child.kill()?;
            child.wait()?;
            return Err(format!("captured-operation crash timed out at {point}").into());
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    let log = std::fs::read_to_string(directory.path().join("authority-history-child.log"))?;
    eprintln!("historical capture child: {point} status={status}\n{log}");
    assert_eq!(status.signal(), Some(6), "{point}: {log}");
    assert!(
        log.contains(&format!("recovery crash cutpoint: {point}")),
        "captured-operation child missed {point}: {log}"
    );
    assert_eq!(external_count(directory.path())?, 1);
    Ok(directory)
}

fn retained_workflow(path: &Path) -> TestResult<RecoveryWorkflowRecordV1> {
    let db = rusqlite::Connection::open_with_flags(
        path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let bytes: Vec<u8> = db.query_row(
        "SELECT payload FROM admission_operation_recovery_records WHERE kind='workflow'",
        [],
        |row| row.get(0),
    )?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn rotate_coverage(path: &Path, scope: &RecoveryScopeV1) -> TestResult {
    rotate_deployment(path, scope, DeploymentRotation::Coverage)
}

fn install_current_profile(path: &Path, profile: &RecoveryDeploymentV1) -> TestResult {
    let authority =
        SqliteAuthorityStore::open_serving(path.join("admission.db"), path.join("locks"))?;
    authority
        .admission_operation_store()
        .configure_recovery_deployment(profile)?;
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum DeploymentRotation {
    Coverage,
    Actor,
    Aggregate,
    Policy,
    EffectContract,
    ObservationKey,
    NativeAuthority,
}

fn rotate_deployment(
    path: &Path,
    scope: &RecoveryScopeV1,
    rotation: DeploymentRotation,
) -> TestResult {
    let authority =
        SqliteAuthorityStore::open_serving(path.join("admission.db"), path.join("locks"))?;
    let store = authority.admission_operation_store();
    let mut profile = store.deployment(scope, &authority.mutation_fence(), now_ms()?)?;
    match rotation {
        DeploymentRotation::Coverage => {
            let mut coverage = profile.coverage.as_slice().to_vec();
            coverage[0].key = Keypair::from_seed(&[201; 32]).public_key();
            profile.coverage = NonEmptyBoundedList::new(coverage)?;
        }
        DeploymentRotation::Actor => {
            let mut actors = profile.actors.as_slice().to_vec();
            actors[0].subject = Keypair::from_seed(&[202; 32]).public_key();
            profile.actors = NonEmptyBoundedList::new(actors)?;
            std::fs::write(
                path.join("current-recovery-actor"),
                b"synthetic actor rotation",
            )?;
        }
        DeploymentRotation::Aggregate => {
            profile.aggregate_issuer = Keypair::from_seed(&[203; 32]).public_key();
            std::fs::write(
                path.join("current-recovery-aggregate"),
                b"synthetic issuer rotation",
            )?;
        }
        DeploymentRotation::Policy => {
            profile.policy_digest = PolicyDigest::from_bytes(
                *chio_core::sha256(b"rotated-native-flow-policy-test").as_bytes(),
            );
            std::fs::write(
                path.join("current-recovery-policy"),
                chio_core::sha256_hex(b"rotated-native-flow-policy-test"),
            )?;
        }
        DeploymentRotation::EffectContract => {
            profile.effect_contract.resource =
                ProtectedText::new("https://fixture.invalid/issues-v2")?;
        }
        DeploymentRotation::ObservationKey => {
            profile.effect_contract.observation_key = Keypair::from_seed(&[205; 32]).public_key();
        }
        DeploymentRotation::NativeAuthority => {
            let source_path = path.join("rotated-native-source.db");
            let source = SqliteSecurityStateStore::open(&source_path)?;
            source.seal_declassification_live_dispatch()?;
            source.join(&FlowJoinRequest {
                key: recovery_flow_key(&profile.security_context),
                principal_join: InformationLabel::bottom(),
                lineage_join: InformationLabel::bottom(),
                session_join: InformationLabel::bottom(),
                transition_id: RecordId::new("rotated-native-low-source")?,
            })?;
            drop(source);
            let source = SqliteSecurityParticipantSource::open(source_path)?;
            let selected = AdmissionIdentifier::try_new("authority", "recovery-native-rotated")?;
            let fence = authority.mutation_fence();
            let time = now_ms()?;
            let expectation = store
                .expect_security_participant_source(&selected, &selected, &source, &fence, time)?;
            store.import_security_participant_source(
                &selected,
                expectation.expectation_id(),
                &source,
                &fence,
                time,
            )?;
            profile.native_authority = store
                .hydrate_security_participant_state(
                    &selected,
                    expectation.expectation_id(),
                    &fence,
                    time,
                )?
                .admission_binding()?;
        }
    }
    profile.contract_digest = ContractDigest::from_bytes(recovery_digest(
        RecoveryDigestDomain::EffectContract,
        &profile.effect_contract,
    )?);
    profile.authority_scope = recovery_authority_scope_digest(&profile)?;
    store.configure_recovery_deployment(&profile)?;
    std::fs::write(
        path.join("current-recovery-effect-contract.json"),
        chio_core::canonical_json_bytes(&profile.effect_contract)?,
    )?;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn recovery_captured_return_survives_coverage_rotation() -> TestResult {
    for point in ["return-recorded", "evaluation", "resolved", "release-ack"] {
        let directory = Box::pin(crash_after_capture(point)).await?;
        let before = retained_workflow(directory.path())?;
        assert!(before.captured, "{point}: capture is required");
        assert!(!before.admission_closed);
        rotate_coverage(directory.path(), &before.scope)?;
        let f = RecoveryFixture::open(directory.path().to_path_buf(), None, false).map_err(
            |error| format!("{point}: post-capture coverage rotation blocked startup: {error}"),
        )?;
        let response = f.runtime.settle(&f.control, &before.workflow_id)?;
        let settled = f.record(&before.workflow_id)?;
        assert_eq!(response.effect, settled.effect);
        assert!(matches!(
            settled.effect,
            EffectObservationV1::Complete { .. }
        ));
        assert!(settled.admission_closed);
        assert!(matches!(
            settled.release,
            ReleaseDispositionV1::Withheld { .. }
        ));
        assert_eq!(before.continuation_id, settled.continuation_id);
        for (old, new) in [
            (
                text::<65536, _>(&before.action)?,
                text::<65536, _>(&settled.action)?,
            ),
            (
                text::<65536, _>(&before.signed_grant)?,
                text::<65536, _>(&settled.signed_grant)?,
            ),
            (
                text::<65536, _>(&before.envelope)?,
                text::<65536, _>(&settled.envelope)?,
            ),
            (
                text::<65536, _>(&before.admission)?,
                text::<65536, _>(&settled.admission)?,
            ),
        ] {
            assert_eq!(old, new, "{point}: changed original custody");
        }
        let actor = f.kernel.authenticate_recovery_actor(
            f.runtime.scope(),
            &f.control,
            RecoveryPermission::Inspect,
        )?;
        let first = f
            .kernel
            .replay_recovery_result(&actor, &before.workflow_id)?;
        let second = f
            .kernel
            .replay_recovery_result(&actor, &before.workflow_id)?;
        assert_eq!(
            chio_core::canonical_json_bytes(&first.receipt)?,
            chio_core::canonical_json_bytes(&second.receipt)?,
            "{point}: replaced receipt"
        );
        assert_eq!(external_count(&f.path)?, 1, "{point}: repeated effect");
        assert_eq!(
            f.process.process("root")?.tree_calls,
            2,
            "{point}: charged again"
        );
        drop(f);
        let reopened = RecoveryFixture::open(directory.path().to_path_buf(), None, false)?;
        assert!(reopened
            .runtime
            .settle(&reopened.control, &before.workflow_id)?
            .effect
            .is_settled());
        assert_eq!(external_count(&reopened.path)?, 1);
        assert_eq!(reopened.process.process("root")?.tree_calls, 2);
    }
    Ok(())
}

fn current_control(f: &RecoveryFixture) -> TestResult<CapabilityToken> {
    Ok(f.kernel.issue_capability(
        &fixture_approval_key(&f.path).public_key(),
        f.control.scope.clone(),
        1200,
    )?)
}

#[cfg(unix)]
#[tokio::test]
async fn recovery_captured_return_survives_each_authority_input_rotation() -> TestResult {
    for rotation in [
        DeploymentRotation::Actor,
        DeploymentRotation::Aggregate,
        DeploymentRotation::Policy,
        DeploymentRotation::EffectContract,
        DeploymentRotation::ObservationKey,
        DeploymentRotation::NativeAuthority,
    ] {
        let directory = Box::pin(crash_after_capture("return-recorded")).await?;
        let before = retained_workflow(directory.path())?;
        rotate_deployment(directory.path(), &before.scope, rotation)?;
        let mut f = Box::new(
            RecoveryFixture::open(directory.path().to_path_buf(), None, false).map_err(
                |error| format!("{rotation:?}: captured custody blocked startup: {error}"),
            )?,
        );
        if matches!(rotation, DeploymentRotation::Actor) {
            assert!(
                f.kernel
                    .authenticate_recovery_actor(
                        &before.scope,
                        &f.control,
                        RecoveryPermission::Settle,
                    )
                    .is_err(),
                "removed actor retained settlement authority"
            );
            f.control = current_control(&f)?;
        }
        let status = f.runtime.settle(&f.control, &before.workflow_id)?;
        assert!(
            matches!(status.effect, EffectObservationV1::Complete { .. }),
            "{rotation:?}"
        );
        let settled = f.record(&before.workflow_id)?;
        assert!(settled.admission_closed);
        assert_eq!(before.continuation_id, settled.continuation_id);
        assert_eq!(before.deployment_digest, settled.deployment_digest);
        assert_eq!(
            chio_core::canonical_json_bytes(&before.action)?,
            chio_core::canonical_json_bytes(&settled.action)?
        );
        assert_eq!(
            chio_core::canonical_json_bytes(&before.signed_grant)?,
            chio_core::canonical_json_bytes(&settled.signed_grant)?
        );
        assert_eq!(
            chio_core::canonical_json_bytes(&before.envelope)?,
            chio_core::canonical_json_bytes(&settled.envelope)?
        );
        assert_eq!(
            chio_core::canonical_json_bytes(&before.admission)?,
            chio_core::canonical_json_bytes(&settled.admission)?
        );
        require_original_terminal_receipt(&f, &before)?;
        if matches!(rotation, DeploymentRotation::Policy) {
            assert_ne!(
                fixture_policy_hash(&f.path)?,
                before
                    .admission
                    .as_ref()
                    .ok_or("original policy binding")?
                    .native_binding
                    .policy_hash
                    .as_str(),
            );
            let actor = f.kernel.authenticate_recovery_actor(
                &before.scope,
                &f.control,
                RecoveryPermission::Inspect,
            )?;
            assert!(
                f.kernel
                    .replay_recovery_result(&actor, &before.workflow_id)
                    .is_err(),
                "current policy change released the old captured output"
            );
            assert!(matches!(
                f.record(&before.workflow_id)?.release,
                ReleaseDispositionV1::Withheld { .. }
            ));
            let request: ToolCallRequest = serde_json::from_str(
                before
                    .envelope
                    .as_ref()
                    .ok_or("policy original envelope")?
                    .request
                    .as_str(),
            )?;
            let reservation: RecoveryProcessReservationV1 = serde_json::from_str(
                before
                    .process_reservation
                    .as_ref()
                    .ok_or("policy original reservation")?
                    .as_str(),
            )?;
            if let Ok(response) = f
                .process
                .invoke_known_only("root", &reservation.operation_key, &request)
                .await
            {
                assert!(
                    response.output.is_none(),
                    "generic policy-rotated replay returned output"
                );
                assert!(
                    response.execution_nonce.is_none(),
                    "generic policy-rotated replay minted nonce"
                );
            }
        }
        assert_eq!(external_count(&f.path)?, 1, "{rotation:?}: repeated effect");
        assert_eq!(
            f.process.process("root")?.tree_calls,
            2,
            "{rotation:?}: new charge"
        );
        f.runtime.settle(&f.control, &before.workflow_id)?;
        assert_eq!(external_count(&f.path)?, 1);
    }
    Ok(())
}

#[tokio::test]
async fn recovery_unknown_uses_original_contract_and_current_observation_key() -> TestResult {
    use chio_core_types::recovery::SignedRecoveryProviderFinalityV1;

    let directory = tempfile::tempdir()?;
    let f = Box::new(RecoveryFixture::open(
        directory.path().to_path_buf(),
        None,
        false,
    )?);
    let id = Box::pin(f.ready()).await?;
    let profile = f.kernel.recovery_deployment(f.runtime.scope())?;
    f.behavior.store(1, Ordering::SeqCst);
    let before = f.record(&id)?;
    f.execute(
        "unknown-original",
        RecoveryCommandBodyV1::ResumeWorkflow {
            workflow_id: id.clone(),
            expected_revision: before.revision,
        },
    )
    .await?;
    assert!(matches!(
        f.record(&id)?.effect,
        EffectObservationV1::Unknown { .. }
    ));
    drop(f);
    rotate_deployment(
        directory.path(),
        &profile.scope,
        DeploymentRotation::ObservationKey,
    )?;
    let f = Box::new(RecoveryFixture::open(
        directory.path().to_path_buf(),
        None,
        false,
    )?);
    let actor = f.kernel.authenticate_recovery_actor(
        f.runtime.scope(),
        &f.control,
        RecoveryPermission::Settle,
    )?;
    let lookup = f.kernel.reserve_recovery_provider_lookup(&actor, &id)?;
    let record = lookup.workflow();
    let reference = record
        .effect
        .operation()
        .ok_or("unknown original reference")?;
    let native = f
        .authority
        .admission_operation_store()
        .load_by_operation_id(
            &chio_kernel::admission_operation::AdmissionOperationId::from_persisted(
                reference.operation_id().as_str(),
            )?,
        )?
        .ok_or("unknown original native operation")?;
    let native_before = chio_core::canonical_json_bytes(&native.to_persisted())?;
    let now = now_ms()?;
    let body = RecoveryProviderFinalityV1 {
        schema: RecoveryProviderFinalitySchema::V1,
        version: VersionV1,
        scope: record.scope.clone(),
        workflow_id: record.workflow_id.clone(),
        continuation_id: record.continuation_id.clone(),
        operation_id: reference.operation_id().clone(),
        native_admission_digest: reference.native_admission_digest(),
        attempt_id: ProviderAttemptId::new(
            &native
                .provider_attempt()
                .ok_or("original attempt")?
                .attempt_id,
        )?,
        provider: profile.effect_contract.provider.clone(),
        account: profile.effect_contract.account.clone(),
        resource_digest: ResourceDigest::from_bytes(recovery_digest(
            RecoveryDigestDomain::ProviderResource,
            &profile.effect_contract.resource,
        )?),
        contract_digest: profile.contract_digest,
        observed_at_unix_ms: SafeInteger::new(now)?,
        expires_at_unix_ms: SafeInteger::new(now + 30_000)?,
        disposition: RecoveryEffectDisposition::Succeeded,
        applied_effects: SafeInteger::new(1)?,
    };
    let old_proof =
        SignedRecoveryProviderFinalityV1::sign(body.clone(), &Keypair::from_seed(&[143; 32]))?;
    assert!(old_proof.verify_signature()?);
    assert!(
        f.kernel
            .attach_recovery_provider_finality(&actor, &id, &old_proof)
            .is_err(),
        "rotated-out provider observer authorized fresh finality"
    );
    let current = Keypair::from_seed(&[205; 32]);
    let mut retargeted = body.clone();
    retargeted.contract_digest = lookup.deployment().contract_digest;
    let retargeted = SignedRecoveryProviderFinalityV1::sign(retargeted, &current)?;
    assert!(
        f.kernel
            .attach_recovery_provider_finality(&actor, &id, &retargeted)
            .is_err(),
        "new contract replaced the captured original contract"
    );
    let proof = SignedRecoveryProviderFinalityV1::sign(body, &current)?;
    f.kernel
        .attach_recovery_provider_finality(&actor, &id, &proof)?;
    f.kernel
        .attach_recovery_provider_finality(&actor, &id, &proof)?;
    let settled = f.runtime.settle(&f.control, &id)?;
    assert!(matches!(
        settled.effect,
        EffectObservationV1::Complete { .. }
    ));
    assert_eq!(settled.release, ReleaseDispositionV1::NotAvailable);
    assert_eq!(external_count(&f.path)?, 1);
    assert_eq!(f.process.process("root")?.tree_calls, 2);
    let native_after = f
        .authority
        .admission_operation_store()
        .load_by_operation_id(native.binding().operation_id())?
        .ok_or("settled native original")?;
    assert_eq!(
        native_before,
        chio_core::canonical_json_bytes(&native_after.to_persisted())?
    );
    Ok(())
}

#[tokio::test]
async fn recovery_checkpointed_result_rechecks_current_output_classification() -> TestResult {
    let directory = tempfile::tempdir()?;
    let f = Box::new(RecoveryFixture::open(
        directory.path().to_path_buf(),
        None,
        false,
    )?);
    let id = Box::pin(f.ready()).await?;
    let before = f.record(&id)?;
    let completed = f
        .execute(
            "complete-original",
            RecoveryCommandBodyV1::ResumeWorkflow {
                workflow_id: id.clone(),
                expected_revision: before.revision,
            },
        )
        .await?;
    assert!(completed.original_response.is_some());
    assert!(matches!(
        completed.status.effect,
        EffectObservationV1::Complete { .. }
    ));
    let request: ToolCallRequest = serde_json::from_str(
        f.record(&id)?
            .envelope
            .as_ref()
            .ok_or("original envelope")?
            .request
            .as_str(),
    )?;
    let reservation: RecoveryProcessReservationV1 = serde_json::from_str(
        f.record(&id)?
            .process_reservation
            .as_ref()
            .ok_or("original reservation")?
            .as_str(),
    )?;
    drop(f);
    let higher = output_only_label()?;
    assert!(!higher.flows_to(&restricted_label()));
    set_output_floor(directory.path(), &higher)?;
    let f = Box::new(RecoveryFixture::open(
        directory.path().to_path_buf(),
        None,
        false,
    )?);
    let actor = f.kernel.authenticate_recovery_actor(
        f.runtime.scope(),
        &f.control,
        RecoveryPermission::Inspect,
    )?;
    assert!(
        f.kernel.replay_recovery_result(&actor, &id).is_err(),
        "checkpointed output bypassed the current classifier and actor audience"
    );
    let generic = Box::pin(f.process.invoke_known_only(
        "root",
        &reservation.operation_key,
        &request,
    ))
    .await;
    assert!(
        generic.is_err() || generic.is_ok_and(|response| response.output.is_none()),
        "generic completed replay bypassed current output classification"
    );
    assert!(f.runtime.settle(&f.control, &id)?.effect.is_settled());
    assert_eq!(external_count(&f.path)?, 1);
    assert_eq!(f.process.process("root")?.tree_calls, 2);
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn recovery_native_rotation_retains_stricter_original_output_taint() -> TestResult {
    for point in ["release-ack", "terminal"] {
        let higher = output_only_label()?;
        assert!(!higher.flows_to(&restricted_label()));
        let directory =
            Box::pin(crash_after_capture_with_output_floor(point, Some(higher))).await?;
        let before = retained_workflow(directory.path())?;
        let original_policy = before
            .action
            .as_ref()
            .ok_or("original action")?
            .policy_digest;
        rotate_deployment(
            directory.path(),
            &before.scope,
            DeploymentRotation::NativeAuthority,
        )?;
        // The current classifier and current native source are now lower. The
        // original captured output had a compartment not present in the action
        // or the reviewer's clearance. Policy digest intentionally stays equal.
        set_output_floor(directory.path(), &InformationLabel::bottom())?;
        let f = Box::new(
            RecoveryFixture::open(directory.path().to_path_buf(), None, false).map_err(
                |error| format!("{point}: native rotation blocked captured settlement: {error}"),
            )?,
        );
        assert_eq!(
            f.kernel
                .recovery_deployment(f.runtime.scope())?
                .policy_digest,
            original_policy
        );
        let status = f.runtime.settle(&f.control, &before.workflow_id)?;
        assert!(matches!(
            status.effect,
            EffectObservationV1::Complete { .. }
        ));
        let actor = f.kernel.authenticate_recovery_actor(
            f.runtime.scope(),
            &f.control,
            RecoveryPermission::Inspect,
        )?;
        assert!(
            f.kernel
                .replay_recovery_result(&actor, &before.workflow_id)
                .is_err(),
            "{point}: lower current authority erased stricter original output taint"
        );
        assert!(matches!(
            f.record(&before.workflow_id)?.release,
            ReleaseDispositionV1::Withheld { .. }
        ));
        assert_eq!(external_count(&f.path)?, 1);
        assert_eq!(f.process.process("root")?.tree_calls, 2);
    }
    Ok(())
}

#[tokio::test]
async fn recovery_native_rotation_rechecks_both_current_inherited_authorities() -> TestResult {
    for strengthen_original in [false, true] {
        let directory = tempfile::tempdir()?;
        let f = Box::new(RecoveryFixture::open(
            directory.path().to_path_buf(),
            None,
            false,
        )?);
        let original_id = Box::pin(f.ready()).await?;
        let ready = f.record(&original_id)?;
        let response = f
            .execute(
                "complete-original-inherited",
                RecoveryCommandBodyV1::ResumeWorkflow {
                    workflow_id: original_id.clone(),
                    expected_revision: ready.revision,
                },
            )
            .await?;
        assert!(response.original_response.is_some());
        let original = f.record(&original_id)?;
        let original_profile = f.kernel.recovery_deployment(f.runtime.scope())?;
        let native_before = native_original_bytes(&f.path, &original)?;
        drop(f);
        rotate_deployment(
            directory.path(),
            &original.scope,
            DeploymentRotation::NativeAuthority,
        )?;
        let current_profile = {
            let authority = SqliteAuthorityStore::open_serving(
                directory.path().join("admission.db"),
                directory.path().join("locks"),
            )?;
            authority.admission_operation_store().deployment(
                &original.scope,
                &authority.mutation_fence(),
                now_ms()?,
            )?
        };
        let accessible = Box::new(RecoveryFixture::open(
            directory.path().to_path_buf(),
            None,
            false,
        )?);
        let actor = accessible.kernel.authenticate_recovery_actor(
            accessible.runtime.scope(),
            &accessible.control,
            RecoveryPermission::Inspect,
        )?;
        assert!(
            accessible
                .kernel
                .replay_recovery_result(&actor, &original_id)?
                .output
                .is_some(),
            "low current authority could not read the authenticated original before strengthening"
        );
        assert_eq!(
            native_before,
            native_original_bytes(&accessible.path, &original)?
        );
        drop(accessible);
        if strengthen_original {
            install_current_profile(directory.path(), &original_profile)?;
        }
        set_output_floor(directory.path(), &output_only_label()?)?;
        let f = Box::new(RecoveryFixture::open(
            directory.path().to_path_buf(),
            None,
            false,
        )?);
        // A second, separately admitted actual effect raises inherited taint in
        // exactly the selected authority. It cannot replace the first effect.
        let source_id =
            Box::pin(f.ready_named("higher-inherited-source", "source-strengthen-")).await?;
        let ready = f.record(&source_id)?;
        let resume = f.command(
            "complete-higher-inherited-source",
            RecoveryCommandBodyV1::ResumeWorkflow {
                workflow_id: source_id.clone(),
                expected_revision: ready.revision,
            },
        )?;
        assert!(
            matches!(
                Box::pin(f.runtime.execute_command(&f.control, &resume)).await,
                Err(crate::recovery::RecoveryRuntimeError::AuthorityDenied)
            ),
            "higher output did not reach the current audience refusal"
        );
        let binding =
            chio_kernel::admission_operation::AdmissionOperationBindingV1::from_persisted(
                ready
                    .admission
                    .as_ref()
                    .ok_or("inherited source admission")?
                    .native_binding
                    .clone(),
            )?;
        let operation = f
            .authority
            .admission_operation_store()
            .load_by_operation_id(binding.operation_id())?
            .ok_or("completed inherited native source")?;
        assert_eq!(operation.state(), AdmissionOperationState::Completed);
        require_original_terminal_receipt(&f, &ready)?;
        // Audience refusal precedes the runtime's completion bookkeeping.
        let settled = f.runtime.settle(&f.control, &source_id)?;
        assert!(matches!(
            settled.effect,
            EffectObservationV1::Complete { .. }
        ));
        assert!(matches!(
            settled.release,
            ReleaseDispositionV1::Withheld { .. }
        ));
        assert_eq!(external_count(&f.path)?, 2);
        assert_eq!(f.process.process("root")?.tree_calls, 4);
        assert_eq!(native_before, native_original_bytes(&f.path, &original)?);
        drop(f);
        if strengthen_original {
            install_current_profile(directory.path(), &current_profile)?;
        }
        // The current classifier is low again. Only the persisted inherited
        // restriction in the old or the current authority can refuse replay.
        set_output_floor(directory.path(), &InformationLabel::bottom())?;
        let f = Box::new(RecoveryFixture::open(
            directory.path().to_path_buf(),
            None,
            false,
        )?);
        let actor = f.kernel.authenticate_recovery_actor(
            f.runtime.scope(),
            &f.control,
            RecoveryPermission::Inspect,
        )?;
        assert!(
            f.kernel
                .replay_recovery_result(&actor, &original_id)
                .is_err(),
            "rotation lost current inherited restrictions (original={strengthen_original})"
        );
        assert!(f
            .runtime
            .settle(&f.control, &original_id)?
            .effect
            .is_settled());
        assert_eq!(external_count(&f.path)?, 2);
        assert_eq!(f.process.process("root")?.tree_calls, 4);
        assert_eq!(native_before, native_original_bytes(&f.path, &original)?);
    }
    Ok(())
}

fn recovery_event_count(path: &Path) -> TestResult<u64> {
    let db = rusqlite::Connection::open_with_flags(
        path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let count: i64 = db.query_row(
        "SELECT count(*) FROM admission_operation_recovery_events",
        [],
        |row| row.get(0),
    )?;
    Ok(u64::try_from(count)?)
}

fn native_original_bytes(path: &Path, record: &RecoveryWorkflowRecordV1) -> TestResult<Vec<u8>> {
    let db = rusqlite::Connection::open_with_flags(
        path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let id = &record
        .admission
        .as_ref()
        .ok_or("captured original admission")?
        .native_operation_id;
    Ok(db.query_row(
        "SELECT operation_json FROM admission_operations WHERE operation_id=?1",
        [id.as_str()],
        |row| row.get(0),
    )?)
}

fn captured_return_bytes(
    path: &Path,
    record: &RecoveryWorkflowRecordV1,
) -> TestResult<(Vec<u8>, Vec<u8>)> {
    let db = rusqlite::Connection::open_with_flags(
        path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let id = &record
        .admission
        .as_ref()
        .ok_or("captured admission")?
        .native_operation_id;
    Ok(db.query_row(
        "SELECT o.outcome_json,b.canonical_bytes FROM tool_outcomes o
         JOIN tool_outcome_blobs b ON b.digest=o.raw_output_digest WHERE o.operation_id=?1",
        [id.as_str()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?)
}

fn retained_workflow_quota_bytes(
    path: &Path,
    record: &RecoveryWorkflowRecordV1,
) -> TestResult<(u64, Vec<u8>)> {
    let scope_hash = chio_core::sha256_hex(&chio_core::canonical_json_bytes(&record.scope)?);
    let key = format!(
        "workflow-quota:{scope_hash}:{}",
        record.workflow_id.as_str()
    );
    let db = rusqlite::Connection::open_with_flags(
        path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let (version, payload): (i64, Vec<u8>) = db.query_row(
        "SELECT version,payload FROM admission_operation_recovery_records
         WHERE record_key=?1 AND kind='command'",
        [key],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok((u64::try_from(version)?, payload))
}

fn captured_receipt_signer(
    path: &Path,
    record: &RecoveryWorkflowRecordV1,
) -> TestResult<chio_core::PublicKey> {
    let (_, raw) = captured_return_bytes(path, record)?;
    let raw: serde_json::Value = serde_json::from_slice(&raw)?;
    Ok(serde_json::from_value(
        raw.get("receipt_signing_identity")
            .and_then(|identity| identity.get("public_key"))
            .ok_or("captured raw signing identity")?
            .clone(),
    )?)
}

fn require_original_terminal_receipt(
    fixture: &RecoveryFixture,
    before: &RecoveryWorkflowRecordV1,
) -> TestResult {
    use chio_kernel::admission_operation::{
        AdmissionOperationId, AdmissionReceiptMetadataV1, AdmissionTerminalReplay,
        ADMISSION_RECEIPT_METADATA_KEY,
    };
    use chio_kernel::ReceiptStore;
    let intent = before.admission.as_ref().ok_or("original intent")?;
    let store = fixture.authority.admission_operation_store();
    let operation = store
        .load_by_operation_id(&AdmissionOperationId::from_persisted(
            intent.native_operation_id.as_str(),
        )?)?
        .ok_or("completed physical original")?;
    let receipt_id = match operation.terminal_replay() {
        Some(AdmissionTerminalReplay::Receipt { receipt_id, .. }) => receipt_id,
        _ => return Err("original terminal receipt reference".into()),
    };
    let receipt = store
        .load_chio_receipt(receipt_id.as_str())?
        .ok_or("authenticated original terminal receipt")?;
    assert_eq!(
        receipt.policy_hash,
        intent.native_binding.policy_hash.as_str()
    );
    assert_eq!(
        receipt.kernel_key,
        captured_receipt_signer(&fixture.path, before)?
    );
    assert!(receipt.verify_signature()?);
    let metadata: AdmissionReceiptMetadataV1 = serde_json::from_value(
        receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get(ADMISSION_RECEIPT_METADATA_KEY))
            .ok_or("original receipt admission metadata")?
            .clone(),
    )?;
    assert_eq!(metadata.operation_id, *operation.binding().operation_id());
    assert_eq!(metadata.request_id, *operation.binding().request_id());
    assert_eq!(
        metadata.request_binding_hash,
        *operation.binding().request_binding_hash()
    );
    assert_eq!(
        metadata.request_namespace_digest,
        *operation.binding().request_namespace_digest()
    );
    assert_eq!(metadata.projected_operation_version, operation.version());
    assert_eq!(
        metadata.coordinator_lease_epoch,
        operation.coordinator_lease_epoch()
    );
    assert_eq!(
        metadata.retained_dispatch_commit,
        operation.dispatch_commit().cloned()
    );
    let db = rusqlite::Connection::open_with_flags(
        fixture.path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let (outcome_id, outcome_version): (String, i64) = db.query_row(
        "SELECT outcome_id,outcome_version FROM tool_outcomes WHERE operation_id=?1",
        [intent.native_operation_id.as_str()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(
        metadata.tool_outcome_id.as_ref().map(|id| id.as_str()),
        Some(outcome_id.as_str())
    );
    assert_eq!(
        metadata.tool_outcome_version,
        Some(u64::try_from(outcome_version)?)
    );
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn recovery_nested_classifier_panic_is_fatal_before_output_join() -> TestResult {
    let directory = Box::pin(crash_after_capture("return-recorded")).await?;
    let before = retained_workflow(directory.path())?;
    let raw_before = captured_return_bytes(directory.path(), &before)?;
    std::fs::write(
        directory.path().join("current-recovery-classifier-panic"),
        b"1",
    )?;
    let startup = RecoveryFixture::open(directory.path().to_path_buf(), None, false);
    assert_eq!(
        std::fs::read(directory.path().join("classifier-panic-observed"))?,
        b"nested-classifier-entered"
    );
    assert!(
        startup.is_err(),
        "nested classifier panic was folded into withheld output and successful startup"
    );
    drop(startup);
    let after = retained_workflow(directory.path())?;
    assert_eq!(
        chio_core::canonical_json_bytes(&after)?,
        chio_core::canonical_json_bytes(&before)?
    );
    assert!(!after.admission_closed && !after.effect.is_settled());
    assert!(after.historical_hold.is_none());
    let return_after = captured_return_bytes(directory.path(), &after)?;
    assert_eq!(
        return_after.1, raw_before.1,
        "classifier panic changed immutable raw bytes"
    );
    let native = chio_kernel::admission_operation::AdmissionOperationV1::from_persisted(
        serde_json::from_slice(&native_original_bytes(directory.path(), &after)?)?,
    )?;
    assert_eq!(native.state(), AdmissionOperationState::Finalizing);
    let raw =
        chio_kernel::tool_outcome::RawInvocationOutcomeV1::from_canonical_bytes(&return_after.1)?;
    let blob = raw.canonical_blob()?;
    let original_outcome = chio_kernel::tool_outcome::ToolOutcomeRecordV1::from_persisted(
        serde_json::from_slice(&raw_before.0)?,
    )?;
    let resolved_outcome = chio_kernel::tool_outcome::ToolOutcomeRecordV1::from_persisted(
        serde_json::from_slice(&return_after.0)?,
    )?;
    original_outcome.validate_canonical_blob(&native, &blob)?;
    resolved_outcome.validate_canonical_blob(&native, &blob)?;
    assert!(matches!(
        original_outcome.disposition(),
        chio_kernel::tool_outcome::ResolvedToolOutcomeV1::Returned
    ));
    assert!(matches!(
        resolved_outcome.disposition(),
        chio_kernel::tool_outcome::ResolvedToolOutcomeV1::Resolved { .. }
    ));
    assert_eq!(resolved_outcome.version(), original_outcome.version() + 1);
    let mut immutable_before = serde_json::to_value(original_outcome.to_persisted())?;
    let mut immutable_after = serde_json::to_value(resolved_outcome.to_persisted())?;
    for field in ["disposition", "lifecycle_digest", "version"] {
        immutable_before
            .as_object_mut()
            .ok_or("original outcome object")?
            .remove(field);
        immutable_after
            .as_object_mut()
            .ok_or("resolved outcome object")?
            .remove(field);
    }
    assert_eq!(
        chio_core::canonical_json_bytes(&immutable_after)?,
        chio_core::canonical_json_bytes(&immutable_before)?
    );
    let db = rusqlite::Connection::open_with_flags(
        directory.path().join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let release_count: i64 = db.query_row(
        "SELECT count(*) FROM tool_outcome_security_releases WHERE operation_id=?1",
        [native.binding().operation_id().as_str()],
        |row| row.get(0),
    )?;
    assert_eq!(
        release_count, 0,
        "classifier panic persisted a release checkpoint"
    );
    let joined: i64 = db.query_row(
        "SELECT count(*) FROM security_participant_output_events WHERE operation_id=?1",
        [after
            .admission
            .as_ref()
            .ok_or("panic original admission")?
            .native_operation_id
            .as_str()],
        |row| row.get(0),
    )?;
    assert_eq!(
        joined, 0,
        "panicking classifier wrote native output custody"
    );
    assert_eq!(external_count(directory.path())?, 1);
    Ok(())
}

#[cfg(all(unix, feature = "pq"))]
#[tokio::test]
async fn recovery_captured_signer_rotation_reaches_current_signed_withheld_terminal() -> TestResult
{
    use chio_kernel::admission_operation::{AdmissionOperationId, AdmissionTerminalReplay};
    use chio_kernel::ReceiptStore;
    for point in ["return-recorded", "evaluation", "resolved", "release-ack"] {
        let directory = Box::pin(crash_after_capture_with_original_receipt_signer(point)).await?;
        let before = retained_workflow(directory.path())?;
        let physical_before = chio_core::canonical_json_bytes(&before)?;
        let raw_before = captured_return_bytes(directory.path(), &before)?.1;
        let original_signer = captured_receipt_signer(directory.path(), &before)?;
        assert_eq!(
            original_signer.algorithm(),
            chio_core::SigningAlgorithm::Hybrid
        );
        let intent = before
            .admission
            .as_ref()
            .ok_or("rotated signer original intent")?;
        let operation_id =
            AdmissionOperationId::from_persisted(intent.native_operation_id.as_str())?;
        std::fs::write(
            directory.path().join("current-recovery-receipt-signer"),
            b"1",
        )?;
        std::fs::remove_file(directory.path().join("original-recovery-receipt-signer"))?;
        eprintln!("historical signer phase: {point} current signer open");
        let fixture = Box::new(RecoveryFixture::open(
            directory.path().to_path_buf(),
            None,
            false,
        )?);
        let current_signer = fixture.kernel.receipt_signing_public_key();
        assert_ne!(current_signer, original_signer);
        let store = fixture.authority.admission_operation_store();
        let terminal = store
            .load_by_operation_id(&operation_id)?
            .ok_or("captured terminal")?;
        assert_eq!(
            terminal.state(),
            AdmissionOperationState::Completed,
            "{point}: current authority left the authenticated external effect unfinished"
        );
        assert_eq!(terminal.binding().to_persisted(), intent.native_binding);
        let private = store.inspect_captured_workflow_terminal_for_test(
            fixture.runtime.scope(),
            &before.workflow_id,
        )?;
        assert!(private.captured && private.admission_closed, "{point}");
        assert!(
            private.historical_hold.is_none(),
            "{point}: permanent signing debt"
        );
        assert!(matches!(
            private.effect,
            EffectObservationV1::Complete { .. }
        ));
        assert!(matches!(
            private.release,
            ReleaseDispositionV1::Withheld { .. }
        ));
        assert_eq!(
            chio_core::canonical_json_bytes(&retained_workflow(&fixture.path)?)?,
            physical_before,
            "{point}: rotated settlement changed the captured workflow"
        );
        assert_eq!(captured_return_bytes(&fixture.path, &before)?.1, raw_before);
        let receipt_id = match terminal.terminal_replay() {
            Some(AdmissionTerminalReplay::Receipt { receipt_id, .. }) => receipt_id,
            _ => return Err("rotated settlement terminal receipt absent".into()),
        };
        let receipt = store
            .load_chio_receipt(receipt_id.as_str())?
            .ok_or("rotated terminal receipt")?;
        assert_eq!(receipt.kernel_key, current_signer);
        assert_eq!(
            receipt.policy_hash,
            intent.native_binding.policy_hash.as_str()
        );
        assert!(receipt.verify_signature_with_floor(
            chio_core::receipt::crypto_floor::ReceiptCryptoFloor::PqRequired,
        )?);
        let settlement = receipt
            .metadata
            .as_ref()
            .and_then(|metadata| {
                metadata.get(chio_kernel::tool_outcome::PRIVATE_RECOVERY_SETTLEMENT_METADATA_KEY)
            })
            .ok_or("distinct signed private settlement attestation")?;
        assert_eq!(settlement["disposition"], "permanently_withheld");
        assert_eq!(
            settlement["original_signing_identity"]["public_key"],
            serde_json::to_value(&original_signer)?
        );
        assert_eq!(
            settlement["settlement_signing_identity"]["public_key"],
            serde_json::to_value(&current_signer)?
        );
        assert_eq!(
            settlement["raw_output_digest"],
            chio_core::sha256_hex(&raw_before)
        );
        assert_eq!(
            settlement["captured_deployment_digest"],
            serde_json::to_value(before.deployment_digest)?
        );
        let actor = fixture.kernel.authenticate_recovery_actor(
            fixture.runtime.scope(),
            &fixture.control,
            RecoveryPermission::Inspect,
        )?;
        assert!(fixture
            .kernel
            .replay_recovery_result(&actor, &before.workflow_id)
            .is_err());
        assert_eq!(
            external_count(&fixture.path)?,
            1,
            "{point}: duplicate original effect"
        );
        assert_eq!(
            fixture.process.process("root")?.tree_calls,
            2,
            "{point}: duplicate charge"
        );
        let terminal_bytes = native_original_bytes(&fixture.path, &before)?;
        let events = recovery_event_count(&fixture.path)?;
        for _ in 0..2 {
            fixture.kernel.reconcile_durable_admission_startup()?;
            fixture
                .runtime
                .settle(&fixture.control, &before.workflow_id)?;
        }
        assert_eq!(
            native_original_bytes(&fixture.path, &before)?,
            terminal_bytes
        );
        assert_eq!(recovery_event_count(&fixture.path)?, events);
        drop(store);
        drop(fixture);
        eprintln!("historical signer phase: {point} terminal reopen");
        let reopened = Box::new(RecoveryFixture::open(
            directory.path().to_path_buf(),
            None,
            false,
        )?);
        assert_eq!(
            native_original_bytes(&reopened.path, &before)?,
            terminal_bytes
        );
        assert_eq!(
            captured_return_bytes(&reopened.path, &before)?.1,
            raw_before
        );
        assert_eq!(external_count(&reopened.path)?, 1);
        // New guarded work uses the installed signing authority, while the old
        // operation remains terminal and its original effect remains singular.
        let fresh_id =
            Box::pin(reopened.ready_named("after-signer-rotation", "current-signer")).await?;
        let fresh = reopened.record(&fresh_id)?;
        let delivered = Box::pin(reopened.execute(
            "current-signer-resume",
            RecoveryCommandBodyV1::ResumeWorkflow {
                workflow_id: fresh_id,
                expected_revision: fresh.revision,
            },
        ))
        .await?;
        let fresh_response = delivered
            .original_response
            .ok_or("fresh current-authority response")?;
        assert_eq!(
            fresh_response.receipt.decision,
            Some(chio_core::receipt::decision::Decision::Allow)
        );
        assert!(
            fresh_response.result.is_some(),
            "{point}: fresh guarded output withheld"
        );
        assert_eq!(fresh_response.receipt.kernel_key, current_signer);
        assert_eq!(external_count(&reopened.path)?, 2);
        assert_eq!(reopened.process.process("root")?.tree_calls, 4);
        assert_eq!(
            native_original_bytes(&reopened.path, &before)?,
            terminal_bytes
        );
        let effects = rusqlite::Connection::open(&reopened.path.join("effects.db"))?;
        let old_effects: i64 = effects.query_row(
            "SELECT count(*) FROM effects WHERE operation=?1",
            [operation_id.as_str()],
            |row| row.get(0),
        )?;
        assert_eq!(
            old_effects, 1,
            "{point}: original repeated during future guarded work"
        );
    }
    Ok(())
}

#[cfg(all(unix, feature = "pq"))]
#[tokio::test]
async fn recovery_previously_held_signer_rotation_reaches_authenticated_withheld_terminal(
) -> TestResult {
    use chio_kernel::admission_operation::{AdmissionOperationId, AdmissionTerminalReplay};
    use chio_kernel::ReceiptStore;
    let directory = Box::pin(crash_after_capture_with_original_receipt_signer(
        "return-recorded",
    ))
    .await?;
    let before = retained_workflow(directory.path())?;
    let raw_before = captured_return_bytes(directory.path(), &before)?.1;
    let original_signer = captured_receipt_signer(directory.path(), &before)?;
    let intent = before
        .admission
        .as_ref()
        .ok_or("historical signer original")?;
    let operation_id = AdmissionOperationId::from_persisted(intent.native_operation_id.as_str())?;
    let quota_before;
    {
        // Reproduce the earlier qualified runtime's signer-only hold through
        // its owning fenced API, over this genuine immutable native capture.
        let authority = SqliteAuthorityStore::open_serving(
            directory.path().join("admission.db"),
            directory.path().join("locks"),
        )?;
        authority
            .admission_operation_store()
            .recovery_authority()
            .ok_or("historical signer authority")?
            .quarantine_historical(
                &operation_id,
                RecoveryHistoricalHoldReasonV1::FrozenSigningCustodyUnavailable,
                &authority.mutation_fence(),
                now_ms()?,
            )?;
        quota_before = retained_workflow_quota_bytes(directory.path(), &before)?;
    }
    let old_quota: serde_json::Value = serde_json::from_slice(&quota_before.1)?;
    let old_hold = old_quota
        .get("native_hold")
        .cloned()
        .ok_or("authentic retained signer hold")?;
    let database = rusqlite::Connection::open(directory.path().join("admission.db"))?;
    let old_hold_audit_digest: String = database.query_row(
        "SELECT e.record_digest FROM admission_operation_recovery_events e
         JOIN admission_operation_recovery_records r
         ON e.record_key=r.record_key AND e.record_version=r.version
         WHERE r.record_key GLOB 'workflow-quota:*' AND r.payload=?1",
        [&quota_before.1],
        |row| row.get(0),
    )?;
    let old_hold_events = database.query_row(
        "SELECT count(*) FROM admission_operation_recovery_events WHERE record_digest=?1",
        [&old_hold_audit_digest],
        |row| row.get::<_, i64>(0),
    )?;
    drop(database);
    assert_eq!(old_hold_events, 1);
    std::fs::write(
        directory.path().join("current-recovery-receipt-signer"),
        b"1",
    )?;
    std::fs::remove_file(directory.path().join("original-recovery-receipt-signer"))?;
    let fixture = Box::new(RecoveryFixture::open(
        directory.path().to_path_buf(),
        None,
        false,
    )?);
    assert_ne!(fixture.kernel.receipt_signing_public_key(), original_signer);
    let store = fixture.authority.admission_operation_store();
    let native = store
        .load_by_operation_id(&operation_id)?
        .ok_or("settled previously held original")?;
    assert_eq!(native.state(), AdmissionOperationState::Completed);
    assert_eq!(native.binding().to_persisted(), intent.native_binding);
    let settled = fixture.record(&before.workflow_id)?;
    assert!(settled.captured && settled.admission_closed);
    assert_eq!(settled.control, WorkflowControlV1::Active);
    assert!(settled.historical_hold.is_none());
    assert!(matches!(
        settled.effect,
        EffectObservationV1::Complete { .. }
    ));
    assert!(matches!(
        settled.release,
        ReleaseDispositionV1::Withheld { .. }
    ));
    assert_eq!(captured_return_bytes(&fixture.path, &before)?.1, raw_before);
    assert_eq!(
        chio_core::canonical_json_bytes(&retained_workflow(&fixture.path)?)?,
        chio_core::canonical_json_bytes(&before)?
    );
    let quota_after: serde_json::Value =
        serde_json::from_slice(&retained_workflow_quota_bytes(&fixture.path, &before)?.1)?;
    assert_eq!(quota_after.get("native_hold"), Some(&old_hold));
    assert_eq!(
        rusqlite::Connection::open(fixture.path.join("admission.db"))?.query_row(
            "SELECT count(*) FROM admission_operation_recovery_events WHERE record_digest=?1",
            [&old_hold_audit_digest],
            |row| row.get::<_, i64>(0),
        )?,
        1,
        "old signer hold audit event changed"
    );
    let receipt_id = match native.terminal_replay() {
        Some(AdmissionTerminalReplay::Receipt { receipt_id, .. }) => receipt_id,
        _ => return Err("held original private terminal receipt absent".into()),
    };
    let receipt = store
        .load_chio_receipt(receipt_id.as_str())?
        .ok_or("held original settlement receipt")?;
    assert_eq!(
        receipt.kernel_key,
        fixture.kernel.receipt_signing_public_key()
    );
    assert!(receipt.verify_signature_with_floor(
        chio_core::receipt::crypto_floor::ReceiptCryptoFloor::PqRequired
    )?);
    let marker = receipt
        .metadata
        .as_ref()
        .and_then(|metadata| {
            metadata.get(chio_kernel::tool_outcome::PRIVATE_RECOVERY_SETTLEMENT_METADATA_KEY)
        })
        .ok_or("held settlement attestation")?;
    assert_eq!(marker["historical_signing_hold"], old_hold["hold"]);
    assert_eq!(
        marker["original_signing_identity"]["public_key"],
        serde_json::to_value(original_signer)?
    );
    let events = recovery_event_count(&fixture.path)?;
    let terminal_bytes = native_original_bytes(&fixture.path, &before)?;
    for _ in 0..2 {
        fixture
            .runtime
            .settle(&fixture.control, &before.workflow_id)?;
        fixture.kernel.reconcile_recoverable_admissions()?;
    }
    assert_eq!(recovery_event_count(&fixture.path)?, events);
    assert_eq!(external_count(&fixture.path)?, 1);
    assert_eq!(fixture.process.process("root")?.tree_calls, 2);
    let actor = fixture.kernel.authenticate_recovery_actor(
        fixture.runtime.scope(),
        &fixture.control,
        RecoveryPermission::Inspect,
    )?;
    assert!(fixture
        .kernel
        .replay_recovery_result(&actor, &before.workflow_id)
        .is_err());
    drop(store);
    drop(fixture);
    let reopened = Box::new(RecoveryFixture::open(
        directory.path().to_path_buf(),
        None,
        false,
    )?);
    assert_eq!(
        native_original_bytes(&reopened.path, &before)?,
        terminal_bytes
    );
    assert!(reopened.record(&before.workflow_id)?.admission_closed);
    assert_eq!(recovery_event_count(&reopened.path)?, events);
    assert_eq!(external_count(&reopened.path)?, 1);
    Ok(())
}

#[cfg(all(unix, feature = "pq"))]
#[tokio::test]
async fn recovery_rotated_signer_preserves_digest_denial_and_settles_known_private_return(
) -> TestResult {
    use chio_kernel::admission_operation::{
        AdmissionOperationId, AdmissionReceiptMetadataV1, AdmissionTerminalReplay,
    };
    use chio_kernel::ReceiptStore;
    for previously_held in [false, true] {
        let directory = Box::pin(crash_after_digest_rejection_with_original_receipt_signer(
            "return-recorded",
        ))
        .await?;
        let before = retained_workflow(directory.path())?;
        let raw_before = captured_return_bytes(directory.path(), &before)?.1;
        let original_signer = captured_receipt_signer(directory.path(), &before)?;
        let intent = before.admission.as_ref().ok_or("digest denial original")?;
        let operation_id =
            AdmissionOperationId::from_persisted(intent.native_operation_id.as_str())?;
        let retained_hold = if previously_held {
            // The previous release wrote this hold through its owning fenced
            // authority. Preserve its immutable audit record during settlement.
            let authority = SqliteAuthorityStore::open_serving(
                directory.path().join("admission.db"),
                directory.path().join("locks"),
            )?;
            authority
                .admission_operation_store()
                .recovery_authority()
                .ok_or("digest denial historical authority")?
                .quarantine_historical(
                    &operation_id,
                    RecoveryHistoricalHoldReasonV1::FrozenSigningCustodyUnavailable,
                    &authority.mutation_fence(),
                    now_ms()?,
                )?;
            let quota = retained_workflow_quota_bytes(directory.path(), &before)?.1;
            let value: serde_json::Value = serde_json::from_slice(&quota)?;
            let audit_digest: String =
                rusqlite::Connection::open(directory.path().join("admission.db"))?.query_row(
                    "SELECT e.record_digest FROM admission_operation_recovery_events e
                     JOIN admission_operation_recovery_records r
                     ON e.record_key=r.record_key AND e.record_version=r.version
                     WHERE r.record_key GLOB 'workflow-quota:*' AND r.payload=?1",
                    [&quota],
                    |row| row.get(0),
                )?;
            Some((
                value
                    .get("native_hold")
                    .cloned()
                    .ok_or("retained signer hold")?,
                audit_digest,
            ))
        } else {
            None
        };
        std::fs::write(
            directory.path().join("current-recovery-receipt-signer"),
            b"1",
        )?;
        std::fs::remove_file(directory.path().join("original-recovery-receipt-signer"))?;
        let fixture = Box::new(RecoveryFixture::open(
            directory.path().to_path_buf(),
            None,
            false,
        )?);
        let current_signer = fixture.kernel.receipt_signing_public_key();
        assert_ne!(current_signer, original_signer);
        let store = fixture.authority.admission_operation_store();
        let terminal = store
            .load_by_operation_id(&operation_id)?
            .ok_or("rotated digest denial terminal")?;
        assert_eq!(
            terminal.state(),
            AdmissionOperationState::DeniedAfterDelivery
        );
        assert_eq!(terminal.binding().to_persisted(), intent.native_binding);
        let settled = fixture.record(&before.workflow_id)?;
        assert!(settled.captured && settled.admission_closed);
        assert!(settled.historical_hold.is_none());
        assert!(matches!(
            settled.effect,
            EffectObservationV1::Complete { .. }
        ));
        assert!(matches!(
            settled.release,
            ReleaseDispositionV1::Withheld { .. }
        ));
        assert_eq!(
            chio_core::canonical_json_bytes(&retained_workflow(&fixture.path)?)?,
            chio_core::canonical_json_bytes(&before)?
        );
        assert_eq!(captured_return_bytes(&fixture.path, &before)?.1, raw_before);
        let receipt_id = match terminal.terminal_replay() {
            Some(AdmissionTerminalReplay::Receipt { receipt_id, .. }) => receipt_id,
            _ => return Err("digest denial terminal receipt absent".into()),
        };
        let receipt = store
            .load_chio_receipt(receipt_id.as_str())?
            .ok_or("digest denial private receipt")?;
        assert_eq!(receipt.kernel_key, current_signer);
        assert!(matches!(
            receipt.decision,
            Some(chio_core::receipt::decision::Decision::Deny { .. })
        ));
        let expected_digest = chio_core::sha256_hex(b"an output the provider will never return");
        let mut redacted_preimage = b"chio.delivery-mismatch.redacted.v1\0".to_vec();
        redacted_preimage.extend_from_slice(expected_digest.as_bytes());
        assert_eq!(
            receipt.content_hash,
            chio_core::sha256_hex(&redacted_preimage)
        );
        assert_ne!(receipt.content_hash, chio_core::sha256_hex(&raw_before));
        assert!(receipt.verify_signature_with_floor(
            chio_core::receipt::crypto_floor::ReceiptCryptoFloor::PqRequired
        )?);
        let metadata = receipt.metadata.as_ref().ok_or("digest denial metadata")?;
        let native_metadata: AdmissionReceiptMetadataV1 = serde_json::from_value(
            metadata[chio_kernel::admission_operation::ADMISSION_RECEIPT_METADATA_KEY].clone(),
        )?;
        assert_eq!(
            native_metadata.projected_state,
            AdmissionOperationState::DeniedAfterDelivery
        );
        assert!(native_metadata.tool_outcome_id.is_none());
        assert!(native_metadata.tool_outcome_version.is_none());
        let marker = metadata
            .get(chio_kernel::tool_outcome::PRIVATE_RECOVERY_SETTLEMENT_METADATA_KEY)
            .ok_or("digest denial private attestation")?;
        assert_eq!(marker["disposition"], "permanently_withheld");
        assert_eq!(
            marker["raw_output_digest"],
            chio_core::sha256_hex(&raw_before)
        );
        assert_eq!(
            marker["original_signing_identity"]["public_key"],
            serde_json::to_value(&original_signer)?
        );
        assert_eq!(
            marker["settlement_signing_identity"]["public_key"],
            serde_json::to_value(&current_signer)?
        );
        assert_eq!(
            marker["captured_deployment_digest"],
            serde_json::to_value(before.deployment_digest)?
        );
        let database = rusqlite::Connection::open(fixture.path.join("admission.db"))?;
        let projection: Vec<u8> = database.query_row(
            "SELECT projection_json FROM admission_operation_terminal_projections WHERE operation_id=?1",
            [operation_id.as_str()], |row| row.get(0),
        )?;
        let projection: serde_json::Value = serde_json::from_slice(&projection)?;
        assert_eq!(projection["terminal"], "denied_after_delivery");
        assert_eq!(projection["reason"], "digest_mismatch");
        if let Some((old_hold, audit_digest)) = &retained_hold {
            assert_eq!(marker["historical_signing_hold"], old_hold["hold"]);
            let quota: serde_json::Value =
                serde_json::from_slice(&retained_workflow_quota_bytes(&fixture.path, &before)?.1)?;
            assert_eq!(quota.get("native_hold"), Some(old_hold));
            let events: i64 = database.query_row(
                "SELECT count(*) FROM admission_operation_recovery_events WHERE record_digest=?1",
                [audit_digest],
                |row| row.get(0),
            )?;
            assert_eq!(events, 1);
        } else {
            assert!(marker["historical_signing_hold"].is_null());
        }
        let actor = fixture.kernel.authenticate_recovery_actor(
            fixture.runtime.scope(),
            &fixture.control,
            RecoveryPermission::Inspect,
        )?;
        assert!(fixture
            .kernel
            .replay_recovery_result(&actor, &before.workflow_id)
            .is_err());
        let terminal_bytes = native_original_bytes(&fixture.path, &before)?;
        let events = recovery_event_count(&fixture.path)?;
        for _ in 0..2 {
            fixture.kernel.reconcile_durable_admission_startup()?;
            fixture
                .runtime
                .settle(&fixture.control, &before.workflow_id)?;
        }
        assert_eq!(
            native_original_bytes(&fixture.path, &before)?,
            terminal_bytes
        );
        assert_eq!(recovery_event_count(&fixture.path)?, events);
        assert_eq!(external_count(&fixture.path)?, 1);
        assert_eq!(fixture.process.process("root")?.tree_calls, 2);
        drop(database);
        drop(store);
        drop(fixture);
        let reopened = Box::new(RecoveryFixture::open(
            directory.path().to_path_buf(),
            None,
            false,
        )?);
        assert_eq!(
            native_original_bytes(&reopened.path, &before)?,
            terminal_bytes
        );
        assert!(reopened.record(&before.workflow_id)?.admission_closed);
        let fresh_id =
            Box::pin(reopened.ready_named("after-digest-denial", "current-denial")).await?;
        let fresh = reopened.record(&fresh_id)?;
        let delivered = Box::pin(reopened.execute(
            "current-denial-resume",
            RecoveryCommandBodyV1::ResumeWorkflow {
                workflow_id: fresh_id,
                expected_revision: fresh.revision,
            },
        ))
        .await?;
        assert!(delivered.original_response.is_none());
        assert!(matches!(
            delivered.status.effect,
            EffectObservationV1::Unknown { .. }
        ));
        let fresh = reopened.record(&delivered.status.workflow_id)?;
        let fresh_intent = fresh.admission.as_ref().ok_or("fresh denial intent")?;
        let fresh_operation = reopened
            .authority
            .admission_operation_store()
            .load_by_operation_id(&AdmissionOperationId::from_persisted(
                fresh_intent.native_operation_id.as_str(),
            )?)?
            .ok_or("fresh denial operation")?;
        assert_eq!(
            fresh_operation.state(),
            AdmissionOperationState::DeniedAfterDelivery
        );
        let fresh_receipt_id = match fresh_operation.terminal_replay() {
            Some(AdmissionTerminalReplay::Receipt { receipt_id, .. }) => receipt_id,
            _ => return Err("fresh denial receipt absent".into()),
        };
        let fresh_receipt = reopened
            .authority
            .admission_operation_store()
            .load_chio_receipt(fresh_receipt_id.as_str())?
            .ok_or("fresh current denial receipt")?;
        assert!(matches!(
            fresh_receipt.decision,
            Some(chio_core::receipt::decision::Decision::Deny { .. })
        ));
        assert_eq!(fresh_receipt.kernel_key, current_signer);
        assert!(fresh_receipt
            .metadata
            .as_ref()
            .is_none_or(|metadata| metadata
                .get(chio_kernel::tool_outcome::PRIVATE_RECOVERY_SETTLEMENT_METADATA_KEY)
                .is_none()));
        assert_eq!(external_count(&reopened.path)?, 2);
        assert_eq!(reopened.process.process("root")?.tree_calls, 4);
        assert_eq!(
            native_original_bytes(&reopened.path, &before)?,
            terminal_bytes
        );
        let effects = rusqlite::Connection::open(reopened.path.join("effects.db"))?;
        let old_effects: i64 = effects.query_row(
            "SELECT count(*) FROM effects WHERE operation=?1",
            [operation_id.as_str()],
            |row| row.get(0),
        )?;
        assert_eq!(old_effects, 1);
    }
    Ok(())
}

#[cfg(all(unix, feature = "pq"))]
#[tokio::test]
async fn recovery_signer_rotation_rejects_corrupt_original_return_without_hold() -> TestResult {
    for fault in [
        "missing-identity",
        "schema-downgrade",
        "hash-changed",
        "held-hash-changed",
    ] {
        let directory = Box::pin(crash_after_capture("return-recorded")).await?;
        let before = retained_workflow(directory.path())?;
        if fault == "held-hash-changed" {
            let authority = SqliteAuthorityStore::open_serving(
                directory.path().join("admission.db"),
                directory.path().join("locks"),
            )?;
            let id = chio_kernel::admission_operation::AdmissionOperationId::from_persisted(
                before
                    .admission
                    .as_ref()
                    .ok_or("corrupted held original")?
                    .native_operation_id
                    .as_str(),
            )?;
            authority
                .admission_operation_store()
                .recovery_authority()
                .ok_or("corrupted held original authority")?
                .quarantine_historical(
                    &id,
                    RecoveryHistoricalHoldReasonV1::FrozenSigningCustodyUnavailable,
                    &authority.mutation_fence(),
                    now_ms()?,
                )?;
        }
        let physical_before = retained_workflow(directory.path())?;
        let quota_before = retained_workflow_quota_bytes(directory.path(), &before)?;
        let native_before = native_original_bytes(directory.path(), &before)?;
        let (outcome_before, raw_before) = captured_return_bytes(directory.path(), &before)?;
        let mut raw: serde_json::Value = serde_json::from_slice(&raw_before)?;
        assert_eq!(
            raw.get("schema").and_then(serde_json::Value::as_str),
            Some(chio_kernel::tool_outcome::RAW_INVOCATION_OUTCOME_WITH_SIGNING_IDENTITY_SCHEMA)
        );
        let fields = raw.as_object_mut().ok_or("captured raw object")?;
        match fault {
            "missing-identity" => {
                fields.remove("receipt_signing_identity");
            }
            "schema-downgrade" => {
                fields.remove("receipt_signing_identity");
                fields.insert(
                    "schema".into(),
                    serde_json::json!(
                        chio_kernel::tool_outcome::RAW_INVOCATION_OUTCOME_WITH_SECURITY_RELEASE_SCHEMA
                    ),
                );
            }
            "hash-changed" | "held-hash-changed" => {
                let elapsed = fields
                    .get("elapsed_millis")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or("captured elapsed time")?;
                fields.insert(
                    "elapsed_millis".into(),
                    serde_json::json!(if elapsed == 0 { 1 } else { elapsed - 1 }),
                );
            }
            _ => return Err("unknown signing return fault".into()),
        }
        let corrupted = chio_core::canonical_json_bytes(&raw)?;
        let decoded =
            chio_kernel::tool_outcome::RawInvocationOutcomeV1::from_canonical_bytes(&corrupted);
        assert_eq!(decoded.is_err(), fault == "missing-identity");
        let id = &before
            .admission
            .as_ref()
            .ok_or("signing fault original admission")?
            .native_operation_id;
        // Inject only into a disposable native capture, then restore the exact
        // trigger inventory. This fault never changes original outcome anchors.
        let db = rusqlite::Connection::open(directory.path().join("admission.db"))?;
        db.execute_batch("DROP TRIGGER tool_outcome_blobs_immutable;")?;
        assert_eq!(
            db.execute(
                "UPDATE tool_outcome_blobs SET canonical_bytes=?1,blob_size_bytes=?2
                 WHERE digest=(SELECT raw_output_digest FROM tool_outcomes WHERE operation_id=?3)",
                rusqlite::params![&corrupted, i64::try_from(corrupted.len())?, id.as_str()],
            )?,
            1
        );
        db.execute_batch(include_str!(
            "../../../../chio-store-sqlite/src/tool_outcome_store.sql"
        ))?;
        drop(db);
        std::fs::write(
            directory.path().join("current-recovery-receipt-signer"),
            b"1",
        )?;
        assert!(
            RecoveryFixture::open(directory.path().to_path_buf(), None, false).is_err(),
            "{fault}: corrupted return became a signer-rotation hold"
        );
        let after = retained_workflow(directory.path())?;
        assert_eq!(
            chio_core::canonical_json_bytes(&after)?,
            chio_core::canonical_json_bytes(&physical_before)?
        );
        assert_eq!(after.historical_hold, physical_before.historical_hold);
        assert_eq!(
            retained_workflow_quota_bytes(directory.path(), &after)?,
            quota_before,
            "{fault}: corrupted return changed authenticated auxiliary custody"
        );
        assert_eq!(
            native_original_bytes(directory.path(), &after)?,
            native_before
        );
        let (outcome_after, raw_after) = captured_return_bytes(directory.path(), &after)?;
        assert_eq!(outcome_after, outcome_before);
        assert_eq!(raw_after, corrupted);
        assert_eq!(external_count(directory.path())?, 1);
    }
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn recovery_unavailable_current_classifier_withholds_without_blocking_settlement(
) -> TestResult {
    let directory = Box::pin(crash_after_capture("return-recorded")).await?;
    let before = retained_workflow(directory.path())?;
    let raw_before = captured_return_bytes(directory.path(), &before)?.1;
    std::fs::write(
        directory
            .path()
            .join("current-recovery-classifier-unavailable"),
        b"unavailable",
    )?;
    let f = Box::new(RecoveryFixture::open(
        directory.path().to_path_buf(),
        None,
        false,
    )?);
    let intent = before
        .admission
        .as_ref()
        .ok_or("classifier original admission")?;
    let native = f
        .authority
        .admission_operation_store()
        .load_by_operation_id(
            &chio_kernel::admission_operation::AdmissionOperationId::from_persisted(
                intent.native_operation_id.as_str(),
            )?,
        )?
        .ok_or("classifier physical original")?;
    let physical = retained_workflow(&f.path)?;
    assert_eq!(
        chio_core::canonical_json_bytes(&physical)?,
        chio_core::canonical_json_bytes(&before)?,
        "private terminal custody rewrote the captured workflow"
    );
    let private = f
        .authority
        .admission_operation_store()
        .inspect_captured_workflow_terminal_for_test(f.runtime.scope(), &before.workflow_id)?;
    let observed = f.kernel.observe_recovery_source(f.runtime.scope())?;
    let current = observed.snapshot().ok_or("classifier current source")?;
    let actor = f.kernel.authenticate_recovery_actor(
        f.runtime.scope(),
        &f.control,
        RecoveryPermission::Settle,
    );
    let public_read = match &actor {
        Ok(actor) => f.kernel.read_recovery_workflow(actor, &before.workflow_id),
        Err(_) => Err(KernelError::RecoveryAuthorityDenied),
    };
    let public_settle = f.runtime.settle(&f.control, &before.workflow_id);
    eprintln!(
        "unavailable classifier finality phases: {}",
        serde_json::json!({
            "native_state": format!("{:?}", native.state()),
            "native_binding_unchanged": native.binding().to_persisted() == intent.native_binding,
            "private_workflow_effect": format!("{:?}", private.effect),
            "private_admission_closed": private.admission_closed,
            "private_hold_present": private.historical_hold.is_some(),
            "private_control": format!("{:?}", private.control),
            "current_principal_top": matches!(&current.principal_label, InformationLabel::Top),
            "current_lineage_top": matches!(&current.lineage_label, InformationLabel::Top),
            "current_session_top": matches!(&current.session_label, InformationLabel::Top),
            "current_actor_authenticated": actor.is_ok(),
            "actor_authentication_error": actor.as_ref().err().map(ToString::to_string),
            "public_read_error": public_read.as_ref().err().map(ToString::to_string),
            "public_settle_error": public_settle.as_ref().err().map(ToString::to_string),
            "effect_count": external_count(&f.path)?,
            "tree_calls": f.process.process("root")?.tree_calls,
        })
    );
    assert_eq!(native.state(), AdmissionOperationState::Completed);
    assert_eq!(native.binding().to_persisted(), intent.native_binding);
    require_original_terminal_receipt(&f, &before)?;
    assert_eq!(captured_return_bytes(&f.path, &before)?.1, raw_before);
    assert_eq!(external_count(&f.path)?, 1);
    assert_eq!(f.process.process("root")?.tree_calls, 2);
    assert!(actor.is_ok());
    assert!(matches!(&current.principal_label, InformationLabel::Top));
    assert!(matches!(&current.lineage_label, InformationLabel::Top));
    assert!(matches!(&current.session_label, InformationLabel::Top));
    assert!(
        matches!(private.effect, EffectObservationV1::Complete { .. }),
        "current audience refusal blocked private captured workflow finality"
    );
    assert!(matches!(
        public_read,
        Err(KernelError::RecoveryAuthorityDenied)
    ));
    assert!(matches!(
        public_settle,
        Err(RecoveryRuntimeError::AuthorityDenied)
    ));
    let settled = private;
    assert!(settled.admission_closed);
    assert_eq!(settled.control, WorkflowControlV1::Active);
    assert!(settled.historical_hold.is_none());
    assert!(matches!(
        settled.release,
        ReleaseDispositionV1::Withheld { .. }
    ));
    let actor = f.kernel.authenticate_recovery_actor(
        f.runtime.scope(),
        &f.control,
        RecoveryPermission::Inspect,
    )?;
    assert!(f
        .kernel
        .replay_recovery_result(&actor, &before.workflow_id)
        .is_err());
    assert_eq!(external_count(&f.path)?, 1);
    assert_eq!(f.process.process("root")?.tree_calls, 2);
    let events = recovery_event_count(&f.path)?;
    drop(f);
    let reopened = Box::new(RecoveryFixture::open(
        directory.path().to_path_buf(),
        None,
        false,
    )?);
    let effective = reopened
        .authority
        .admission_operation_store()
        .inspect_captured_workflow_terminal_for_test(
            reopened.runtime.scope(),
            &before.workflow_id,
        )?;
    assert!(matches!(
        effective.effect,
        EffectObservationV1::Complete { .. }
    ));
    assert!(effective.admission_closed);
    assert!(matches!(
        reopened
            .runtime
            .settle(&reopened.control, &before.workflow_id),
        Err(RecoveryRuntimeError::AuthorityDenied)
    ));
    assert_eq!(
        chio_core::canonical_json_bytes(&retained_workflow(&reopened.path)?)?,
        chio_core::canonical_json_bytes(&before)?
    );
    assert_eq!(recovery_event_count(&reopened.path)?, events);
    assert_eq!(external_count(&reopened.path)?, 1);
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn recovery_unavailable_frozen_output_verifier_is_durably_quarantined() -> TestResult {
    for marker in [
        "current-recovery-post-return-hook",
        "current-recovery-post-return-unavailable",
    ] {
        let directory = Box::pin(crash_after_capture("return-recorded")).await?;
        let before = retained_workflow(directory.path())?;
        let native_before = native_original_bytes(directory.path(), &before)?;
        std::fs::write(directory.path().join(marker), b"current")?;
        let f = Box::new(RecoveryFixture::open(directory.path().to_path_buf(), None, false)
            .map_err(|error| format!("{marker}: unavailable original verifier blocked unrelated serving: {error}"))?);
        let held = f.record(&before.workflow_id)?;
        let hold = held
            .historical_hold
            .as_ref()
            .ok_or("durable historical hold")?;
        assert_eq!(held.control, WorkflowControlV1::Quarantined);
        assert_eq!(
            hold.reason,
            RecoveryHistoricalHoldReasonV1::FrozenOutputVerifierUnavailable
        );
        assert_eq!(
            hold.operation.operation_id(),
            &before
                .admission
                .as_ref()
                .ok_or("native original")?
                .native_operation_id
        );
        assert!(held.captured);
        assert!(!held.admission_closed);
        assert_eq!(native_before, native_original_bytes(&f.path, &held)?);
        assert_eq!(
            chio_core::canonical_json_bytes(&before.envelope)?,
            chio_core::canonical_json_bytes(&held.envelope)?
        );
        f.runtime.settle(&f.control, &held.workflow_id)?;
        let events = recovery_event_count(&f.path)?;
        for _ in 0..3 {
            let status = f.runtime.settle(&f.control, &held.workflow_id)?;
            assert_eq!(status.control, WorkflowControlV1::Quarantined);
            assert!(!status.effect.is_settled());
        }
        assert_eq!(
            events,
            recovery_event_count(&f.path)?,
            "repeated hold consumed new native slots"
        );
        let current = f.record(&held.workflow_id)?;
        assert!(
            f.execute(
                "held-original-resume",
                RecoveryCommandBodyV1::ResumeWorkflow {
                    workflow_id: held.workflow_id.clone(),
                    expected_revision: current.revision,
                }
            )
            .await
            .is_err(),
            "quarantined custody reopened a continuation"
        );
        let actor = f.kernel.authenticate_recovery_actor(
            f.runtime.scope(),
            &f.control,
            RecoveryPermission::Inspect,
        )?;
        assert!(f
            .kernel
            .replay_recovery_result(&actor, &held.workflow_id)
            .is_err());
        assert_eq!(external_count(&f.path)?, 1);
        assert_eq!(f.process.process("root")?.tree_calls, 2);
        drop(f);
        let reopened = Box::new(RecoveryFixture::open(
            directory.path().to_path_buf(),
            None,
            false,
        )?);
        assert_eq!(
            reopened.record(&held.workflow_id)?.control,
            WorkflowControlV1::Quarantined
        );
        assert_eq!(events, recovery_event_count(&reopened.path)?);
        assert_eq!(native_before, native_original_bytes(&reopened.path, &held)?);
        assert_eq!(external_count(&reopened.path)?, 1);
        if marker == "current-recovery-post-return-hook" {
            let fresh_id =
                Box::pin(reopened.ready_named("after-frozen-verifier-hold", "current-verifier"))
                    .await?;
            let fresh = reopened.record(&fresh_id)?;
            let delivered = Box::pin(reopened.execute(
                "current-verifier-resume",
                RecoveryCommandBodyV1::ResumeWorkflow {
                    workflow_id: fresh_id,
                    expected_revision: fresh.revision,
                },
            ))
            .await?;
            let response = delivered
                .original_response
                .ok_or("unrelated current-verifier response")?;
            assert_eq!(
                response.receipt.decision,
                Some(chio_core::receipt::decision::Decision::Allow)
            );
            assert!(response.result.is_some());
            assert_eq!(external_count(&reopened.path)?, 2);
            assert_eq!(reopened.process.process("root")?.tree_calls, 4);
        } else {
            // Current unavailable output verification cannot authorize a fresh
            // effect. A genuine unrelated durable input denial still completes.
            Box::pin(reopened.denied_seed_named("after-unavailable-verifier-hold")).await?;
            assert_eq!(external_count(&reopened.path)?, 1);
            assert_eq!(reopened.process.process("root")?.tree_calls, 3);
        }
        let current_hold = reopened.record(&held.workflow_id)?;
        assert_eq!(current_hold.control, WorkflowControlV1::Quarantined);
        assert_eq!(current_hold.historical_hold, held.historical_hold);
        assert!(!current_hold.admission_closed);
        assert_eq!(native_before, native_original_bytes(&reopened.path, &held)?);
        let events = recovery_event_count(&reopened.path)?;
        reopened.kernel.reconcile_durable_admission_startup()?;
        reopened
            .runtime
            .settle(&reopened.control, &held.workflow_id)?;
        assert_eq!(events, recovery_event_count(&reopened.path)?);
        let operation_id = held
            .admission
            .as_ref()
            .ok_or("held original intent")?
            .native_operation_id
            .as_str();
        let old_effects: i64 = rusqlite::Connection::open(reopened.path.join("effects.db"))?
            .query_row(
                "SELECT count(*) FROM effects WHERE operation=?1",
                [operation_id],
                |row| row.get(0),
            )?;
        assert_eq!(old_effects, 1);
    }
    Ok(())
}

#[tokio::test]
async fn recovery_current_actor_revocation_during_classification_refuses_output() -> TestResult {
    let directory = tempfile::tempdir()?;
    let f = Box::new(RecoveryFixture::open(
        directory.path().to_path_buf(),
        None,
        false,
    )?);
    let id = Box::pin(f.ready()).await?;
    let ready = f.record(&id)?;
    let response = f
        .execute(
            "complete-before-actor-revocation",
            RecoveryCommandBodyV1::ResumeWorkflow {
                workflow_id: id.clone(),
                expected_revision: ready.revision,
            },
        )
        .await?;
    assert!(response.original_response.is_some());
    let original = f.record(&id)?;
    let native_before = native_original_bytes(&f.path, &original)?;
    drop(f);
    std::fs::write(
        directory
            .path()
            .join("revoke-current-recovery-actor-during-classification"),
        b"revoke",
    )?;
    let f = Box::new(RecoveryFixture::open(
        directory.path().to_path_buf(),
        None,
        false,
    )?);
    let actor = f.kernel.authenticate_recovery_actor(
        f.runtime.scope(),
        &f.control,
        RecoveryPermission::Inspect,
    )?;
    assert!(
        f.kernel.replay_recovery_result(&actor, &id).is_err(),
        "callback-revoked actor received output"
    );
    assert!(
        f.kernel
            .authenticate_recovery_actor(f.runtime.scope(), &f.control, RecoveryPermission::Inspect)
            .is_err(),
        "test did not commit its real revocation inside classification"
    );
    assert_eq!(native_before, native_original_bytes(&f.path, &original)?);
    assert_eq!(external_count(&f.path)?, 1);
    assert_eq!(f.process.process("root")?.tree_calls, 2);
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn recovery_captured_deployment_snapshot_is_immutable_and_required() -> TestResult {
    for corrupt in [false, true] {
        let directory = Box::pin(crash_after_capture("return-recorded")).await?;
        let before = retained_workflow(directory.path())?;
        assert!(
            before.captured_deployment.is_some(),
            "new capture omitted mandatory custody"
        );
        let native_before = native_original_bytes(directory.path(), &before)?;
        let db = rusqlite::Connection::open(directory.path().join("admission.db"))?;
        let history_count: i64 = db.query_row(
            "SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'deployment-history:*'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(u64::try_from(history_count)?, 1);
        assert!(db.execute("UPDATE admission_operation_recovery_records SET version=version+1,payload=payload WHERE record_key GLOB 'deployment-history:*'", []).is_err());
        assert!(db.execute("DELETE FROM admission_operation_recovery_records WHERE record_key GLOB 'deployment-history:*'", []).is_err());
        // Inject a physical integrity fault only into this disposable store,
        // restoring the exact canonical trigger catalog before reopening it.
        db.execute_batch("PRAGMA foreign_keys=OFF;")?;
        if corrupt {
            db.execute_batch("DROP TRIGGER admission_operation_recovery_history_immutable;
                DROP TRIGGER admission_operation_recovery_identity;
                UPDATE admission_operation_recovery_records SET payload=cast('null' AS blob) WHERE record_key GLOB 'deployment-history:*';")?;
        } else {
            db.execute_batch("DROP TRIGGER admission_operation_recovery_no_delete;
                DELETE FROM admission_operation_recovery_records WHERE record_key GLOB 'deployment-history:*';")?;
        }
        db.execute_batch(include_str!(
            "../../../../chio-store-sqlite/src/admission_operation_recovery.sql"
        ))?;
        db.execute_batch(include_str!(
            "../../../../chio-store-sqlite/src/recovery_deployment_history.sql"
        ))?;
        drop(db);
        assert!(
            RecoveryFixture::open(directory.path().to_path_buf(), None, false).is_err(),
            "mandatory new custody corruption was misclassified as legacy verifier absence"
        );
        let refused = retained_workflow(directory.path())?;
        assert!(
            refused.historical_hold.is_none(),
            "integrity fault became an isolated hold"
        );
        assert_eq!(
            native_before,
            native_original_bytes(directory.path(), &before)?
        );
        assert_eq!(external_count(directory.path())?, 1);
    }
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
#[ignore = "requires a new provenance-pinned predecessor capture with seventeen signed owners"]
async fn recovery_legacy_seventeen_owner_capture_settles_with_retained_authority() -> TestResult {
    use chio_kernel::admission_operation::{AdmissionOperationId, AdmissionOperationState};

    let path = std::path::PathBuf::from(
        std::env::var_os("CHIO_RECOVERY_RETAINED_COVERAGE_ROOT")
            .ok_or("disposable genuine predecessor seventeen-owner root")?,
    );
    let before = retained_workflow(&path)?;
    assert!(before.captured && !before.admission_closed);
    assert!(before.historical_hold.is_none());
    let approval = before
        .approval
        .as_ref()
        .ok_or("captured retained approval")?;
    assert_eq!(approval.coverage.as_slice().len(), 17);
    let original_approval = chio_core::canonical_json_bytes(approval)?;
    assert!(
        serde_json::from_slice::<RecoveryApprovalSubmissionV1>(&original_approval).is_err(),
        "a retained seventeen-owner bundle became fresh approval authority"
    );
    let mut sixteen = serde_json::to_value(approval)?;
    sixteen
        .get_mut("coverage")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or("retained proof list")?
        .truncate(16);
    let sixteen_bytes = chio_core::canonical_json_bytes(&sixteen)?;
    let fresh_sixteen: RecoveryApprovalSubmissionV1 = serde_json::from_slice(&sixteen_bytes)?;
    assert_eq!(fresh_sixteen.coverage.as_slice().len(), 16);
    assert_eq!(
        chio_core::canonical_json_bytes(&fresh_sixteen)?,
        sixteen_bytes,
        "fresh sixteen-owner codec changed otherwise identical wire bytes"
    );
    let intent = before.admission.as_ref().ok_or("captured native intent")?;
    let db = rusqlite::Connection::open_with_flags(
        path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let version: i64 = db.query_row(
        "SELECT version FROM chio_store_schema_versions WHERE store_key='admission_operation'",
        [],
        |row| row.get(0),
    )?;
    assert!(matches!(version, 35 | 36), "fixture is not a predecessor");
    assert_eq!(
        db.query_row(
            "SELECT state FROM admission_operations WHERE operation_id=?1",
            [intent.native_operation_id.as_str()],
            |row| row.get::<_, String>(0),
        )?,
        "finalizing"
    );
    let bytes: Vec<u8> = db.query_row(
        "SELECT payload FROM admission_operation_recovery_records WHERE record_key GLOB 'deployment:*'",
        [],
        |row| row.get(0),
    )?;
    let mut current: RecoveryDeploymentV1 = serde_json::from_slice(&bytes)?;
    assert_eq!(current.scope, before.scope);
    assert_eq!(current.coverage.as_slice().len(), 17);
    assert_eq!(
        DeploymentDigest::from_bytes(recovery_digest(RecoveryDigestDomain::Deployment, &current)?),
        before.deployment_digest,
        "original predecessor installation is required"
    );
    drop(db);
    assert_eq!(external_count(&path)?, 1);
    let raw_before = captured_return_bytes(&path, &before)?.1;

    // Finite current control authority is installed through the normal
    // operator path. That path archives the original profile byte-for-byte;
    // original captured grants and coverage are never reconstructed.
    let mut assignments = current.actors.as_slice().to_vec();
    for assignment in &mut assignments {
        if matches!(assignment.preview_clearance, InformationLabel::Top) {
            assignment.preview_clearance = restricted_label();
        }
    }
    current.actors = NonEmptyBoundedList::new(assignments)?;
    current.authority_scope = recovery_authority_scope_digest(&current)?;
    install_current_profile(&path, &current)?;
    let mut fixture = Box::new(RecoveryFixture::open(path.clone(), None, false)?);
    fixture.control = current_control(&fixture)?;
    let status = fixture
        .runtime
        .settle(&fixture.control, &before.workflow_id)?;
    assert!(matches!(
        status.effect,
        EffectObservationV1::Complete { .. }
    ));
    let settled = fixture.record(&before.workflow_id)?;
    assert!(settled.captured && settled.admission_closed);
    assert!(settled.historical_hold.is_none());
    assert_eq!(
        chio_core::canonical_json_bytes(&settled.approval)?,
        chio_core::canonical_json_bytes(&before.approval)?
    );
    for (original, retained) in [
        (
            chio_core::canonical_json_bytes(&before.action)?,
            chio_core::canonical_json_bytes(&settled.action)?,
        ),
        (
            chio_core::canonical_json_bytes(&before.signed_grant)?,
            chio_core::canonical_json_bytes(&settled.signed_grant)?,
        ),
        (
            chio_core::canonical_json_bytes(&before.envelope)?,
            chio_core::canonical_json_bytes(&settled.envelope)?,
        ),
        (
            chio_core::canonical_json_bytes(&before.admission)?,
            chio_core::canonical_json_bytes(&settled.admission)?,
        ),
    ] {
        assert_eq!(original, retained, "changed captured original custody");
    }
    let operation = fixture
        .authority
        .admission_operation_store()
        .load_by_operation_id(&AdmissionOperationId::from_persisted(
            intent.native_operation_id.as_str(),
        )?)?
        .ok_or("completed native original")?;
    assert_eq!(operation.state(), AdmissionOperationState::Completed);
    assert_eq!(operation.binding().to_persisted(), intent.native_binding);
    assert_eq!(captured_return_bytes(&path, &settled)?.1, raw_before);
    require_original_terminal_receipt(&fixture, &before)?;
    let actor = fixture.kernel.authenticate_recovery_actor(
        &before.scope,
        &fixture.control,
        RecoveryPermission::Inspect,
    )?;
    let first = fixture
        .kernel
        .replay_recovery_result(&actor, &before.workflow_id)?;
    let second = fixture
        .kernel
        .replay_recovery_result(&actor, &before.workflow_id)?;
    assert_eq!(
        chio_core::canonical_json_bytes(&first.receipt)?,
        chio_core::canonical_json_bytes(&second.receipt)?,
    );
    assert_eq!(external_count(&path)?, 1);
    assert_eq!(fixture.process.process("root")?.tree_calls, 2);
    drop(fixture);
    let mut reopened = Box::new(RecoveryFixture::open(path, None, false)?);
    reopened.control = current_control(&reopened)?;
    assert!(reopened
        .runtime
        .settle(&reopened.control, &before.workflow_id)?
        .effect
        .is_settled());
    assert_eq!(external_count(&reopened.path)?, 1);
    assert_eq!(reopened.process.process("root")?.tree_calls, 2);
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
#[ignore = "requires a new genuine old-schema capture and old-schema public rotation"]
async fn recovery_legacy_captured_rotation_is_durably_quarantined() -> TestResult {
    let path = std::path::PathBuf::from(
        std::env::var_os("CHIO_RECOVERY_AUTHORITY_LEGACY_ROOT")
            .ok_or("genuine legacy captured fixture root")?,
    );
    let before = retained_workflow(&path)?;
    assert!(before.captured);
    assert!(!before.admission_closed);
    assert!(before.captured_deployment.is_none());
    assert!(before.historical_hold.is_none());
    let db = rusqlite::Connection::open_with_flags(
        path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    assert_eq!(
        db.query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key='admission_operation'",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        35,
        "acceptance fixture was not produced before the rollback fence"
    );
    assert_eq!(db.query_row("SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'deployment-history:*'", [], |row| row.get::<_, i64>(0))?, 0,
        "legacy verifier absence was replaced by a fabricated mandatory snapshot deletion");
    let current_bytes: Vec<u8> = db.query_row("SELECT payload FROM admission_operation_recovery_records WHERE record_key GLOB 'deployment:*'", [], |row| row.get(0))?;
    let mut current: RecoveryDeploymentV1 = serde_json::from_slice(&current_bytes)?;
    assert_eq!(current.scope, before.scope);
    assert_ne!(
        DeploymentDigest::from_bytes(recovery_digest(RecoveryDigestDomain::Deployment, &current)?),
        before.deployment_digest,
        "old-schema producer did not rotate before upgrade"
    );
    drop(db);
    let native_before = native_original_bytes(&path, &before)?;
    // The old producer already replaced the original verification root. Only
    // this rotated current profile receives finite current actor clearances.
    // Installing it cannot reconstruct the missing original deployment.
    let mut assignments = current.actors.as_slice().to_vec();
    for assignment in &mut assignments {
        if matches!(assignment.preview_clearance, InformationLabel::Top) {
            assignment.preview_clearance = restricted_label();
        }
    }
    current.actors = NonEmptyBoundedList::new(assignments)?;
    current.authority_scope = recovery_authority_scope_digest(&current)?;
    install_current_profile(&path, &current)?;
    let db = rusqlite::Connection::open_with_flags(
        path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let original_history_key = format!(
        "deployment-history:{}:{}",
        chio_core::sha256_hex(&chio_core::canonical_json_bytes(&before.scope)?),
        hex::encode(before.deployment_digest.as_bytes()),
    );
    assert!(
        !db.query_row(
            "SELECT EXISTS(SELECT 1 FROM admission_operation_recovery_records WHERE record_key=?1)",
            [original_history_key],
            |row| row.get::<_, bool>(0),
        )?,
        "current control installation restored the missing original root"
    );
    drop(db);
    let mut f = Box::new(
        RecoveryFixture::open(path.clone(), None, false).map_err(|error| {
            format!("verified legacy verifier absence blocked authority startup: {error}")
        })?,
    );
    f.control = current_control(&f)?;
    let held = f.record(&before.workflow_id)?;
    assert_eq!(held.control, WorkflowControlV1::Quarantined);
    let hold = held
        .historical_hold
        .as_ref()
        .ok_or("legacy historical hold")?;
    assert_eq!(
        hold.reason,
        RecoveryHistoricalHoldReasonV1::LegacyDeploymentUnavailable
    );
    assert!(held.captured_deployment.is_none());
    assert!(held.captured);
    assert!(!held.admission_closed);
    assert_eq!(before.continuation_id, held.continuation_id);
    for (original, retained) in [
        (
            chio_core::canonical_json_bytes(&before.action)?,
            chio_core::canonical_json_bytes(&held.action)?,
        ),
        (
            chio_core::canonical_json_bytes(&before.signed_grant)?,
            chio_core::canonical_json_bytes(&held.signed_grant)?,
        ),
        (
            chio_core::canonical_json_bytes(&before.envelope)?,
            chio_core::canonical_json_bytes(&held.envelope)?,
        ),
        (
            chio_core::canonical_json_bytes(&before.admission)?,
            chio_core::canonical_json_bytes(&held.admission)?,
        ),
    ] {
        assert_eq!(original, retained);
    }
    assert_eq!(native_before, native_original_bytes(&path, &held)?);
    assert_eq!(external_count(&path)?, 1);
    assert_eq!(f.process.process("root")?.tree_calls, 2);
    f.runtime.settle(&f.control, &held.workflow_id)?;
    let events = recovery_event_count(&path)?;
    for _ in 0..3 {
        f.runtime.settle(&f.control, &held.workflow_id)?;
    }
    assert_eq!(events, recovery_event_count(&path)?);
    let actor = f.kernel.authenticate_recovery_actor(
        f.runtime.scope(),
        &f.control,
        RecoveryPermission::Inspect,
    )?;
    assert!(f
        .kernel
        .replay_recovery_result(&actor, &held.workflow_id)
        .is_err());
    let current = f.record(&held.workflow_id)?;
    assert!(f
        .execute(
            "legacy-held-resume",
            RecoveryCommandBodyV1::ResumeWorkflow {
                workflow_id: held.workflow_id.clone(),
                expected_revision: current.revision,
            }
        )
        .await
        .is_err());
    let request: ToolCallRequest = serde_json::from_str(
        held.envelope
            .as_ref()
            .ok_or("legacy envelope")?
            .request
            .as_str(),
    )?;
    let reservation: RecoveryProcessReservationV1 = serde_json::from_str(
        held.process_reservation
            .as_ref()
            .ok_or("legacy reservation")?
            .as_str(),
    )?;
    assert!(f
        .process
        .invoke_known_only("root", &reservation.operation_key, &request)
        .await
        .is_err());
    assert_eq!(f.process.process("root")?.tree_calls, 2);
    assert_eq!(external_count(&path)?, 1);
    Box::pin(f.denied_seed_named("unrelated-current-native-operation")).await?;
    assert_eq!(
        f.process.process("root")?.tree_calls,
        3,
        "unrelated native evaluation did not consume exactly its own call"
    );
    assert_eq!(native_before, native_original_bytes(&path, &held)?);
    assert_eq!(external_count(&path)?, 1);
    drop(f);
    let mut reopened = Box::new(RecoveryFixture::open(path.clone(), None, false)?);
    reopened.control = current_control(&reopened)?;
    assert_eq!(
        reopened.record(&held.workflow_id)?.control,
        WorkflowControlV1::Quarantined
    );
    let events = recovery_event_count(&path)?;
    reopened
        .runtime
        .settle(&reopened.control, &held.workflow_id)?;
    assert_eq!(events, recovery_event_count(&path)?);
    assert_eq!(native_before, native_original_bytes(&path, &held)?);
    assert_eq!(external_count(&path)?, 1);
    assert_eq!(reopened.process.process("root")?.tree_calls, 3);
    Ok(())
}
