//! Affine child custody. No process/authority lock spans child execution.
use super::*;
use chio_cage::{CompiledCage, EnforcedChild, FdPurpose, NetworkMode};
use std::time::{Duration, Instant};

#[cfg(test)]
#[derive(Debug)]
enum ConfinementDiagnosticPhase {
    LaunchActor,
    ParentContext,
    LaunchReservation,
    ConfinedAttachment,
    ReturnReservation,
    InputInventory,
    InputBlobRead,
    InputAdmission,
    ParentBeforeInput,
    ChildBeforeInput,
    InputChannel,
    StageActor,
    StageAudience,
    StageAudienceAfterChannels,
    StageAudienceAfterExit,
    StageValueChannel,
    StageDiagnosticChannel,
    StageWaitExit,
    StageNativeExit,
    StageBrokerCandidate,
    StageNativeCandidate,
}

// Private test evidence prints only a closed phase and closed outcome. It never
// formats the error, identity, metadata, labels, digests or channel contents.
macro_rules! diagnostic_phase {
    ($phase:ident, $operation:expr) => {{
        let result = $operation;
        #[cfg(test)]
        eprintln!(
            "confined-phase:{:?}:{}",
            ConfinementDiagnosticPhase::$phase,
            if result.is_ok() {
                "returned_ok"
            } else {
                "returned_err"
            }
        );
        result
    }};
}

pub struct ConfinedExecution {
    runtime: NativeConfinedRuntime,
    request: RequestId,
    reservation: NativeConfinedReservationV1,
    child: Option<EnforcedChild>,
    stdout: Option<std::thread::JoinHandle<Result<Zeroizing<Vec<u8>>, KernelError>>>,
    stderr: Option<std::thread::JoinHandle<Result<Zeroizing<Vec<u8>>, KernelError>>>,
    deadline: Instant,
    launch_capability: CapabilityToken,
}
struct LaunchCustody<'a> {
    runtime: &'a NativeConfinedRuntime,
    actor: &'a AuthenticatedRecoveryActor,
    request: &'a RequestId,
    armed: bool,
}
impl Drop for LaunchCustody<'_> {
    fn drop(&mut self) {
        if self.armed {
            if let Ok(time) = now() {
                let _ = self.runtime.store.quarantine_confined_child(
                    self.actor,
                    self.request,
                    &self.runtime.fence,
                    time,
                );
            }
        }
    }
}
impl core::fmt::Debug for ConfinedExecution {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ConfinedExecution([redacted])")
    }
}
fn digest(hex: &str) -> Result<CageMeasurementDigest, KernelError> {
    parse_cage_digest(hex).map_err(refused)
}
/// Inspect and pin the existing compiled cage's complete pre-stdio plan. The
/// final preparation separately binds its ephemeral socket identities.
pub fn confined_execution_profile(
    compiled: &CompiledCage,
) -> Result<ConfinedExecutionProfileV1, KernelError> {
    let plan = compiled.plan();
    if plan.landlock.network_mode != NetworkMode::Blocked
        || compiled.profile().native_syscall_profile
            != chio_manifest::NativeSyscallProfile::NativeMinimalV1
        || !plan.landlock.default_filesystem_deny
        || plan.environment.len() != 3
        || [("LANG", "C"), ("LC_ALL", "C"), ("TZ", "UTC")]
            .iter()
            .any(|(name, value)| plan.environment.get(*name).map(String::as_str) != Some(*value))
        || compiled.broker_ipc().is_some()
        || plan.target_argv.len() != 1
        || plan.fd_table.iter().any(|f| {
            !matches!(
                f.purpose,
                FdPurpose::CageInitHelper
                    | FdPurpose::TargetExecutable
                    | FdPurpose::WorkingDirectory
                    | FdPurpose::TargetStdin
                    | FdPurpose::TargetStdout
                    | FdPurpose::TargetStderr
            )
        })
    {
        return Err(refused("confined channel coverage"));
    }
    Ok(ConfinedExecutionProfileV1 {
        manifest: digest(&plan.manifest_digest)?,
        profile: digest(compiled.profile_digest())?,
        configuration: digest(compiled.plan_digest())?,
        helper: digest(&compiled.profile().helper_binding_digest)?,
        image: digest(&compiled.profile().target_binding_digest)?,
        provider: ConfinedProviderV1::Disabled,
    })
}
impl NativeConfinedRuntime {
    pub fn launch(
        &self,
        capability: &CapabilityToken,
        request: &RequestId,
        compiled: CompiledCage,
    ) -> Result<ConfinedExecution, KernelError> {
        let actor = diagnostic_phase!(
            LaunchActor,
            self.actor(capability, RecoveryPermission::ConfinedLaunch)
        )?;
        let profile = self
            .store
            .knowledge_installation(&actor, &self.fence, now()?)
            .map_err(refused)?;
        diagnostic_phase!(
            ParentContext,
            self.broker.validate_process(
                &self.installation.scope.process_id,
                &profile.producer_context,
            )
        )?;
        let reserved = diagnostic_phase!(
            LaunchReservation,
            self.store
                .confined_launch_reservation(&actor, request, &self.fence, now()?)
                .map_err(refused)
        )?;
        diagnostic_phase!(
            ConfinedAttachment,
            self.broker.validate_confined_attachment(&reserved.boundary)
        )?;
        diagnostic_phase!(
            ReturnReservation,
            self.broker.reserve_confined_return(&reserved.boundary)
        )?;
        if confined_execution_profile(&compiled)? != self.installation.execution {
            return Err(refused("execution profile changed"));
        }
        let prepared = chio_cage::prepare_launch(compiled).map_err(refused)?;
        self.store
            .prepare_confined_launch(&actor, request, &prepared, &self.fence, now()?)
            .map_err(refused)?;
        let mut custody = LaunchCustody {
            runtime: self,
            actor: &actor,
            request,
            armed: true,
        };
        self.cutpoint(ConfinedCutpoint::LaunchPrepared)?;
        let mut child =
            chio_cage::launch_prepared(prepared, chio_cage::CageLaunchOptions::default())
                .map_err(refused)?;
        let reservation = self
            .store
            .record_confined_enforcement(&actor, request, &child, &self.fence, now()?)
            .map_err(refused)?;
        self.cutpoint(ConfinedCutpoint::Enforced)?;
        let left = reservation
            .boundary
            .deadline_unix_ms
            .get()
            .checked_sub(now()?)
            .filter(|v| *v > 0)
            .ok_or_else(|| refused("execution deadline"))?;
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(left))
            .ok_or_else(|| refused("deadline"))?;
        child.enforce_deadline(deadline).map_err(refused)?;
        let (stdin, stdout, stderr) = child
            .take_stdio()
            .ok_or_else(|| refused("enforced channel custody"))?
            .into_parts();
        let stdout = channels::socket(stdout);
        let stderr = channels::socket(stderr);
        let stdout = std::thread::Builder::new()
            .name("confined-value".into())
            .spawn(move || channels::read(stdout, 8, deadline))
            .map_err(refused)?;
        let diagnostic_bound = reservation.boundary.limits.diagnostic_bytes.get() as usize;
        let stderr = std::thread::Builder::new()
            .name("confined-diagnostics".into())
            .spawn(move || channels::read(stderr, diagnostic_bound, deadline))
            .map_err(refused)?;
        let execution = ConfinedExecution {
            runtime: self.clone(),
            request: request.clone(),
            reservation,
            child: Some(child),
            stdout: Some(stdout),
            stderr: Some(stderr),
            deadline,
            launch_capability: capability.clone(),
        };
        let inventory = diagnostic_phase!(
            InputInventory,
            self.store
                .confined_input_inventory(&actor, request, &self.fence, now()?)
                .map_err(refused)
        )?;
        let mut input = Vec::new();
        for record in inventory {
            let seal = record.seal.ok_or_else(|| refused("immutable input seal"))?;
            input.push(Zeroizing::new(diagnostic_phase!(
                InputBlobRead,
                self.broker.read_private(&seal)
            )?));
        }
        let observation = input.first().ok_or_else(|| refused("observation"))?;
        let seeds = Zeroizing::new(input.iter().skip(1).map(|b| b.to_vec()).collect::<Vec<_>>());
        let packet = Zeroizing::new(
            encode_confined_input(
                self.installation.contract.field.as_str(),
                observation,
                &seeds,
            )
            .map_err(refused)?,
        );
        diagnostic_phase!(
            InputAdmission,
            self.store
                .admit_confined_input(&actor, request, &packet, &self.fence, now()?)
                .map_err(refused)
        )?;
        self.cutpoint(ConfinedCutpoint::ObservationCommitted)?;
        diagnostic_phase!(
            ParentBeforeInput,
            self.broker.validate_process(
                &self.installation.scope.process_id,
                &profile.producer_context,
            )
        )?;
        diagnostic_phase!(
            ChildBeforeInput,
            self.broker.validate_process(
                &execution.reservation.boundary.child,
                &execution.reservation.child_context,
            )
        )?;
        self.cutpoint(ConfinedCutpoint::BeforeInput)?;
        diagnostic_phase!(
            InputChannel,
            channels::write(channels::socket(stdin), &packet, deadline)
        )?;
        custody.armed = false;
        Ok(execution)
    }
}
impl ConfinedExecution {
    /// Consumes execution custody, verifies normal exit and independently
    /// stages the exact return. The evidence stays in trusted host custody.
    ///
    /// Staging does not expose classified metadata to the launch caller.
    ///
    /// ```compile_fail
    /// use chio_control_plane::confinement::ConfinedExecution;
    /// use chio_core_types::capability::token::CapabilityToken;
    /// use chio_kernel::KernelError;
    /// fn expose_staged_digest(
    ///     execution: ConfinedExecution,
    ///     capability: &CapabilityToken,
    /// ) -> Result<(), KernelError> {
    ///     let staged = execution.stage(capability)?;
    ///     let _digest = staged.content;
    ///     Ok(())
    /// }
    /// ```
    ///
    /// ```no_run
    /// use chio_control_plane::confinement::ConfinedExecution;
    /// use chio_core_types::capability::token::CapabilityToken;
    /// use chio_kernel::KernelError;
    /// fn stage_without_metadata(
    ///     execution: ConfinedExecution,
    ///     capability: &CapabilityToken,
    /// ) -> Result<(), KernelError> {
    ///     execution.stage(capability)?;
    ///     Ok(())
    /// }
    /// ```
    pub fn stage(mut self, capability: &CapabilityToken) -> Result<(), KernelError> {
        let actor = diagnostic_phase!(
            StageActor,
            self.runtime
                .actor(capability, RecoveryPermission::ConfinedLaunch)
        )?;
        diagnostic_phase!(
            StageAudience,
            self.runtime
                .store
                .verify_confined_staging_audience(
                    &actor,
                    &self.request,
                    &self.runtime.fence,
                    now()?,
                )
                .map_err(refused)
        )?;
        // Keep private channel results in custody until a current source
        // check succeeds after the potentially blocking joins. An error must
        // not become an audience bypass when clearance changes while waiting.
        let value_result = (|| {
            self.stdout
                .take()
                .ok_or_else(|| refused("stdout custody"))?
                .join()
                .map_err(|_| refused("channel reader"))?
        })();
        let diagnostic_result = (|| {
            self.stderr
                .take()
                .ok_or_else(|| refused("stderr custody"))?
                .join()
                .map_err(|_| refused("channel reader"))?
        })();
        diagnostic_phase!(
            StageAudienceAfterChannels,
            self.runtime
                .store
                .verify_confined_staging_audience(
                    &actor,
                    &self.request,
                    &self.runtime.fence,
                    now()?,
                )
                .map_err(refused)
        )?;
        let bytes = diagnostic_phase!(StageValueChannel, value_result)?;
        let diagnostics = diagnostic_phase!(StageDiagnosticChannel, diagnostic_result)?;
        drop(diagnostics);
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| refused("child custody"))?;
        loop {
            let exit_result = child.try_wait_verified().map_err(refused);
            diagnostic_phase!(
                StageAudienceAfterExit,
                self.runtime
                    .store
                    .verify_confined_staging_audience(
                        &actor,
                        &self.request,
                        &self.runtime.fence,
                        now()?,
                    )
                    .map_err(refused)
            )?;
            if let Some(exit) = diagnostic_phase!(StageWaitExit, exit_result)? {
                diagnostic_phase!(
                    StageNativeExit,
                    self.runtime
                        .store
                        .record_confined_exit(
                            &actor,
                            &self.request,
                            &exit,
                            &self.runtime.fence,
                            now()?
                        )
                        .map_err(refused)
                )?;
                if exit.record().exit.as_ref().and_then(|e| e.exit_code) != Some(0) {
                    return Err(refused("classified child failure"));
                }
                break;
            }
            if Instant::now() >= self.deadline {
                return Err(refused("execution timeout"));
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        let seal = diagnostic_phase!(
            StageBrokerCandidate,
            self.runtime
                .broker
                .stage_confined_return(&actor, &self.reservation.boundary, &bytes)
        )?;
        diagnostic_phase!(
            StageNativeCandidate,
            self.runtime
                .store
                .stage_confined_return(
                    &actor,
                    &self.request,
                    &seal,
                    &bytes,
                    &self.runtime.fence,
                    now()?,
                )
                .map_err(refused)
        )?;
        self.runtime.cutpoint(ConfinedCutpoint::ReturnStaged)?;
        Ok(())
    }
    pub fn cancel(
        mut self,
        capability: &CapabilityToken,
        process: &chio_process::ProcessRuntime,
    ) -> Result<(), KernelError> {
        self.runtime.cancel(capability, process, &self.request)?;
        if let Some(child) = self.child.take() {
            child.terminate().map_err(refused)?;
        }
        Ok(())
    }
}
impl Drop for ConfinedExecution {
    fn drop(&mut self) {
        if let (Ok(actor), Ok(time)) = (
            self.runtime
                .actor(&self.launch_capability, RecoveryPermission::ConfinedLaunch),
            now(),
        ) {
            let _ = self.runtime.store.quarantine_confined_child(
                &actor,
                &self.request,
                &self.runtime.fence,
                time,
            );
        }
        // Existing cage Drop transfers exact process custody to its bounded
        // pidfd supervisor. Channel readers have the original absolute deadline.
        drop(self.child.take());
    }
}
