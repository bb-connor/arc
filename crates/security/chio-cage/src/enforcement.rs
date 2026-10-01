use serde::{Deserialize, Serialize};

use crate::{ExecutionIdentity, FileIdentity, ResourceKind, SandboxArchitecture};

pub const ENFORCEMENT_PREPARED_SCHEMA: &str = "chio.cage.enforcement-prepared.v1";
pub const EXEC_TRANSITION_OBSERVED_SCHEMA: &str = "chio.cage.exec-transition-observed.v1";
pub const CAGE_ENFORCEMENT_RECORD_SCHEMA: &str = "chio.cage.enforcement-record.v1";
pub const MINIMUM_LANDLOCK_ABI: u32 = 4;
pub const PINNED_NONO_VERSION: &str = "0.53.0";
pub const NONO_PATCH_VERSION: &str = "chio.2";
pub const PINNED_SECCOMPILER_VERSION: &str = "0.5.0";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CageEnforcementState {
    Unsupported,
    Rejected,
    BootstrapFailed,
    FullyEnforced,
    Exited,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CageEnforcementFailureCode {
    UnsupportedKernel,
    HelperIdentityMismatch,
    InvalidPlanSeals,
    InvalidPlan,
    DescriptorCountMismatch,
    DescriptorIdentityMismatch,
    PrivilegedExecutable,
    NonSingleThreadedHelper,
    ExecutionIdentityInvalid,
    ExecutionIdentityApplyFailed,
    ExecutionIdentityMismatch,
    TraceHandshakeFailed,
    LandlockUnavailable,
    LandlockPartial,
    SeccompUnavailable,
    SeccompArchitectureMismatch,
    SeccompInstallFailed,
    PreparedRecordInvalid,
    ExecEventMissing,
    ExecIdentityMismatch,
    StatusProtocolViolation,
    Timeout,
    ChildExitedBeforeExec,
}

/// Kernel-observed status of one required Landlock policy class.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedRulesetStatus {
    FullyEnforced,
    PartiallyEnforced,
    NotEnforced,
}

/// Observed installation state of the independent seccompiler filter.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SeccompEnforcementStatus {
    FullyEnforced,
    NotEnforced,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CageEnforcementFailure {
    pub code: CageEnforcementFailureCode,
    pub stage: String,
}

impl CageEnforcementFailure {
    pub fn new(
        code: CageEnforcementFailureCode,
        stage: impl Into<String>,
    ) -> Result<Self, EnforcementEvidenceError> {
        let stage = stage.into();
        validate_identifier(&stage, "failure stage")?;
        Ok(Self { code, stage })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcementPrepared {
    pub schema: String,
    pub process_id: u32,
    pub manifest_digest: String,
    pub profile_digest: String,
    pub plan_digest: String,
    pub fd_table_digest: String,
    pub helper_binding_digest: String,
    pub target_binding_digest: String,
    pub target_identity: FileIdentity,
    pub applied_execution_identity: ExecutionIdentity,
    pub nono_version: String,
    pub nono_patch_version: String,
    pub landlock_abi: u32,
    pub landlock_filesystem_status: ObservedRulesetStatus,
    pub landlock_network_status: ObservedRulesetStatus,
    pub seccompiler_version: String,
    pub seccomp_status: SeccompEnforcementStatus,
    pub seccomp_architecture: SandboxArchitecture,
    pub seccomp_filter_digest: String,
    pub trace_session_digest: String,
    pub prepared_at_unix_ms: u64,
}

impl EnforcementPrepared {
    pub fn validate(&self) -> Result<(), EnforcementEvidenceError> {
        if self.schema != ENFORCEMENT_PREPARED_SCHEMA {
            return Err(EnforcementEvidenceError::InvalidSchema);
        }
        if self.process_id == 0
            || self.landlock_abi < MINIMUM_LANDLOCK_ABI
            || self.prepared_at_unix_ms == 0
        {
            return Err(EnforcementEvidenceError::InvalidNumber);
        }
        if self.nono_version != PINNED_NONO_VERSION
            || self.nono_patch_version != NONO_PATCH_VERSION
            || self.seccompiler_version != PINNED_SECCOMPILER_VERSION
            || self.seccomp_architecture != SandboxArchitecture::X86_64
        {
            return Err(EnforcementEvidenceError::InvalidEnforcementVersion);
        }
        if self.landlock_filesystem_status != ObservedRulesetStatus::FullyEnforced
            || self.landlock_network_status != ObservedRulesetStatus::FullyEnforced
            || self.seccomp_status != SeccompEnforcementStatus::FullyEnforced
        {
            return Err(EnforcementEvidenceError::IncompleteEnforcement);
        }
        for digest in [
            &self.manifest_digest,
            &self.profile_digest,
            &self.plan_digest,
            &self.fd_table_digest,
            &self.helper_binding_digest,
            &self.target_binding_digest,
            &self.seccomp_filter_digest,
            &self.trace_session_digest,
        ] {
            validate_digest(digest)?;
        }
        validate_target_identity(self.target_identity)?;
        self.applied_execution_identity
            .validate()
            .map_err(|_| EnforcementEvidenceError::BindingMismatch)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecTransitionObserved {
    pub schema: String,
    pub process_id: u32,
    pub trace_session_digest: String,
    pub target_binding_digest: String,
    pub target_identity: FileIdentity,
    pub observed_at_unix_ms: u64,
}

impl ExecTransitionObserved {
    pub fn validate(&self) -> Result<(), EnforcementEvidenceError> {
        if self.schema != EXEC_TRANSITION_OBSERVED_SCHEMA {
            return Err(EnforcementEvidenceError::InvalidSchema);
        }
        if self.process_id == 0 || self.observed_at_unix_ms == 0 {
            return Err(EnforcementEvidenceError::InvalidNumber);
        }
        validate_digest(&self.trace_session_digest)?;
        validate_digest(&self.target_binding_digest)?;
        validate_target_identity(self.target_identity)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FullyEnforcedEvidence {
    pub prepared: EnforcementPrepared,
    pub exec_transition: ExecTransitionObserved,
    pub status_eof_observed: bool,
}

impl FullyEnforcedEvidence {
    pub fn new(
        prepared: EnforcementPrepared,
        exec_transition: ExecTransitionObserved,
        status_eof_observed: bool,
    ) -> Result<Self, EnforcementEvidenceError> {
        prepared.validate()?;
        exec_transition.validate()?;
        if !status_eof_observed {
            return Err(EnforcementEvidenceError::MissingStatusEof);
        }
        if prepared.process_id != exec_transition.process_id
            || prepared.trace_session_digest != exec_transition.trace_session_digest
            || prepared.target_binding_digest != exec_transition.target_binding_digest
            || prepared.target_identity != exec_transition.target_identity
            || exec_transition.observed_at_unix_ms < prepared.prepared_at_unix_ms
        {
            return Err(EnforcementEvidenceError::BindingMismatch);
        }
        Ok(Self {
            prepared,
            exec_transition,
            status_eof_observed,
        })
    }

    pub fn validate(&self) -> Result<(), EnforcementEvidenceError> {
        Self::new(
            self.prepared.clone(),
            self.exec_transition.clone(),
            self.status_eof_observed,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessExitEvidence {
    pub process_id: u32,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub exited_at_unix_ms: u64,
}

impl ProcessExitEvidence {
    pub fn validate(&self) -> Result<(), EnforcementEvidenceError> {
        if self.process_id == 0
            || self.exited_at_unix_ms == 0
            || self.exit_code.is_some() == self.signal.is_some()
            || self
                .exit_code
                .is_some_and(|exit_code| !(0..=255).contains(&exit_code))
            || self
                .signal
                .is_some_and(|signal| !(1..=64).contains(&signal))
        {
            return Err(EnforcementEvidenceError::InvalidExit);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CageEnforcementRecord {
    pub schema: String,
    pub state: CageEnforcementState,
    pub fully_enforced: Option<FullyEnforcedEvidence>,
    pub failure: Option<CageEnforcementFailure>,
    pub exit: Option<ProcessExitEvidence>,
}

impl CageEnforcementRecord {
    pub fn fully_enforced(
        evidence: FullyEnforcedEvidence,
    ) -> Result<Self, EnforcementEvidenceError> {
        evidence.validate()?;
        Ok(Self {
            schema: CAGE_ENFORCEMENT_RECORD_SCHEMA.to_string(),
            state: CageEnforcementState::FullyEnforced,
            fully_enforced: Some(evidence),
            failure: None,
            exit: None,
        })
    }

    pub fn bootstrap_failed(
        failure: CageEnforcementFailure,
    ) -> Result<Self, EnforcementEvidenceError> {
        Self::terminal_failure(CageEnforcementState::BootstrapFailed, failure)
    }

    pub fn rejected(failure: CageEnforcementFailure) -> Result<Self, EnforcementEvidenceError> {
        Self::terminal_failure(CageEnforcementState::Rejected, failure)
    }

    pub fn unsupported(failure: CageEnforcementFailure) -> Result<Self, EnforcementEvidenceError> {
        Self::terminal_failure(CageEnforcementState::Unsupported, failure)
    }

    fn terminal_failure(
        state: CageEnforcementState,
        failure: CageEnforcementFailure,
    ) -> Result<Self, EnforcementEvidenceError> {
        if !matches!(
            state,
            CageEnforcementState::Unsupported
                | CageEnforcementState::Rejected
                | CageEnforcementState::BootstrapFailed
        ) {
            return Err(EnforcementEvidenceError::InvalidStateShape);
        }
        validate_identifier(&failure.stage, "failure stage")?;
        Ok(Self {
            schema: CAGE_ENFORCEMENT_RECORD_SCHEMA.to_string(),
            state,
            fully_enforced: None,
            failure: Some(failure),
            exit: None,
        })
    }

    pub fn exited(
        evidence: FullyEnforcedEvidence,
        exit: ProcessExitEvidence,
    ) -> Result<Self, EnforcementEvidenceError> {
        evidence.validate()?;
        if evidence.prepared.process_id != exit.process_id
            || exit.exited_at_unix_ms < evidence.exec_transition.observed_at_unix_ms
        {
            return Err(EnforcementEvidenceError::BindingMismatch);
        }
        exit.validate()?;
        Ok(Self {
            schema: CAGE_ENFORCEMENT_RECORD_SCHEMA.to_string(),
            state: CageEnforcementState::Exited,
            fully_enforced: Some(evidence),
            failure: None,
            exit: Some(exit),
        })
    }

    pub fn validate(&self) -> Result<(), EnforcementEvidenceError> {
        if self.schema != CAGE_ENFORCEMENT_RECORD_SCHEMA {
            return Err(EnforcementEvidenceError::InvalidSchema);
        }
        match self.state {
            CageEnforcementState::FullyEnforced => {
                if self.failure.is_some() || self.exit.is_some() {
                    return Err(EnforcementEvidenceError::InvalidStateShape);
                }
                let evidence = self
                    .fully_enforced
                    .as_ref()
                    .ok_or(EnforcementEvidenceError::InvalidStateShape)?;
                FullyEnforcedEvidence::new(
                    evidence.prepared.clone(),
                    evidence.exec_transition.clone(),
                    evidence.status_eof_observed,
                )?;
            }
            CageEnforcementState::Exited => {
                if self.failure.is_some() {
                    return Err(EnforcementEvidenceError::InvalidStateShape);
                }
                let evidence = self
                    .fully_enforced
                    .as_ref()
                    .ok_or(EnforcementEvidenceError::InvalidStateShape)?;
                let exit = self
                    .exit
                    .as_ref()
                    .ok_or(EnforcementEvidenceError::InvalidStateShape)?;
                FullyEnforcedEvidence::new(
                    evidence.prepared.clone(),
                    evidence.exec_transition.clone(),
                    evidence.status_eof_observed,
                )?;
                exit.validate()?;
                if evidence.prepared.process_id != exit.process_id
                    || exit.exited_at_unix_ms < evidence.exec_transition.observed_at_unix_ms
                {
                    return Err(EnforcementEvidenceError::BindingMismatch);
                }
            }
            CageEnforcementState::BootstrapFailed
            | CageEnforcementState::Rejected
            | CageEnforcementState::Unsupported => {
                if self.fully_enforced.is_some() || self.exit.is_some() || self.failure.is_none() {
                    return Err(EnforcementEvidenceError::InvalidStateShape);
                }
                validate_identifier(
                    &self
                        .failure
                        .as_ref()
                        .ok_or(EnforcementEvidenceError::InvalidStateShape)?
                        .stage,
                    "failure stage",
                )?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum EnforcementEvidenceError {
    #[error("enforcement evidence schema is invalid")]
    InvalidSchema,
    #[error("enforcement evidence contains an invalid numeric value")]
    InvalidNumber,
    #[error("enforcement evidence contains an invalid digest")]
    InvalidDigest,
    #[error("enforcement evidence contains an invalid identifier")]
    InvalidIdentifier,
    #[error("enforcement evidence names an unreviewed nono or seccompiler version")]
    InvalidEnforcementVersion,
    #[error("enforcement evidence reports partial or missing enforcement")]
    IncompleteEnforcement,
    #[error("enforcement evidence bindings do not match")]
    BindingMismatch,
    #[error("enforcement evidence is missing status EOF")]
    MissingStatusEof,
    #[error("enforcement record state shape is invalid")]
    InvalidStateShape,
    #[error("process exit evidence is invalid")]
    InvalidExit,
}

fn validate_digest(value: &str) -> Result<(), EnforcementEvidenceError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(EnforcementEvidenceError::InvalidDigest);
    }
    Ok(())
}

fn validate_identifier(value: &str, _field: &'static str) -> Result<(), EnforcementEvidenceError> {
    if value.is_empty()
        || value.len() > 128
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(EnforcementEvidenceError::InvalidIdentifier);
    }
    Ok(())
}

fn validate_target_identity(identity: FileIdentity) -> Result<(), EnforcementEvidenceError> {
    if identity.kind() != ResourceKind::RegularFile
        || identity.inode() == 0
        || identity.mount_id() == 0
        || identity.mode() & 0o111 == 0
    {
        return Err(EnforcementEvidenceError::BindingMismatch);
    }
    Ok(())
}
