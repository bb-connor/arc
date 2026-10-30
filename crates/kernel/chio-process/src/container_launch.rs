//! Signed evidence that a container worker started under the fixed profile.

use chio_cage_plan::CageEnforcementState;
use chio_core_types::canonical::CanonicalBytes;
use chio_core_types::crypto::{verify_wrapped, Keypair, PublicKey, Signature};
use serde::{Deserialize, Serialize};

use crate::ProcessError;

pub const CONTAINER_LAUNCH_RECORD_SCHEMA: &str = "chio.process.container-launch.v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerLaunchFailure {
    ProfileMismatch,
    StartFailed,
    StartUnconfirmed,
}

/// One record per `(process_id, attempt)`. `attempt` is the runner's launch
/// attempt for the worker, not the dispatch attempt of a logical operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerLaunchRecord {
    pub schema: String,
    pub process_id: String,
    pub attempt: u32,
    pub image_id: String,
    pub container_id: String,
    pub engine_identity: String,
    pub profile_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inspected_config_digest: Option<String>,
    pub state: CageEnforcementState,
    /// Engine-reported start time; present only on `FullyEnforced`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_at_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_class: Option<ContainerLaunchFailure>,
}

impl ContainerLaunchRecord {
    pub fn validate(&self) -> Result<(), ProcessError> {
        let hex64 = |value: &str| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        };
        if self.schema != CONTAINER_LAUNCH_RECORD_SCHEMA
            || self.process_id.is_empty()
            || self.attempt == 0
            || !self.image_id.strip_prefix("sha256:").is_some_and(hex64)
            || !hex64(&self.container_id)
            || self.engine_identity.is_empty()
            || !hex64(&self.profile_digest)
            || self
                .inspected_config_digest
                .as_deref()
                .is_some_and(|digest| !hex64(digest))
        {
            return Err(ProcessError::Invalid("container launch record identity"));
        }
        let shape_holds = match self.state {
            CageEnforcementState::FullyEnforced => {
                self.inspected_config_digest.is_some()
                    && self.started_at.as_deref().is_some_and(|at| !at.is_empty())
                    && self.failed_at_unix_ms.is_none()
                    && self.failure_class.is_none()
            }
            CageEnforcementState::Rejected => {
                self.started_at.is_none()
                    && self.failed_at_unix_ms.is_some()
                    && self.failure_class == Some(ContainerLaunchFailure::ProfileMismatch)
            }
            CageEnforcementState::BootstrapFailed => {
                self.started_at.is_none()
                    && self.failed_at_unix_ms.is_some()
                    && matches!(
                        self.failure_class,
                        Some(
                            ContainerLaunchFailure::StartFailed
                                | ContainerLaunchFailure::StartUnconfirmed
                        )
                    )
            }
            CageEnforcementState::Unsupported | CageEnforcementState::Exited => false,
        };
        if !shape_holds {
            return Err(ProcessError::Invalid("container launch record state"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedContainerLaunchRecord {
    pub record: ContainerLaunchRecord,
    pub signer: PublicKey,
    pub signature: Signature,
}

impl SignedContainerLaunchRecord {
    pub fn sign(record: ContainerLaunchRecord, keypair: &Keypair) -> Result<Self, ProcessError> {
        record.validate()?;
        let signature = keypair.sign_wrapped(
            CONTAINER_LAUNCH_RECORD_SCHEMA,
            &CanonicalBytes::from_serializable(&record)?,
        )?;
        Ok(Self {
            record,
            signer: keypair.public_key(),
            signature,
        })
    }

    pub fn verify(
        &self,
        trusted_signer: &PublicKey,
    ) -> Result<&ContainerLaunchRecord, ProcessError> {
        if &self.signer != trusted_signer
            || verify_wrapped(
                trusted_signer,
                CONTAINER_LAUNCH_RECORD_SCHEMA,
                &self.record,
                &self.signature,
            )
            .is_err()
        {
            return Err(ProcessError::Invalid("container launch record signature"));
        }
        self.record.validate()?;
        Ok(&self.record)
    }

    pub fn sha256(&self) -> Result<String, ProcessError> {
        Ok(chio_core_types::sha256_hex(
            &chio_core_types::canonical_json_bytes(self)?,
        ))
    }

    /// The worker-lane attribution this launch supports. Only a fully
    /// enforced launch yields a `container` profile.
    pub fn worker_profile(&self) -> Result<WorkerProfile, ProcessError> {
        if self.record.state != CageEnforcementState::FullyEnforced {
            return Err(ProcessError::Invalid(
                "only a fully enforced container launch supports a worker profile",
            ));
        }
        Ok(WorkerProfile {
            kind: WorkerProfileKind::Container,
            launch_ref: LaunchRef {
                record_id: self.record.container_id.clone(),
                record_sha256: self.sha256()?,
            },
            launch_attempt: self.record.attempt,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerProfileKind {
    Container,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchRef {
    pub record_id: String,
    pub record_sha256: String,
}

/// Host-sourced worker confinement, bound to one launch attempt. An absent
/// profile renders as `direct` and never satisfies a confinement requirement.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerProfile {
    pub kind: WorkerProfileKind,
    pub launch_ref: LaunchRef,
    pub launch_attempt: u32,
}

#[cfg(test)]
#[path = "container_launch_tests.rs"]
mod tests;
