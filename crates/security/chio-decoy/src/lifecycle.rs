// Adapted from Clawdstrike concepts; see docs/security/clawdstrike-active-defense-provenance.md.
use chio_security_types::{
    DecoyErrorClass, DecoyLifecycle, DecoyLifecycleState, DecoyOperationAttempt,
    DecoyOperationKind, DecoyRecord,
};
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArmedReplacement {
    tenant_id: chio_security_types::ports::TenantId,
    predecessor_artifact_id: chio_security_types::ports::ArtifactId,
    artifact_id: chio_security_types::ports::ArtifactId,
    version: chio_security_types::DecoyVersion,
    version_hash: chio_security_types::ports::Digest32,
}

impl ArmedReplacement {
    pub fn new(old: &DecoyRecord, replacement: &DecoyRecord) -> Result<Self, LifecycleError> {
        old.validate().map_err(|_| LifecycleError::InvalidRecord)?;
        replacement
            .validate()
            .map_err(|_| LifecycleError::InvalidRecord)?;
        if !replacement.lifecycle.is_matchable() {
            return Err(LifecycleError::ReplacementNotArmed);
        }
        let expected_version = old
            .version
            .checked_next()
            .map_err(|_| LifecycleError::VersionOverflow)?;
        if old.tenant_id != replacement.tenant_id
            || old.artifact_id == replacement.artifact_id
            || old.surface != replacement.surface
            || old.scope_id != replacement.scope_id
            || old.successor_artifact_id.as_ref() != Some(&replacement.artifact_id)
            || replacement.predecessor_artifact_id.as_ref() != Some(&old.artifact_id)
            || replacement.version != expected_version
        {
            return Err(LifecycleError::ReplacementMismatch);
        }
        Ok(Self {
            tenant_id: replacement.tenant_id.clone(),
            predecessor_artifact_id: old.artifact_id.clone(),
            artifact_id: replacement.artifact_id.clone(),
            version: replacement.version,
            version_hash: replacement.version_hash,
        })
    }

    fn validates(&self, old: &DecoyRecord, attempt: &DecoyOperationAttempt) -> bool {
        self.tenant_id == old.tenant_id
            && self.predecessor_artifact_id == old.artifact_id
            && old.successor_artifact_id.as_ref() == Some(&self.artifact_id)
            && attempt.successor_artifact_id.as_ref() == Some(&self.artifact_id)
            && old
                .version
                .checked_next()
                .is_ok_and(|expected| expected == self.version)
            && self.version_hash != old.version_hash
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LifecycleError {
    #[error("decoy record is invalid")]
    InvalidRecord,
    #[error("decoy generation does not match")]
    GenerationConflict,
    #[error("decoy version does not match")]
    VersionConflict,
    #[error("decoy generation overflow")]
    GenerationOverflow,
    #[error("decoy version overflow")]
    VersionOverflow,
    #[error("decoy lifecycle edge is illegal")]
    IllegalEdge,
    #[error("decoy operation shape is invalid")]
    InvalidOperation,
    #[error("decoy error recovery permits only exact retry or retirement")]
    RecoveryRestricted,
    #[error("decoy retry does not match the recorded attempt")]
    RetryMismatch,
    #[error("decoy is not in an error state")]
    NotInError,
    #[error("an armed replacement is required")]
    ReplacementRequired,
    #[error("replacement is not armed")]
    ReplacementNotArmed,
    #[error("replacement does not match the rotating artifact")]
    ReplacementMismatch,
}

pub fn transition(
    current: &DecoyRecord,
    attempt: &DecoyOperationAttempt,
    replacement: Option<&ArmedReplacement>,
) -> Result<DecoyRecord, LifecycleError> {
    current
        .validate()
        .map_err(|_| LifecycleError::InvalidRecord)?;
    if matches!(current.lifecycle, DecoyLifecycle::Error { .. }) {
        if attempt.kind != DecoyOperationKind::Retire {
            return Err(LifecycleError::RecoveryRestricted);
        }
        validate_current_attempt(current, attempt)?;
        validate_shape(attempt, true)?;
        return revised(current, DecoyLifecycle::Retired, None);
    }
    validate_current_attempt(current, attempt)?;

    let prior = current
        .lifecycle
        .state()
        .ok_or(LifecycleError::InvalidRecord)?;
    let target = target_for(prior, attempt.kind)?;
    validate_shape(attempt, false)?;
    revise_for_target(current, attempt, target, replacement)
}

pub fn fail_transition(
    current: &DecoyRecord,
    attempt: &DecoyOperationAttempt,
    error_class: DecoyErrorClass,
) -> Result<DecoyRecord, LifecycleError> {
    current
        .validate()
        .map_err(|_| LifecycleError::InvalidRecord)?;
    validate_current_attempt(current, attempt)?;
    let prior = current
        .lifecycle
        .state()
        .ok_or(LifecycleError::RecoveryRestricted)?;
    let _ = target_for(prior, attempt.kind)?;
    validate_shape(attempt, false)?;
    revised(
        current,
        DecoyLifecycle::Error {
            prior,
            attempted: attempt.clone(),
            error_class,
        },
        current.successor_artifact_id.clone(),
    )
}

pub fn retry_transition(
    current: &DecoyRecord,
    attempted: &DecoyOperationAttempt,
    replacement: Option<&ArmedReplacement>,
) -> Result<DecoyRecord, LifecycleError> {
    current
        .validate()
        .map_err(|_| LifecycleError::InvalidRecord)?;
    let DecoyLifecycle::Error {
        prior,
        attempted: recorded,
        ..
    } = &current.lifecycle
    else {
        return Err(LifecycleError::NotInError);
    };
    if recorded != attempted {
        return Err(LifecycleError::RetryMismatch);
    }
    let target = target_for(*prior, recorded.kind)?;
    validate_shape(recorded, false)?;
    revise_for_target(current, recorded, target, replacement)
}

fn validate_current_attempt(
    current: &DecoyRecord,
    attempt: &DecoyOperationAttempt,
) -> Result<(), LifecycleError> {
    if attempt.expected_generation != current.generation {
        return Err(LifecycleError::GenerationConflict);
    }
    if attempt.expected_version != current.version {
        return Err(LifecycleError::VersionConflict);
    }
    Ok(())
}

fn validate_shape(
    attempt: &DecoyOperationAttempt,
    retiring_error: bool,
) -> Result<(), LifecycleError> {
    let successor_is_valid = match attempt.kind {
        DecoyOperationKind::BeginRotation => attempt.successor_artifact_id.is_some(),
        DecoyOperationKind::Retire => retiring_error || attempt.successor_artifact_id.is_some(),
        DecoyOperationKind::BeginMaterialization
        | DecoyOperationKind::Arm
        | DecoyOperationKind::Trigger => attempt.successor_artifact_id.is_none(),
    };
    if successor_is_valid {
        Ok(())
    } else {
        Err(LifecycleError::InvalidOperation)
    }
}

fn target_for(
    prior: DecoyLifecycleState,
    kind: DecoyOperationKind,
) -> Result<DecoyLifecycleState, LifecycleError> {
    match (prior, kind) {
        (DecoyLifecycleState::Planned, DecoyOperationKind::BeginMaterialization) => {
            Ok(DecoyLifecycleState::Materializing)
        }
        (DecoyLifecycleState::Materializing, DecoyOperationKind::Arm) => {
            Ok(DecoyLifecycleState::Armed)
        }
        (DecoyLifecycleState::Armed, DecoyOperationKind::Trigger) => {
            Ok(DecoyLifecycleState::Triggered)
        }
        (DecoyLifecycleState::Triggered, DecoyOperationKind::BeginRotation) => {
            Ok(DecoyLifecycleState::Rotating)
        }
        (DecoyLifecycleState::Rotating, DecoyOperationKind::Retire) => {
            Ok(DecoyLifecycleState::Retired)
        }
        _ => Err(LifecycleError::IllegalEdge),
    }
}

fn revise_for_target(
    current: &DecoyRecord,
    attempt: &DecoyOperationAttempt,
    target: DecoyLifecycleState,
    replacement: Option<&ArmedReplacement>,
) -> Result<DecoyRecord, LifecycleError> {
    let successor = match target {
        DecoyLifecycleState::Rotating => attempt.successor_artifact_id.clone(),
        DecoyLifecycleState::Retired => {
            let replacement = replacement.ok_or(LifecycleError::ReplacementRequired)?;
            if !replacement.validates(current, attempt) {
                return Err(LifecycleError::ReplacementMismatch);
            }
            current.successor_artifact_id.clone()
        }
        _ => current.successor_artifact_id.clone(),
    };
    revised(current, target.into(), successor)
}

fn revised(
    current: &DecoyRecord,
    lifecycle: DecoyLifecycle,
    successor_artifact_id: Option<chio_security_types::ports::ArtifactId>,
) -> Result<DecoyRecord, LifecycleError> {
    let generation = current
        .generation
        .checked_add(1)
        .ok_or(LifecycleError::GenerationOverflow)?;
    let mut revised = current.clone();
    revised.lifecycle = lifecycle;
    revised.generation = generation;
    revised.successor_artifact_id = successor_artifact_id;
    revised
        .validate()
        .map_err(|_| LifecycleError::InvalidRecord)?;
    Ok(revised)
}
