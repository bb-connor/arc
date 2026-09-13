use std::fmt;
use std::sync::Arc;

use chio_security_types::ports::TenantId;
use chio_security_types::{DecoyEvidenceRef, DecoyLifecycleState, DecoySurface};
use thiserror::Error;

use crate::registry::{PrivateDecoyRegistry, RegistryError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationClass {
    DirectPresentation,
    InventoryScanner,
    BackupReader,
    OperatorTouch,
    TestHarness,
    InternalTelemetry,
}

pub struct TripwireObservation<'a> {
    pub tenant_id: &'a TenantId,
    pub surface: DecoySurface,
    pub presented: &'a [u8],
    pub class: ObservationClass,
    pub observed_at_unix_ms: u64,
}

impl fmt::Debug for TripwireObservation<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TripwireObservation")
            .field("tenant_id", self.tenant_id)
            .field("surface", &self.surface)
            .field("presented", &"<redacted>")
            .field("class", &self.class)
            .field("observed_at_unix_ms", &self.observed_at_unix_ms)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetectionConfidence {
    High,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecoyDetection {
    ActiveMatch {
        evidence: DecoyEvidenceRef,
        confidence: DetectionConfidence,
        malice_proven: bool,
        requires_immediate_deny: bool,
    },
    InactiveObservation {
        evidence: DecoyEvidenceRef,
        lifecycle: DecoyLifecycleState,
        expired: bool,
    },
    Clear,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DetectionFailure {
    #[error("tripwire observation is invalid")]
    InvalidObservation,
    #[error("tripwire registry is unavailable")]
    RegistryUnavailable,
    #[error("tripwire registry integrity validation failed")]
    RegistryIntegrityFailure,
    #[error("tripwire lifecycle is in an error state")]
    LifecycleError,
}

pub struct DecoyDetector {
    registry: Arc<PrivateDecoyRegistry>,
}

impl DecoyDetector {
    #[must_use]
    pub fn new(registry: Arc<PrivateDecoyRegistry>) -> Self {
        Self { registry }
    }

    pub fn detect(
        &self,
        observation: &TripwireObservation<'_>,
    ) -> Result<DecoyDetection, DetectionFailure> {
        if observation.observed_at_unix_ms == 0 || observation.presented.is_empty() {
            return Err(DetectionFailure::InvalidObservation);
        }
        let Some(resolved) = self
            .registry
            .resolve_marker(
                observation.tenant_id,
                observation.surface,
                observation.presented,
            )
            .map_err(map_registry_error)?
        else {
            return Ok(DecoyDetection::Clear);
        };
        let Some(lifecycle) = resolved.record.lifecycle.state() else {
            return Err(DetectionFailure::LifecycleError);
        };
        let expired = observation.observed_at_unix_ms >= resolved.record.expires_at_unix_ms;
        if resolved.record.lifecycle.is_matchable() && !expired {
            return Ok(DecoyDetection::ActiveMatch {
                evidence: resolved.evidence,
                confidence: DetectionConfidence::High,
                malice_proven: false,
                requires_immediate_deny: matches!(
                    observation.class,
                    ObservationClass::DirectPresentation
                ),
            });
        }
        Ok(DecoyDetection::InactiveObservation {
            evidence: resolved.evidence,
            lifecycle,
            expired,
        })
    }
}

fn map_registry_error(error: RegistryError) -> DetectionFailure {
    match error {
        RegistryError::Unavailable | RegistryError::KeyUnavailable => {
            DetectionFailure::RegistryUnavailable
        }
        RegistryError::InvalidRequest
        | RegistryError::EmptySecret
        | RegistryError::SecretTooLarge => DetectionFailure::InvalidObservation,
        RegistryError::Lifecycle(_) => DetectionFailure::LifecycleError,
        RegistryError::AuthorizationDenied
        | RegistryError::AuthorizationExpired
        | RegistryError::ExportLimitExceeded
        | RegistryError::InvalidCredential
        | RegistryError::InvalidGrant
        | RegistryError::NotFound
        | RegistryError::Conflict
        | RegistryError::IntegrityFailure
        | RegistryError::AuthenticationFailed
        | RegistryError::Serialization
        | RegistryError::Materialization(_) => DetectionFailure::RegistryIntegrityFailure,
    }
}
