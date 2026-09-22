//! Original trusted configuration data, never activation or claim authority.

use super::governed_approval_claim::GovernedApprovalAuthorityBindingV1;
use super::runtime_participant::RuntimeParticipantAuthorityBindingV1;
use super::AdmissionOperationStoreError;
use crate::dpop::authority::DpopReplayAuthorityV1;
use crate::supplemental_admission::SupplementalAdmissionAuthorityBindingV1;
use serde::{Deserialize, Deserializer, Serialize};

const SCHEMA: &str = "chio.admission-authority-profile.v1";
const CALLER_SCHEMA: &str = "chio.admission-authority-profile.v2";
const SUPPLEMENTAL_SCHEMA: &str = "chio.admission-authority-profile.v3";

/// Explicit selections, including absence, observed before original admission.
/// Stable source generations and DPoP freshness policy are retained; current
/// owner epochs, executable handles and reusable credentials are not.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionAuthoritySelectionV1 {
    pub runtime_hook_installed: bool,
    pub swarm_admission_required: bool,
    pub runtime_enforces_swarm_authority: bool,
    pub runtime_requires_dispatch_revalidation: bool,
    #[serde(deserialize_with = "required_option")]
    pub runtime: Option<RuntimeParticipantAuthorityBindingV1>,
    #[serde(deserialize_with = "required_option")]
    pub approval: Option<GovernedApprovalAuthorityBindingV1>,
    #[serde(deserialize_with = "required_option")]
    pub dpop: Option<DpopReplayAuthorityV1>,
}

// A missing selection field is not evidence of an explicitly absent selection.
fn required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::deserialize(deserializer)
}

/// Bounded typed historical data. A store must bind it to the actual retained
/// operation and independently verify activation and the current recovery lease.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "Wire")]
pub struct AdmissionAuthorityProfileV1 {
    schema: String,
    selection: AdmissionAuthoritySelectionV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    caller_executor: Option<crate::caller_delivery::CallerExecutorIdentityV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    supplemental_participant: Option<SupplementalAdmissionAuthorityBindingV1>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    schema: String,
    selection: AdmissionAuthoritySelectionV1,
    #[serde(default, deserialize_with = "present_executor")]
    caller_executor: Option<crate::caller_delivery::CallerExecutorIdentityV1>,
    #[serde(default, deserialize_with = "present_participant")]
    supplemental_participant: Option<SupplementalAdmissionAuthorityBindingV1>,
}

fn present_participant<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<SupplementalAdmissionAuthorityBindingV1>, D::Error> {
    SupplementalAdmissionAuthorityBindingV1::deserialize(deserializer).map(Some)
}

fn present_executor<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<crate::caller_delivery::CallerExecutorIdentityV1>, D::Error> {
    crate::caller_delivery::CallerExecutorIdentityV1::deserialize(deserializer).map(Some)
}

impl TryFrom<Wire> for AdmissionAuthorityProfileV1 {
    type Error = AdmissionOperationStoreError;

    fn try_from(wire: Wire) -> Result<Self, Self::Error> {
        match (
            wire.schema.as_str(),
            wire.caller_executor,
            wire.supplemental_participant,
        ) {
            (SCHEMA, None, None) => Self::new(wire.selection),
            (CALLER_SCHEMA, Some(executor), None) => {
                Self::new(wire.selection)?.with_caller_executor(executor)
            }
            (SUPPLEMENTAL_SCHEMA, executor, Some(participant)) => {
                let mut profile = Self::new(wire.selection)?;
                if let Some(executor) = executor {
                    profile = profile.with_caller_executor(executor)?;
                }
                Ok(profile.with_supplemental_participant(participant))
            }
            _ => Err(invalid("unsupported admission authority profile selection")),
        }
    }
}

impl AdmissionAuthorityProfileV1 {
    /// Complete original configuration, including legacy hook presence. The
    /// absence of an owned binding alone does not prove absence of authority.
    #[must_use]
    pub fn selection(&self) -> &AdmissionAuthoritySelectionV1 {
        &self.selection
    }

    pub fn new(
        selection: AdmissionAuthoritySelectionV1,
    ) -> Result<Self, AdmissionOperationStoreError> {
        if (!selection.runtime_hook_installed
            && (selection.runtime.is_some()
                || selection.runtime_enforces_swarm_authority
                || selection.runtime_requires_dispatch_revalidation))
            || (selection.runtime.is_some() && !selection.runtime_requires_dispatch_revalidation)
        {
            return Err(invalid(
                "inconsistent admission runtime authority selection",
            ));
        }
        Ok(Self {
            schema: SCHEMA.into(),
            selection,
            caller_executor: None,
            supplemental_participant: None,
        })
    }

    /// Pin the trusted executor before admission. Historical v1 selections
    /// remain unconfigured and cannot adopt a key supplied by a report.
    pub fn with_caller_executor(
        mut self,
        executor: crate::caller_delivery::CallerExecutorIdentityV1,
    ) -> Result<Self, AdmissionOperationStoreError> {
        executor
            .validate()
            .map_err(|_| invalid("invalid caller executor selection"))?;
        self.schema = if self.supplemental_participant.is_some() {
            SUPPLEMENTAL_SCHEMA
        } else {
            CALLER_SCHEMA
        }
        .into();
        self.caller_executor = Some(executor);
        Ok(self)
    }

    #[must_use]
    pub fn caller_executor(&self) -> Option<&crate::caller_delivery::CallerExecutorIdentityV1> {
        self.caller_executor.as_ref()
    }

    #[must_use]
    pub fn with_supplemental_participant(
        mut self,
        participant: SupplementalAdmissionAuthorityBindingV1,
    ) -> Self {
        self.schema = SUPPLEMENTAL_SCHEMA.into();
        self.supplemental_participant = Some(participant);
        self
    }

    #[must_use]
    pub fn supplemental_participant(&self) -> Option<&SupplementalAdmissionAuthorityBindingV1> {
        self.supplemental_participant.as_ref()
    }

    #[must_use]
    pub fn runtime(&self) -> Option<&RuntimeParticipantAuthorityBindingV1> {
        self.selection.runtime.as_ref()
    }

    #[must_use]
    pub fn approval(&self) -> Option<&GovernedApprovalAuthorityBindingV1> {
        self.selection.approval.as_ref()
    }

    #[must_use]
    pub fn dpop(&self) -> Option<&DpopReplayAuthorityV1> {
        self.selection.dpop.as_ref()
    }

    #[must_use]
    pub fn has_operation_owned_authority(&self) -> bool {
        self.runtime().is_some()
            || self.approval().is_some()
            || self.dpop().is_some()
            || self.caller_executor().is_some()
            || self.supplemental_participant().is_some()
    }
}

impl std::fmt::Debug for AdmissionAuthorityProfileV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdmissionAuthorityProfileV1")
            .finish_non_exhaustive()
    }
}

fn invalid(message: &str) -> AdmissionOperationStoreError {
    AdmissionOperationStoreError::Invariant(message.into())
}

#[cfg(test)]
mod tests;
