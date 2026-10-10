use super::{BoundedList, ContractError, DeploymentDigest, VersionV1};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementFeature {
    NativeCapture,
    RecoveryBoundGrant,
    ExactRequestCustody,
    CurrentAudience,
    OperationOwnedNonce,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryAttachmentProfile {
    Ordinary,
    OperationOwnedNonce,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RecoveryProfileSchema {
    #[serde(rename = "chio.recovery.profile-requirements.v1")]
    V1,
}

/// An immutable requirement, never a client negotiation result. A matching
/// inventory is necessary but does not qualify or enable a live deployment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RecoveryProfileRequirementsV1 {
    schema: RecoveryProfileSchema,
    protocol_version: VersionV1,
    deployment_digest: DeploymentDigest,
    attachment_profile: RecoveryAttachmentProfile,
    required_features: BoundedList<EnforcementFeature, 5>,
}
impl RecoveryProfileRequirementsV1 {
    pub fn new(
        deployment_digest: DeploymentDigest,
        attachment_profile: RecoveryAttachmentProfile,
        required_features: BoundedList<EnforcementFeature, 5>,
    ) -> Result<Self, ContractError> {
        let features = required_features.as_slice();
        if features.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(ContractError::UnsupportedProfile);
        }
        let baseline = [
            EnforcementFeature::NativeCapture,
            EnforcementFeature::RecoveryBoundGrant,
            EnforcementFeature::ExactRequestCustody,
            EnforcementFeature::CurrentAudience,
        ];
        if baseline.iter().any(|feature| !features.contains(feature))
            || (attachment_profile == RecoveryAttachmentProfile::OperationOwnedNonce
                && !features.contains(&EnforcementFeature::OperationOwnedNonce))
        {
            return Err(ContractError::UnsupportedProfile);
        }
        Ok(Self {
            schema: RecoveryProfileSchema::V1,
            protocol_version: VersionV1,
            deployment_digest,
            attachment_profile,
            required_features,
        })
    }
    pub fn check_inventory(
        &self,
        deployment: DeploymentDigest,
        enforced: &BoundedList<EnforcementFeature, 5>,
    ) -> Result<(), ContractError> {
        if deployment != self.deployment_digest {
            return Err(ContractError::BindingMismatch);
        }
        if enforced
            .as_slice()
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
            || self
                .required_features
                .as_slice()
                .iter()
                .any(|feature| !enforced.as_slice().contains(feature))
        {
            return Err(ContractError::UnsupportedProfile);
        }
        Ok(())
    }
    pub const fn attachment_profile(&self) -> RecoveryAttachmentProfile {
        self.attachment_profile
    }
}
impl<'de> Deserialize<'de> for RecoveryProfileRequirementsV1 {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            schema: RecoveryProfileSchema,
            protocol_version: VersionV1,
            deployment_digest: DeploymentDigest,
            attachment_profile: RecoveryAttachmentProfile,
            required_features: BoundedList<EnforcementFeature, 5>,
        }
        let Wire {
            schema: RecoveryProfileSchema::V1,
            protocol_version: VersionV1,
            deployment_digest,
            attachment_profile,
            required_features,
        } = Wire::deserialize(d)?;
        Self::new(deployment_digest, attachment_profile, required_features)
            .map_err(serde::de::Error::custom)
    }
}
