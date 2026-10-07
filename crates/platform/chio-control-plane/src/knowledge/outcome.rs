//! Requester-visible delivery facts omit private native observation metadata.
use super::*;

/// The full admitted intent stays with the serving writer and selected host
/// sink. A requester receives only its opaque release identity and outcome.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDeliveryOutcomeV1 {
    pub release: ReleaseId,
    pub state: ArtifactDeliveryStateV1,
}

impl ArtifactDeliveryOutcomeV1 {
    pub(super) fn delivered(intent: &ArtifactReleaseIntentV1) -> Self {
        Self {
            release: intent.release.clone(),
            state: ArtifactDeliveryStateV1::Delivered,
        }
    }
}
