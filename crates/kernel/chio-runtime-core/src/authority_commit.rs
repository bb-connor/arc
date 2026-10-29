use chio_kernel::admission_operation::runtime_participant::{
    RuntimeParticipantClaimIntentV1, RuntimeParticipantClaimReferenceV1,
};
use chio_kernel::admission_operation::{AdmissionIdentifier, RuntimeSourceQualificationV1};
use serde::{Deserialize, Serialize};

use crate::{RuntimeTrustFloorEntry, TreatyScope};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeTreatyAuthorizationBinding {
    pub(crate) verifier_id: AdmissionIdentifier,
    pub(crate) scope: TreatyScope,
    pub(crate) reference: RuntimeParticipantClaimReferenceV1,
    pub(crate) intent: RuntimeParticipantClaimIntentV1,
}

impl RuntimeTreatyAuthorizationBinding {
    pub fn verifier_id(&self) -> &AdmissionIdentifier {
        &self.verifier_id
    }

    pub fn scope(&self) -> &TreatyScope {
        &self.scope
    }

    pub fn reference(&self) -> &RuntimeParticipantClaimReferenceV1 {
        &self.reference
    }

    pub fn intent(&self) -> &RuntimeParticipantClaimIntentV1 {
        &self.intent
    }
}

#[derive(Clone, Debug)]
pub struct RuntimeTreatyAuthorizationRequest {
    pub(crate) binding: RuntimeTreatyAuthorizationBinding,
    pub(crate) now_unix_ms: u64,
    pub(crate) source_qualification: RuntimeSourceQualificationV1,
}

impl RuntimeTreatyAuthorizationRequest {
    pub fn source_qualification(&self) -> &RuntimeSourceQualificationV1 {
        &self.source_qualification
    }

    pub fn binding(&self) -> &RuntimeTreatyAuthorizationBinding {
        &self.binding
    }

    pub fn now_unix_ms(&self) -> u64 {
        self.now_unix_ms
    }
}

#[derive(Clone, Debug)]
pub struct RuntimeTrustFloorUpdate {
    pub(crate) entry: RuntimeTrustFloorEntry,
    pub(crate) previous_hash_sha256: Option<String>,
}

impl RuntimeTrustFloorUpdate {
    pub fn entry(&self) -> &RuntimeTrustFloorEntry {
        &self.entry
    }

    pub fn previous_hash_sha256(&self) -> Option<&str> {
        self.previous_hash_sha256.as_deref()
    }
}

#[derive(Clone, Debug)]
pub struct RuntimeAdmissionAuthorityCommit {
    pub(crate) treaty: Option<RuntimeTreatyAuthorizationRequest>,
    pub(crate) trust_floor: Option<RuntimeTrustFloorUpdate>,
}

impl RuntimeAdmissionAuthorityCommit {
    pub fn treaty(&self) -> Option<&RuntimeTreatyAuthorizationRequest> {
        self.treaty.as_ref()
    }

    pub fn trust_floor(&self) -> Option<&RuntimeTrustFloorUpdate> {
        self.trust_floor.as_ref()
    }
}
