//! Typed private label references retain every semantic field exactly.
use crate::admission_operation_store::{invariant, AdmissionOperationStoreError};
use chio_security_types::knowledge::*;
use chio_security_types::ports::BoundedVec;
use chio_security_types::recovery::*;
use chio_security_types::InformationLabel;
use serde::{Deserialize, Serialize};

/// Nine explicit journal label fields plus six before/after images from the
/// three closed native flow-label tables require at most fifteen labels.
const MAX_LABELS: usize = 16;

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct LabelIndex(u8);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LabelTable {
    values: BoundedVec<InformationLabel, MAX_LABELS>,
}

pub(crate) struct LabelTableBuilder {
    values: Vec<InformationLabel>,
}

impl LabelTableBuilder {
    pub(crate) fn new() -> Self {
        Self { values: Vec::new() }
    }
    pub(crate) fn insert(
        &mut self,
        label: &InformationLabel,
    ) -> Result<LabelIndex, AdmissionOperationStoreError> {
        if let Some(index) = self.values.iter().position(|known| known == label) {
            return u8::try_from(index).map(LabelIndex).map_err(|_| invalid());
        }
        if self.values.len() == MAX_LABELS {
            return Err(invalid());
        }
        let index = u8::try_from(self.values.len()).map_err(|_| invalid())?;
        self.values.push(label.clone());
        Ok(LabelIndex(index))
    }
    pub(crate) fn finish(self) -> Result<LabelTable, AdmissionOperationStoreError> {
        Ok(LabelTable {
            values: BoundedVec::new(self.values).map_err(|_| invalid())?,
        })
    }
}

impl LabelTable {
    pub(crate) fn validate(&self) -> Result<(), AdmissionOperationStoreError> {
        if self.values.is_empty()
            || self
                .values
                .as_slice()
                .iter()
                .enumerate()
                .any(|(index, value)| self.values.as_slice()[..index].contains(value))
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub(crate) fn label(
        &self,
        index: LabelIndex,
    ) -> Result<&InformationLabel, AdmissionOperationStoreError> {
        self.values
            .as_slice()
            .get(usize::from(index.0))
            .ok_or_else(invalid)
    }
    pub(crate) fn label_bytes(
        &self,
        index: LabelIndex,
    ) -> Result<Vec<u8>, AdmissionOperationStoreError> {
        chio_core::canonical_json_bytes(self.label(index)?).map_err(|_| invalid())
    }

    /// Counts the original precise labels before any repeated expansion.
    /// The stored body retains its existing ceiling; callers multiply this
    /// maximum by their closed schema's number of label occurrences.
    pub(crate) fn maximum_label_bytes(&self) -> Result<usize, AdmissionOperationStoreError> {
        self.validate()?;
        self.values.as_slice().iter().try_fold(0, |largest, label| {
            Ok(largest.max(
                chio_core::canonical_json_bytes(label)
                    .map_err(|_| invalid())?
                    .len(),
            ))
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredRecipient {
    recipient: ArtifactRecipientId,
    scope: RecoveryScopeV1,
    runtime: ProtectedText<128>,
    principal: chio_security_types::PrincipalId,
    lineage: IsolationLineageId,
    isolation_epoch: ProtectedText<128>,
    context_generation: SafeInteger,
    clearance: LabelIndex,
    sink: ArtifactSinkV1,
}

impl StoredRecipient {
    pub(crate) fn capture(
        value: &ArtifactRecipientV1,
        labels: &mut LabelTableBuilder,
    ) -> Result<Self, AdmissionOperationStoreError> {
        Ok(Self {
            recipient: value.recipient.clone(),
            scope: value.scope.clone(),
            runtime: value.runtime.clone(),
            principal: value.principal.clone(),
            lineage: value.lineage.clone(),
            isolation_epoch: value.isolation_epoch.clone(),
            context_generation: value.context_generation,
            clearance: labels.insert(&value.clearance)?,
            sink: value.sink.clone(),
        })
    }
    pub(crate) fn expand(
        &self,
        labels: &LabelTable,
    ) -> Result<ArtifactRecipientV1, AdmissionOperationStoreError> {
        Ok(ArtifactRecipientV1 {
            recipient: self.recipient.clone(),
            scope: self.scope.clone(),
            runtime: self.runtime.clone(),
            principal: self.principal.clone(),
            lineage: self.lineage.clone(),
            isolation_epoch: self.isolation_epoch.clone(),
            context_generation: self.context_generation,
            clearance: labels.label(self.clearance)?.clone(),
            sink: self.sink.clone(),
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredRelease {
    domain_version: VersionV1,
    release: ReleaseId,
    kind: ArtifactReleaseKindV1,
    artifact: ArtifactVersionRefV1,
    source_label: LabelIndex,
    admitted_label: LabelIndex,
    influence: ArtifactInfluenceV1,
    recipient: StoredRecipient,
    policy: PolicyDigest,
    authorization: ReleaseAuthorizationDigest,
    observation_transition: EvidenceRef,
    observation_generation: SafeInteger,
    state: ArtifactDeliveryStateV1,
}

impl StoredRelease {
    pub(crate) fn capture(
        value: &ArtifactReleaseIntentV1,
        labels: &mut LabelTableBuilder,
    ) -> Result<Self, AdmissionOperationStoreError> {
        Ok(Self {
            domain_version: value.domain_version,
            release: value.release.clone(),
            kind: value.kind.clone(),
            artifact: value.artifact.clone(),
            source_label: labels.insert(&value.source_label)?,
            admitted_label: labels.insert(&value.admitted_label)?,
            influence: value.influence.clone(),
            recipient: StoredRecipient::capture(&value.recipient, labels)?,
            policy: value.policy,
            authorization: value.authorization,
            observation_transition: value.observation_transition.clone(),
            observation_generation: value.observation_generation,
            state: value.state,
        })
    }
    pub(crate) fn expand(
        &self,
        labels: &LabelTable,
    ) -> Result<ArtifactReleaseIntentV1, AdmissionOperationStoreError> {
        Ok(ArtifactReleaseIntentV1 {
            domain_version: self.domain_version,
            release: self.release.clone(),
            kind: self.kind.clone(),
            artifact: self.artifact.clone(),
            source_label: labels.label(self.source_label)?.clone(),
            admitted_label: labels.label(self.admitted_label)?.clone(),
            influence: self.influence.clone(),
            recipient: self.recipient.expand(labels)?,
            policy: self.policy,
            authorization: self.authorization,
            observation_transition: self.observation_transition.clone(),
            observation_generation: self.observation_generation,
            state: self.state,
        })
    }
}

fn invalid() -> AdmissionOperationStoreError {
    invariant("knowledge label encoding is invalid")
}
