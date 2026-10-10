use super::{ArtifactInfluenceV1, ArtifactVersionRefV1, ModelContextV1};
use crate::{flow::InformationLabel, recovery::*};
use serde::{Deserialize, Serialize};

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabeledCheckpointV1 {
    pub domain_version: VersionV1,
    pub checkpoint: CheckpointId,
    pub revision: SafeInteger,
    pub scope: RecoveryScopeV1,
    pub runtime: ProtectedText<128>,
    pub artifacts: NonEmptyBoundedList<ArtifactVersionRefV1, 8>,
    pub model_contexts: BoundedList<ModelContextV1, 8>,
    pub label: InformationLabel,
    pub influence: ArtifactInfluenceV1,
    pub lineage: IsolationLineageId,
    pub isolation_epoch: ProtectedText<128>,
    pub native_evidence_sequence: SafeInteger,
    pub policy: PolicyDigest,
}
impl LabeledCheckpointV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.revision.get() == 0
            || self.native_evidence_sequence.get() == 0
            || self.artifacts.as_slice().iter().any(|artifact| {
                artifact.scope.tenant_id != self.scope.tenant_id
                    || artifact.scope.authority_domain != self.scope.authority_domain
            })
        {
            return Err(ContractError::BindingMismatch);
        }
        for (index, context) in self.model_contexts.as_slice().iter().enumerate() {
            if self.model_contexts.as_slice()[..index]
                .iter()
                .any(|old| old.context == context.context)
            {
                return Err(ContractError::BindingMismatch);
            }
        }
        Ok(())
    }
}

super::protected_debug!(LabeledCheckpointV1);
