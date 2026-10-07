use super::SemanticOutputDispositionV1;
use crate::recovery::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SemanticPlanInputV1 {
    Exact {
        resource: ProviderResourceId,
        version: ArtifactVersionId,
        material: CanonicalPayloadDigest,
    },
    FutureOutput {
        step: StepId,
    },
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticPlanStepV1 {
    pub step: StepId,
    pub operation: SemanticOperationId,
    pub destination: SemanticDestinationId,
    pub dependencies: BoundedList<StepId, 8>,
    pub inputs: NonEmptyBoundedList<SemanticPlanInputV1, 16>,
    pub output: SemanticOutputDispositionV1,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticPlanV1 {
    pub domain_version: VersionV1,
    pub scope: RecoveryScopeV1,
    pub registry: SemanticRegistryDigest,
    /// The predecessor's structural ceiling stays readable for already owned
    /// captures. Fresh acceptance and capture enforce eight top-level steps.
    pub steps: NonEmptyBoundedList<SemanticPlanStepV1, 16>,
}
impl SemanticPlanV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        Ok(())
    }
}

super::protected_debug!(SemanticPlanV1, SemanticPlanStepV1, SemanticPlanInputV1);
