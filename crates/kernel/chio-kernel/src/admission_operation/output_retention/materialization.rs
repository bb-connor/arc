//! Pure original-bound materialization identity for native phase planning.
//! Decoding a profile or obtaining this identity grants no loan or dispatch.

use serde::Serialize;

use crate::admission_operation::{
    AdmissionDigest, AdmissionIdentifier, AdmissionOperationStoreError,
    NativeOutputRetentionProfileV1,
};
use crate::tool_outcome::{EvaluationModeV1, EvaluationPhaseV1, FrozenEvaluationStepV1};

#[derive(Serialize)]
enum MaterializerSchema {
    #[serde(rename = "chio.kernel-bounded-output-materialization.v1")]
    V1,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ImplementationSelection<'a> {
    schema: MaterializerSchema,
    original_retention: &'a NativeOutputRetentionProfileV1,
}

pub(crate) fn materialization_identity(
    original_retention: &NativeOutputRetentionProfileV1,
) -> Result<FrozenEvaluationStepV1, AdmissionOperationStoreError> {
    let canonical = chio_core::canonical::canonical_json_bytes(&ImplementationSelection {
        schema: MaterializerSchema::V1,
        original_retention,
    })
    .map_err(|_| {
        AdmissionOperationStoreError::Invariant(
            "original bounded materializer identity encoding failed".into(),
        )
    })?;
    Ok(FrozenEvaluationStepV1 {
        phase: EvaluationPhaseV1::OutputGuard,
        position: 0,
        component_id: AdmissionIdentifier::try_new(
            "component_id",
            "kernel-bounded-output-materialization",
        )?,
        component_version: AdmissionIdentifier::try_new("component_version", "v1")?,
        implementation_digest: AdmissionDigest::try_new(
            "implementation_digest",
            chio_core::sha256_hex(&canonical),
        )?,
        mode: EvaluationModeV1::Pure,
    })
}
