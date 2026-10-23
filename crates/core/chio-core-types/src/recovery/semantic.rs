//! Semantic signatures authenticate distinct roles and never replace admission.
use super::authority::{invalid, signed_authority};
use super::RecoveryDigestDomain;
use crate::{CanonicalBytes, Keypair, PublicKey, Result, Signature, SigningBackend};
use chio_security_types::{recovery::*, semantic::*};
use serde::{Deserialize, Serialize};

/// Signing-wrapper schema id of a semantic package.
pub const CHIO_RECOVERY_SEMANTIC_PACKAGE_SCHEMA: &str = "chio.recovery.signed-semantic-package.v1";
/// Signing-wrapper schema id of a semantic deployment.
pub const CHIO_RECOVERY_SEMANTIC_DEPLOYMENT_SCHEMA: &str =
    "chio.recovery.signed-semantic-deployment.v1";
/// Signing-wrapper schema id of a semantic audience observation.
pub const CHIO_RECOVERY_SEMANTIC_AUDIENCE_SCHEMA: &str =
    "chio.recovery.signed-semantic-audience.v1";
/// Signing-wrapper schema id of a scoped endorsement.
pub const CHIO_RECOVERY_SCOPED_ENDORSEMENT_SCHEMA: &str =
    "chio.recovery.signed-scoped-endorsement.v1";
/// Signing-wrapper schema id of a semantic annotation.
pub const CHIO_RECOVERY_SEMANTIC_ANNOTATION_SCHEMA: &str =
    "chio.recovery.signed-semantic-annotation.v1";
/// Signing-wrapper schema id of a semantic transformation.
pub const CHIO_RECOVERY_SEMANTIC_TRANSFORMATION_SCHEMA: &str =
    "chio.recovery.signed-semantic-transformation.v1";
/// Signing-wrapper schema id of a semantic prerequisite.
pub const CHIO_RECOVERY_SEMANTIC_PREREQUISITE_SCHEMA: &str =
    "chio.recovery.signed-semantic-prerequisite.v1";

signed_authority!(
    SignedSemanticPackageV1,
    SemanticPackageV1,
    CHIO_RECOVERY_SEMANTIC_PACKAGE_SCHEMA,
    |body: &SemanticPackageV1| body.validate().map_err(|_| invalid())
);
signed_authority!(
    SignedSemanticDeploymentV1,
    SemanticDeploymentV1,
    CHIO_RECOVERY_SEMANTIC_DEPLOYMENT_SCHEMA,
    |body: &SemanticDeploymentV1| body.validate().map_err(|_| invalid())
);
signed_authority!(
    SignedSemanticAudienceV1,
    SemanticAudienceObservationV1,
    CHIO_RECOVERY_SEMANTIC_AUDIENCE_SCHEMA,
    |body: &SemanticAudienceObservationV1| body.validate().map_err(|_| invalid())
);
signed_authority!(
    SignedScopedEndorsementV1,
    ScopedEndorsementV1,
    CHIO_RECOVERY_SCOPED_ENDORSEMENT_SCHEMA,
    |body: &ScopedEndorsementV1| body.validate().map_err(|_| invalid())
);
signed_authority!(
    SignedSemanticAnnotationV1,
    SemanticAnnotationV1,
    CHIO_RECOVERY_SEMANTIC_ANNOTATION_SCHEMA,
    |body: &SemanticAnnotationV1| body.validate().map_err(|_| invalid())
);
signed_authority!(
    SignedSemanticTransformationV1,
    SemanticTransformationV1,
    CHIO_RECOVERY_SEMANTIC_TRANSFORMATION_SCHEMA,
    |body: &SemanticTransformationV1| body.validate().map_err(|_| invalid())
);
signed_authority!(
    SignedSemanticPrerequisiteV1,
    SemanticPrerequisiteV1,
    CHIO_RECOVERY_SEMANTIC_PREREQUISITE_SCHEMA,
    |body: &SemanticPrerequisiteV1| body.validate().map_err(|_| invalid())
);

/// Proofs are outside the unsigned action preimage. This avoids a cycle between
/// an endorsement of an action and the native request containing that proof.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticInvocationV1 {
    pub schema: SemanticInvocationSchemaV1,
    pub action: SemanticActionV1,
    pub payload: SemanticPayloadV1,
    pub audience: SignedSemanticAudienceV1,
    pub endorsements: BoundedList<SignedScopedEndorsementV1, 8>,
    pub annotations: BoundedList<SignedSemanticAnnotationV1, 8>,
    #[serde(deserialize_with = "required_transformation")]
    pub transformation: Option<SignedSemanticTransformationV1>,
    pub prerequisites: BoundedList<SignedSemanticPrerequisiteV1, 8>,
}

fn digest<T: Serialize>(domain: RecoveryDigestDomain, body: &T) -> Result<[u8; 32]> {
    Ok(*domain.digest(&CanonicalBytes::new(body)?).as_bytes())
}
pub fn semantic_package_digest(body: &SemanticPackageV1) -> Result<SemanticPackageDigest> {
    digest(RecoveryDigestDomain::SemanticPackage, body).map(SemanticPackageDigest::from_bytes)
}
pub fn semantic_registry_digest(body: &SemanticDeploymentV1) -> Result<SemanticRegistryDigest> {
    digest(RecoveryDigestDomain::SemanticRegistry, body).map(SemanticRegistryDigest::from_bytes)
}
pub fn semantic_action_digest(body: &SemanticActionV1) -> Result<SemanticActionDigest> {
    body.validate().map_err(|_| invalid())?;
    digest(RecoveryDigestDomain::SemanticAction, body).map(SemanticActionDigest::from_bytes)
}
pub fn semantic_plan_digest(body: &SemanticPlanV1) -> Result<PlanDigest> {
    digest(RecoveryDigestDomain::SemanticPlan, body).map(PlanDigest::from_bytes)
}
pub fn semantic_content_digest<T: Serialize>(body: &T) -> Result<CanonicalPayloadDigest> {
    digest(RecoveryDigestDomain::SemanticContent, body).map(CanonicalPayloadDigest::from_bytes)
}
/// Role identity cannot be used as the content identity of a payload.
/// ```compile_fail
/// use chio_core_types::{Keypair, recovery::semantic_key_digest};
/// use chio_security_types::recovery::CanonicalPayloadDigest;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let key = Keypair::from_seed(&[1; 32]);
/// let _payload: CanonicalPayloadDigest = semantic_key_digest(&key.public_key())?;
/// # Ok(())
/// # }
/// ```
pub fn semantic_key_digest(key: &PublicKey) -> Result<RoleKeyDigest> {
    digest(RecoveryDigestDomain::SemanticRoleKey, key).map(RoleKeyDigest::from_bytes)
}
/// Exact bounded canonical wire input, including duplicate-key refusal.
pub fn decode_semantic_invocation(bytes: &CanonicalBytes) -> Result<SemanticInvocationV1> {
    super::decode_contract(bytes.as_bytes()).map_err(|_| invalid())
}

fn required_transformation<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> core::result::Result<Option<SignedSemanticTransformationV1>, D::Error> {
    Option::<SignedSemanticTransformationV1>::deserialize(decoder)
}
