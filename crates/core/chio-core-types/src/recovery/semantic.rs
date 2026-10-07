//! Semantic signatures authenticate distinct roles and never replace admission.
use super::authority::{invalid, signed_authority};
use super::RecoveryDigestDomain;
use crate::crypto::Ed25519Backend;
use crate::{
    canonical_json_bytes, CanonicalBytes, Keypair, PublicKey, Result, Signature, SigningAlgorithm,
    SigningBackend,
};
use alloc::vec::Vec;
use chio_security_types::{recovery::*, semantic::*};
use serde::{Deserialize, Serialize};

pub const SEMANTIC_PACKAGE_SIGNATURE_DOMAIN: &str = "chio:semantic-package:v1";
pub const SEMANTIC_DEPLOYMENT_SIGNATURE_DOMAIN: &str = "chio:semantic-deployment:v1";
pub const SEMANTIC_AUDIENCE_SIGNATURE_DOMAIN: &str = "chio:semantic-audience:v1";
pub const SCOPED_ENDORSEMENT_SIGNATURE_DOMAIN: &str = "chio:scoped-endorsement:v1";
pub const SEMANTIC_ANNOTATION_SIGNATURE_DOMAIN: &str = "chio:semantic-annotation:v1";
pub const SEMANTIC_TRANSFORMATION_SIGNATURE_DOMAIN: &str = "chio:semantic-transformation:v1";
pub const SEMANTIC_PREREQUISITE_SIGNATURE_DOMAIN: &str = "chio:semantic-prerequisite:v1";

signed_authority!(
    SignedSemanticPackageV1,
    SemanticPackageV1,
    SEMANTIC_PACKAGE_SIGNATURE_DOMAIN,
    |body: &SemanticPackageV1| body.validate().map_err(|_| invalid())
);
signed_authority!(
    SignedSemanticDeploymentV1,
    SemanticDeploymentV1,
    SEMANTIC_DEPLOYMENT_SIGNATURE_DOMAIN,
    |body: &SemanticDeploymentV1| body.validate().map_err(|_| invalid())
);
signed_authority!(
    SignedSemanticAudienceV1,
    SemanticAudienceObservationV1,
    SEMANTIC_AUDIENCE_SIGNATURE_DOMAIN,
    |body: &SemanticAudienceObservationV1| body.validate().map_err(|_| invalid())
);
signed_authority!(
    SignedScopedEndorsementV1,
    ScopedEndorsementV1,
    SCOPED_ENDORSEMENT_SIGNATURE_DOMAIN,
    |body: &ScopedEndorsementV1| body.validate().map_err(|_| invalid())
);
signed_authority!(
    SignedSemanticAnnotationV1,
    SemanticAnnotationV1,
    SEMANTIC_ANNOTATION_SIGNATURE_DOMAIN,
    |body: &SemanticAnnotationV1| body.validate().map_err(|_| invalid())
);
signed_authority!(
    SignedSemanticTransformationV1,
    SemanticTransformationV1,
    SEMANTIC_TRANSFORMATION_SIGNATURE_DOMAIN,
    |body: &SemanticTransformationV1| body.validate().map_err(|_| invalid())
);
signed_authority!(
    SignedSemanticPrerequisiteV1,
    SemanticPrerequisiteV1,
    SEMANTIC_PREREQUISITE_SIGNATURE_DOMAIN,
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
