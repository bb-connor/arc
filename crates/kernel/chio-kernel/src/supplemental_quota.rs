use std::cmp::Ordering;

use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::features::{CapabilityNegotiation, SUPPLEMENTAL_BROKER_EXECUTION_QUOTA};
use chio_core::crypto::{sha256_hex, PublicKey};
use serde::Serialize;

use crate::budget_store::{
    BudgetAuthorizeHoldRequest, BudgetInvocationQuota, BudgetQuotaKey, BudgetQuotaProfile,
    BudgetStoreError,
};

pub const MAX_SUPPLEMENTAL_QUOTA_ARTIFACT_BYTES: usize = 64 * 1024;
pub const MAX_REVOCATION_IDS_PER_ADMISSION: usize = 128;
const MAX_REVOCATION_ID_BYTES: usize = 512;
const REVOCATION_SET_DOMAIN: &[u8] = b"chio.revocation-set.v1\0";
const BROKER_QUOTA_KEY_DOMAIN: &[u8] = b"chio.broker-capability-execution.v1\0";

#[derive(Debug, thiserror::Error)]
pub enum SupplementalQuotaError {
    #[error("supplemental quota artifact is empty or exceeds the input limit")]
    InvalidArtifactSize,
    #[error("supplemental quota verification failed: {0}")]
    Verification(String),
    #[error("supplemental quota verifier is unavailable")]
    VerifierUnavailable,
    #[error("supplemental quota claim does not match kernel context: {0}")]
    ContextMismatch(String),
    #[error("supplemental quota claim is expired")]
    Expired,
    #[error("supplemental quota profile is unsupported")]
    UnsupportedProfile,
    #[error("supplemental broker execution quota is not negotiated")]
    FeatureNotNegotiated,
    #[error("supplemental quota canonicalization failed: {0}")]
    Canonicalization(String),
    #[error("supplemental revocation set is invalid: {0}")]
    InvalidRevocationSet(String),
    #[error(transparent)]
    Budget(#[from] BudgetStoreError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpaqueSignedSupplementalQuota {
    bytes: Vec<u8>,
}

impl OpaqueSignedSupplementalQuota {
    pub fn new(bytes: Vec<u8>) -> Result<Self, SupplementalQuotaError> {
        if bytes.is_empty() || bytes.len() > MAX_SUPPLEMENTAL_QUOTA_ARTIFACT_BYTES {
            return Err(SupplementalQuotaError::InvalidArtifactSize);
        }
        Ok(Self { bytes })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn digest(&self) -> String {
        sha256_hex(&self.bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SupplementalQuotaDestination {
    server_id: String,
    tool_name: String,
}

impl SupplementalQuotaDestination {
    pub fn new(
        server_id: impl Into<String>,
        tool_name: impl Into<String>,
    ) -> Result<Self, SupplementalQuotaError> {
        let destination = Self {
            server_id: server_id.into(),
            tool_name: tool_name.into(),
        };
        validate_identifier(&destination.server_id, "destination server id")?;
        validate_identifier(&destination.tool_name, "destination tool name")?;
        Ok(destination)
    }

    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    pub fn tool_name(&self) -> &str {
        &self.tool_name
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupplementalQuotaVerificationContext {
    pub capability_id: String,
    pub capability_digest: String,
    pub subject: PublicKey,
    pub request_id: String,
    pub destination: SupplementalQuotaDestination,
    pub arguments_digest: String,
    pub request_binding_hash: String,
    pub now: u64,
    pub negotiated_profile: BudgetQuotaProfile,
    pub negotiated_features: CapabilityNegotiation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSupplementalQuotaClaimBody {
    pub capability_id: String,
    pub capability_digest: String,
    pub subject: PublicKey,
    pub request_id: String,
    pub destination: SupplementalQuotaDestination,
    pub arguments_digest: String,
    pub request_binding_hash: String,
    pub expires_at: u64,
    pub broker_capability_id: String,
    pub issuer: PublicKey,
    pub request_constraint_digest: String,
    pub max_invocations: u32,
    pub supplemental_revocation_ids: Vec<String>,
    pub artifact_digest: String,
    pub negotiated_features_digest: String,
    pub profile: BudgetQuotaProfile,
}

pub trait SupplementalQuotaVerifier: Send + Sync {
    fn verifier_id(&self) -> &str;

    fn verify(
        &self,
        artifact: &OpaqueSignedSupplementalQuota,
        context: &SupplementalQuotaVerificationContext,
    ) -> Result<VerifiedSupplementalQuotaClaimBody, SupplementalQuotaError>;
}

/// Trusted, non-secret request material supplied to an installed supplemental
/// admission registrar before any budget authority mutation.
#[derive(Debug, Clone, Copy)]
pub struct SupplementalAdmissionPrepareRequest<'a> {
    pub request_id: &'a str,
    pub capability_id: &'a str,
    pub arguments: &'a serde_json::Value,
    pub authorization_reference: &'a str,
    pub authorization_artifact: &'a OpaqueSignedSupplementalQuota,
}

/// Deterministic broker participant identifiers derived by the installed
/// registrar from the authenticated request envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupplementalAdmissionPlan {
    attempt_id: String,
    hold_id: String,
    authorize_event_id: String,
    reverse_event_id: String,
    capture_event_id: String,
    registration_payload: Vec<u8>,
}

impl SupplementalAdmissionPlan {
    pub fn new(
        attempt_id: String,
        hold_id: String,
        authorize_event_id: String,
        reverse_event_id: String,
        capture_event_id: String,
        registration_payload: Vec<u8>,
    ) -> Result<Self, SupplementalQuotaError> {
        for (value, label) in [
            (&attempt_id, "supplemental attempt id"),
            (&hold_id, "supplemental hold id"),
            (&authorize_event_id, "supplemental authorize event id"),
            (&reverse_event_id, "supplemental reverse event id"),
            (&capture_event_id, "supplemental capture event id"),
        ] {
            validate_identifier(value, label)?;
        }
        if registration_payload.is_empty()
            || registration_payload.len() > MAX_SUPPLEMENTAL_QUOTA_ARTIFACT_BYTES
        {
            return Err(SupplementalQuotaError::Verification(
                "supplemental registration payload is empty or oversized".to_string(),
            ));
        }
        Ok(Self {
            attempt_id,
            hold_id,
            authorize_event_id,
            reverse_event_id,
            capture_event_id,
            registration_payload,
        })
    }

    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }

    pub fn hold_id(&self) -> &str {
        &self.hold_id
    }

    pub fn authorize_event_id(&self) -> &str {
        &self.authorize_event_id
    }

    pub fn reverse_event_id(&self) -> &str {
        &self.reverse_event_id
    }

    pub fn capture_event_id(&self) -> &str {
        &self.capture_event_id
    }

    pub fn registration_payload(&self) -> &[u8] {
        &self.registration_payload
    }
}

/// Read-only kernel-derived composite authorization passed to the installed
/// registrar. Its private constructor prevents callers from manufacturing the
/// verified quota authority installed in the underlying budget request.
pub struct SupplementalAdmissionAuthorization<'a> {
    admission_operation_id: &'a str,
    budget_request: &'a BudgetAuthorizeHoldRequest,
}

impl<'a> SupplementalAdmissionAuthorization<'a> {
    pub(crate) fn new(
        admission_operation_id: &'a str,
        budget_request: &'a BudgetAuthorizeHoldRequest,
    ) -> Self {
        Self {
            admission_operation_id,
            budget_request,
        }
    }

    pub fn admission_operation_id(&self) -> &str {
        self.admission_operation_id
    }

    pub fn budget_request(&self) -> &BudgetAuthorizeHoldRequest {
        self.budget_request
    }
}

/// Trusted runtime-composition port for broker attempt registration.
///
/// Registration must durably consume the proof nonce and persist the pending
/// attempt before `register_admission` returns. The kernel invokes this port
/// after `AdmissionOperation::Prepared` and before budget authorization.
pub trait SupplementalAdmissionRegistrar: Send + Sync {
    fn prepare_admission(
        &self,
        request: SupplementalAdmissionPrepareRequest<'_>,
    ) -> Result<SupplementalAdmissionPlan, SupplementalQuotaError>;

    fn register_admission(
        &self,
        plan: &SupplementalAdmissionPlan,
        authorization: SupplementalAdmissionAuthorization<'_>,
    ) -> Result<(), SupplementalQuotaError>;

    /// Materialize and retain the exact broker dispatch only after the
    /// admission operation is durably ReadyToDispatch and before capture.
    fn prepare_dispatch(&self, admission_operation_id: &str) -> Result<(), SupplementalQuotaError>;

    fn release_admission(&self, admission_operation_id: &str)
        -> Result<(), SupplementalQuotaError>;

    /// Remove the live broker registration linkage after the kernel has
    /// durably persisted completed dispatch. Outcome-unknown operations retain
    /// their linkage because they still require the original authority.
    fn finalize_admission(
        &self,
        admission_operation_id: &str,
    ) -> Result<(), SupplementalQuotaError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSupplementalQuota {
    quota: BudgetInvocationQuota,
    supplemental_revocation_ids: Vec<String>,
    artifact_digest: String,
    verifier_id: String,
    request_binding_hash: String,
    negotiated_features_digest: String,
}

impl VerifiedSupplementalQuota {
    pub fn quota(&self) -> &BudgetInvocationQuota {
        &self.quota
    }

    pub fn supplemental_revocation_ids(&self) -> &[String] {
        &self.supplemental_revocation_ids
    }

    pub fn artifact_digest(&self) -> &str {
        &self.artifact_digest
    }

    pub fn verifier_id(&self) -> &str {
        &self.verifier_id
    }

    pub fn request_binding_hash(&self) -> &str {
        &self.request_binding_hash
    }

    pub fn negotiated_features_digest(&self) -> &str {
        &self.negotiated_features_digest
    }
}

pub(crate) fn verify_supplemental_quota(
    verifier: &dyn SupplementalQuotaVerifier,
    artifact: &OpaqueSignedSupplementalQuota,
    context: &SupplementalQuotaVerificationContext,
) -> Result<VerifiedSupplementalQuota, SupplementalQuotaError> {
    validate_context(context)?;
    if !context
        .negotiated_features
        .supports(SUPPLEMENTAL_BROKER_EXECUTION_QUOTA)
    {
        return Err(SupplementalQuotaError::FeatureNotNegotiated);
    }
    let body = verifier.verify(artifact, context)?;

    if body.profile != BudgetQuotaProfile::SupplementalBrokerExecution
        || context.negotiated_profile != BudgetQuotaProfile::SupplementalBrokerExecution
    {
        return Err(SupplementalQuotaError::UnsupportedProfile);
    }
    if body.capability_id != context.capability_id {
        return Err(SupplementalQuotaError::ContextMismatch(
            "capability id".to_string(),
        ));
    }
    if body.capability_digest != context.capability_digest {
        return Err(SupplementalQuotaError::ContextMismatch(
            "capability digest".to_string(),
        ));
    }
    if body.subject != context.subject {
        return Err(SupplementalQuotaError::ContextMismatch(
            "subject".to_string(),
        ));
    }
    if body.request_id != context.request_id {
        return Err(SupplementalQuotaError::ContextMismatch(
            "request id".to_string(),
        ));
    }
    if body.destination != context.destination {
        return Err(SupplementalQuotaError::ContextMismatch(
            "destination".to_string(),
        ));
    }
    if body.arguments_digest != context.arguments_digest {
        return Err(SupplementalQuotaError::ContextMismatch(
            "arguments digest".to_string(),
        ));
    }
    if body.request_binding_hash != context.request_binding_hash {
        return Err(SupplementalQuotaError::ContextMismatch(
            "request binding hash".to_string(),
        ));
    }
    if context.now >= body.expires_at {
        return Err(SupplementalQuotaError::Expired);
    }
    if body.artifact_digest != artifact.digest() {
        return Err(SupplementalQuotaError::ContextMismatch(
            "artifact digest".to_string(),
        ));
    }
    let negotiated_features_digest = negotiation_digest(&context.negotiated_features)?;
    if body.negotiated_features_digest != negotiated_features_digest {
        return Err(SupplementalQuotaError::ContextMismatch(
            "negotiated features".to_string(),
        ));
    }
    validate_digest(&body.request_constraint_digest, "request constraint digest")?;
    validate_distinct_revocation_members(&body.supplemental_revocation_ids)?;
    validate_identifier(&body.broker_capability_id, "broker capability id")?;
    validate_identifier(verifier.verifier_id(), "verifier id")?;

    let owner_id = derive_broker_quota_owner(&body)?;
    Ok(VerifiedSupplementalQuota {
        quota: BudgetInvocationQuota::from_verified_parts(
            BudgetQuotaKey::from_verified_parts(
                BudgetQuotaProfile::SupplementalBrokerExecution,
                owner_id,
                None,
            )?,
            body.max_invocations,
        )?,
        supplemental_revocation_ids: body.supplemental_revocation_ids.clone(),
        artifact_digest: body.artifact_digest.clone(),
        verifier_id: verifier.verifier_id().to_string(),
        request_binding_hash: body.request_binding_hash.clone(),
        negotiated_features_digest,
    })
}

fn validate_context(
    context: &SupplementalQuotaVerificationContext,
) -> Result<(), SupplementalQuotaError> {
    validate_digest(&context.capability_digest, "capability digest")?;
    validate_digest(&context.arguments_digest, "arguments digest")?;
    validate_digest(&context.request_binding_hash, "request binding hash")?;
    context.negotiated_features.validate().map_err(|error| {
        SupplementalQuotaError::ContextMismatch(format!("negotiated features are invalid: {error}"))
    })?;
    validate_identifier(&context.request_id, "request id")?;
    validate_identifier(&context.capability_id, "capability id")?;
    validate_identifier(&context.destination.server_id, "destination server id")?;
    validate_identifier(&context.destination.tool_name, "destination tool name")?;
    Ok(())
}

fn negotiation_digest(
    negotiation: &CapabilityNegotiation,
) -> Result<String, SupplementalQuotaError> {
    let canonical = canonical_json_bytes(negotiation)
        .map_err(|error| SupplementalQuotaError::Canonicalization(error.to_string()))?;
    Ok(sha256_hex(&canonical))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BrokerQuotaOwnerBody<'a> {
    broker_capability_id: &'a str,
    issuer: String,
    destination: &'a SupplementalQuotaDestination,
    request_constraint_digest: &'a str,
}

fn derive_broker_quota_owner(
    body: &VerifiedSupplementalQuotaClaimBody,
) -> Result<String, SupplementalQuotaError> {
    let canonical = canonical_json_bytes(&BrokerQuotaOwnerBody {
        broker_capability_id: &body.broker_capability_id,
        issuer: body.issuer.to_hex(),
        destination: &body.destination,
        request_constraint_digest: &body.request_constraint_digest,
    })
    .map_err(|error| SupplementalQuotaError::Canonicalization(error.to_string()))?;
    let mut input = Vec::with_capacity(BROKER_QUOTA_KEY_DOMAIN.len() + canonical.len());
    input.extend_from_slice(BROKER_QUOTA_KEY_DOMAIN);
    input.extend_from_slice(&canonical);
    Ok(sha256_hex(&input))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalRevocationSet {
    ids: Vec<String>,
    digest: String,
}

impl CanonicalRevocationSet {
    /// Build the canonical revocation set for one verified admission.
    ///
    /// The leaf capability, every verified delegation ancestor, and every
    /// supplemental capability identifier must be supplied exactly once. The
    /// constructor validates identifier bounds and uniqueness, sorts by UTF-8
    /// bytes, and derives the domain-separated digest consumed by admission
    /// capture.
    pub fn new(
        leaf_capability_id: &str,
        delegation_ancestor_ids: &[String],
        supplemental_ids: &[String],
    ) -> Result<Self, SupplementalQuotaError> {
        let member_count = 1usize
            .checked_add(delegation_ancestor_ids.len())
            .and_then(|size| size.checked_add(supplemental_ids.len()))
            .ok_or_else(|| {
                SupplementalQuotaError::InvalidRevocationSet("member count overflow".to_string())
            })?;
        if member_count > MAX_REVOCATION_IDS_PER_ADMISSION {
            return Err(SupplementalQuotaError::InvalidRevocationSet(
                "member count exceeds the limit".to_string(),
            ));
        }
        let mut supplied = Vec::with_capacity(member_count);
        supplied.push(leaf_capability_id.to_string());
        supplied.extend_from_slice(delegation_ancestor_ids);
        supplied.extend_from_slice(supplemental_ids);
        validate_distinct_revocation_members(&supplied)?;
        supplied.sort_unstable_by(|left, right| compare_revocation_ids(left, right));
        let ids = supplied;
        let digest = revocation_set_digest(&ids)?;
        Ok(Self { ids, digest })
    }

    pub fn ids(&self) -> &[String] {
        &self.ids
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn validate(&self) -> Result<(), SupplementalQuotaError> {
        validate_revocation_members(&self.ids)?;
        if self
            .ids
            .windows(2)
            .any(|pair| compare_revocation_ids(&pair[0], &pair[1]) != Ordering::Less)
        {
            return Err(SupplementalQuotaError::InvalidRevocationSet(
                "members are not strictly sorted".to_string(),
            ));
        }
        let expected = revocation_set_digest(&self.ids)?;
        if expected != self.digest {
            return Err(SupplementalQuotaError::InvalidRevocationSet(
                "digest does not match members".to_string(),
            ));
        }
        Ok(())
    }

    /// Reconstruct a canonical set from durable members and their stored digest.
    ///
    /// The supplied order, uniqueness, identifier bounds, and digest are all
    /// revalidated. This set remains evidence metadata and cannot itself install
    /// verified admission authority into the kernel.
    pub fn from_persisted_parts(
        ids: Vec<String>,
        digest: String,
    ) -> Result<Self, SupplementalQuotaError> {
        let set = Self { ids, digest };
        set.validate()?;
        Ok(set)
    }
}

fn revocation_set_digest(ids: &[String]) -> Result<String, SupplementalQuotaError> {
    let canonical = canonical_json_bytes(&ids)
        .map_err(|error| SupplementalQuotaError::Canonicalization(error.to_string()))?;
    let mut input = Vec::with_capacity(REVOCATION_SET_DOMAIN.len() + canonical.len());
    input.extend_from_slice(REVOCATION_SET_DOMAIN);
    input.extend_from_slice(&canonical);
    Ok(sha256_hex(&input))
}

fn compare_revocation_ids(left: &str, right: &str) -> Ordering {
    left.as_bytes().cmp(right.as_bytes())
}

fn validate_revocation_members(ids: &[String]) -> Result<(), SupplementalQuotaError> {
    if ids.is_empty() || ids.len() > MAX_REVOCATION_IDS_PER_ADMISSION {
        return Err(SupplementalQuotaError::InvalidRevocationSet(
            "member count is empty or exceeds the limit".to_string(),
        ));
    }
    for id in ids {
        validate_identifier(id, "revocation id")?;
    }
    Ok(())
}

fn validate_distinct_revocation_members(ids: &[String]) -> Result<(), SupplementalQuotaError> {
    validate_revocation_members(ids)?;
    for (index, id) in ids.iter().enumerate() {
        if ids[index + 1..]
            .iter()
            .any(|candidate| id.as_bytes() == candidate.as_bytes())
        {
            return Err(SupplementalQuotaError::InvalidRevocationSet(
                "duplicate member".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_identifier(value: &str, label: &str) -> Result<(), SupplementalQuotaError> {
    if value.is_empty()
        || value.len() > MAX_REVOCATION_ID_BYTES
        || value.chars().next().is_some_and(is_profile_padding)
        || value.chars().next_back().is_some_and(is_profile_padding)
        || value.bytes().any(|byte| byte == 0)
    {
        return Err(SupplementalQuotaError::InvalidRevocationSet(format!(
            "{label} is empty, oversized, padded, or contains NUL"
        )));
    }
    Ok(())
}

fn is_profile_padding(value: char) -> bool {
    matches!(
        value,
        '\u{0009}'..='\u{000d}'
            | '\u{0020}'
            | '\u{0085}'
            | '\u{00a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

fn validate_digest(value: &str, label: &str) -> Result<(), SupplementalQuotaError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(SupplementalQuotaError::ContextMismatch(format!(
            "{label} must be lowercase SHA-256 hex"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::crypto::Keypair;

    #[derive(Clone)]
    struct FixedVerifier {
        claim: VerifiedSupplementalQuotaClaimBody,
    }

    impl SupplementalQuotaVerifier for FixedVerifier {
        fn verifier_id(&self) -> &str {
            "test-verifier"
        }

        fn verify(
            &self,
            _artifact: &OpaqueSignedSupplementalQuota,
            _context: &SupplementalQuotaVerificationContext,
        ) -> Result<VerifiedSupplementalQuotaClaimBody, SupplementalQuotaError> {
            Ok(self.claim.clone())
        }
    }

    fn fixture() -> (
        OpaqueSignedSupplementalQuota,
        SupplementalQuotaVerificationContext,
        VerifiedSupplementalQuotaClaimBody,
    ) {
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
        let artifact = OpaqueSignedSupplementalQuota::new(b"signed-extension".to_vec()).unwrap();
        let destination = SupplementalQuotaDestination::new("broker", "execute").unwrap();
        let mut negotiated_features = CapabilityNegotiation::t1_default();
        negotiated_features
            .features
            .insert(SUPPLEMENTAL_BROKER_EXECUTION_QUOTA.to_string(), true);
        let context = SupplementalQuotaVerificationContext {
            capability_id: "leaf-capability-1".to_string(),
            capability_digest: "11".repeat(32),
            subject: subject.public_key(),
            request_id: "request-1".to_string(),
            destination: destination.clone(),
            arguments_digest: "22".repeat(32),
            request_binding_hash: "44".repeat(32),
            now: 100,
            negotiated_profile: BudgetQuotaProfile::SupplementalBrokerExecution,
            negotiated_features: negotiated_features.clone(),
        };
        let body = VerifiedSupplementalQuotaClaimBody {
            capability_id: context.capability_id.clone(),
            capability_digest: context.capability_digest.clone(),
            subject: context.subject.clone(),
            request_id: context.request_id.clone(),
            destination,
            arguments_digest: context.arguments_digest.clone(),
            request_binding_hash: context.request_binding_hash.clone(),
            expires_at: 101,
            broker_capability_id: "broker-capability-1".to_string(),
            issuer: issuer.public_key(),
            request_constraint_digest: "33".repeat(32),
            max_invocations: 7,
            supplemental_revocation_ids: vec!["broker-capability-1".to_string()],
            artifact_digest: artifact.digest(),
            negotiated_features_digest: negotiation_digest(&negotiated_features).unwrap(),
            profile: BudgetQuotaProfile::SupplementalBrokerExecution,
        };
        (artifact, context, body)
    }

    #[test]
    fn trusted_verifier_result_derives_broker_quota_from_bound_claim() {
        let (artifact, context, body) = fixture();
        let verifier = FixedVerifier { claim: body };

        let verified = verify_supplemental_quota(&verifier, &artifact, &context).unwrap();

        assert_eq!(verified.quota.max_invocations(), 7);
        assert_eq!(
            verified.quota.key().profile(),
            BudgetQuotaProfile::SupplementalBrokerExecution
        );
        assert_eq!(verified.quota.key().owner_id().len(), 64);
        assert_eq!(
            verified.supplemental_revocation_ids,
            ["broker-capability-1"]
        );
    }

    #[test]
    fn verifier_result_mismatch_and_expiry_fail_closed() {
        let (artifact, context, mut body) = fixture();
        body.arguments_digest = "44".repeat(32);
        let verifier = FixedVerifier { claim: body };
        assert!(matches!(
            verify_supplemental_quota(&verifier, &artifact, &context),
            Err(SupplementalQuotaError::ContextMismatch(_))
        ));

        let (artifact, context, mut body) = fixture();
        body.expires_at = context.now;
        let verifier = FixedVerifier { claim: body };
        assert!(matches!(
            verify_supplemental_quota(&verifier, &artifact, &context),
            Err(SupplementalQuotaError::Expired)
        ));
    }

    #[test]
    fn supplemental_quota_requires_explicit_feature_negotiation() {
        let (artifact, mut context, body) = fixture();
        context
            .negotiated_features
            .features
            .remove(SUPPLEMENTAL_BROKER_EXECUTION_QUOTA);
        let verifier = FixedVerifier { claim: body };
        assert!(matches!(
            verify_supplemental_quota(&verifier, &artifact, &context),
            Err(SupplementalQuotaError::FeatureNotNegotiated)
        ));
    }

    #[test]
    fn canonical_revocation_set_sorts_and_rejects_duplicates() {
        let first = CanonicalRevocationSet::new(
            "leaf",
            &["root".to_string(), "parent".to_string()],
            &["supplemental".to_string()],
        )
        .unwrap();
        let second = CanonicalRevocationSet::new(
            "leaf",
            &["parent".to_string(), "root".to_string()],
            &["supplemental".to_string()],
        )
        .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.ids(), ["leaf", "parent", "root", "supplemental"]);
        first.validate().unwrap();

        assert!(CanonicalRevocationSet::new("leaf", &["leaf".to_string()], &[],).is_err());
    }

    #[test]
    fn persisted_revocation_set_revalidates_members_and_digest() {
        let original = CanonicalRevocationSet::new(
            "leaf",
            &["ancestor".to_string()],
            &["supplemental".to_string()],
        )
        .unwrap();
        let restored = CanonicalRevocationSet::from_persisted_parts(
            original.ids().to_vec(),
            original.digest().to_string(),
        )
        .unwrap();
        assert_eq!(restored, original);

        assert!(CanonicalRevocationSet::from_persisted_parts(
            original.ids().to_vec(),
            "00".repeat(32),
        )
        .is_err());
        assert!(CanonicalRevocationSet::from_persisted_parts(
            vec!["supplemental".to_string(), "leaf".to_string()],
            original.digest().to_string(),
        )
        .is_err());
    }

    #[test]
    fn canonical_revocation_set_uses_unsigned_utf8_order_and_fixed_digests() {
        let cases = [
            (
                vec!["leaf".to_string()],
                "baaba5816d4ef1572cfbb26a183f273ea200681234cdd767ab965b9efbaeb12f",
            ),
            (
                vec![
                    "broker-capability-1".to_string(),
                    "leaf".to_string(),
                    "parent".to_string(),
                    "root".to_string(),
                ],
                "70dfdbd61b71e7d6c84b73ca6fc806bab383f2a0f25fc407afc3fd437a417ad7",
            ),
            (
                vec!["\u{e000}".to_string(), "\u{10000}".to_string()],
                "bdacec9a12e86d6cb0a726409ab3c81265efe4435547b9bae2a04fee2551da6a",
            ),
            (
                vec![
                    "A".to_string(),
                    "a".to_string(),
                    "aa".to_string(),
                    "e\u{0301}".to_string(),
                    "\u{00e9}".to_string(),
                ],
                "f1f687cfbbb2e40f6fb3f099485dd0a8db9cea341780a13fff10c35c733fb114",
            ),
            (
                vec!["a\"b".to_string(), "a\\b".to_string()],
                "c708d38a618a5db666f958f7e0ef755db37d68e9dfae1cbe6199636f1024c304",
            ),
        ];

        for (ids, expected) in cases {
            assert_eq!(revocation_set_digest(&ids).unwrap(), expected);
        }

        let utf8_ordered =
            CanonicalRevocationSet::new("\u{10000}", &["\u{e000}".to_string()], &[]).unwrap();
        assert_eq!(utf8_ordered.ids(), ["\u{e000}", "\u{10000}"]);
        assert_eq!(
            utf8_ordered.digest(),
            "bdacec9a12e86d6cb0a726409ab3c81265efe4435547b9bae2a04fee2551da6a"
        );
    }

    #[test]
    fn canonical_revocation_set_rejects_fixed_profile_padding() {
        for padded in [" leaf", "leaf\u{00a0}", "\u{3000}leaf"] {
            assert!(CanonicalRevocationSet::new(padded, &[], &[]).is_err());
        }
    }
}
