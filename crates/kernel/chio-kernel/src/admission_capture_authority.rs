use crate::budget_store::{
    BudgetCaptureInvocationRequest, BudgetCommitMetadata, BudgetHoldMutationDecision,
    BudgetStoreError,
};
use crate::supplemental_quota::{
    CanonicalRevocationSet, SupplementalQuotaError, MAX_REVOCATION_IDS_PER_ADMISSION,
};
use crate::RevocationStoreError;

pub const MAX_AUTHORIZATION_ARTIFACT_DIGESTS_PER_ADMISSION: usize = 8;
const MAX_ADMISSION_IDENTIFIER_BYTES: usize = 512;

#[derive(Debug, thiserror::Error)]
pub enum AdmissionCaptureError {
    #[error("invalid admission capture request: {0}")]
    InvalidRequest(String),

    #[error("admission capture budget store failed: {0}")]
    BudgetStore(#[from] BudgetStoreError),

    #[error("admission capture revocation store failed: {0}")]
    RevocationStore(#[from] RevocationStoreError),

    #[error("admission capture authority unavailable: {0}")]
    Unavailable(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionCaptureRequest {
    operation_id: String,
    budget: BudgetCaptureInvocationRequest,
    revocation_set: CanonicalRevocationSet,
    bound_revocation_set_digest: String,
    authorization_artifact_digests: Vec<String>,
    last_observed_revocation_index: Option<u64>,
}

impl AdmissionCaptureRequest {
    pub fn new(
        operation_id: String,
        budget: BudgetCaptureInvocationRequest,
        revocation_set: CanonicalRevocationSet,
        bound_revocation_set_digest: String,
        authorization_artifact_digests: Vec<String>,
        last_observed_revocation_index: Option<u64>,
    ) -> Result<Self, AdmissionCaptureError> {
        validate_identifier(&operation_id, "operation_id")?;
        validate_identifier(&budget.capability_id, "capability_id")?;
        validate_required_identifier(budget.hold_id.as_deref(), "hold_id")?;
        validate_required_identifier(budget.event_id.as_deref(), "event_id")?;
        revocation_set.validate().map_err(invalid_revocation_set)?;
        validate_digest(&bound_revocation_set_digest, "bound revocation-set digest")?;
        if bound_revocation_set_digest != revocation_set.digest() {
            return Err(AdmissionCaptureError::InvalidRequest(
                "bound revocation-set digest does not match the canonical set".to_string(),
            ));
        }
        if !revocation_set
            .ids()
            .iter()
            .any(|id| id.as_bytes() == budget.capability_id.as_bytes())
        {
            return Err(AdmissionCaptureError::InvalidRequest(
                "canonical revocation set omits the leaf capability".to_string(),
            ));
        }
        validate_authorization_artifact_digests(&authorization_artifact_digests)?;

        Ok(Self {
            operation_id,
            budget,
            revocation_set,
            bound_revocation_set_digest,
            authorization_artifact_digests,
            last_observed_revocation_index,
        })
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub fn budget(&self) -> &BudgetCaptureInvocationRequest {
        &self.budget
    }

    pub fn revocation_set(&self) -> &CanonicalRevocationSet {
        &self.revocation_set
    }

    pub fn bound_revocation_set_digest(&self) -> &str {
        &self.bound_revocation_set_digest
    }

    pub fn authorization_artifact_digests(&self) -> &[String] {
        &self.authorization_artifact_digests
    }

    pub fn last_observed_revocation_index(&self) -> Option<u64> {
        self.last_observed_revocation_index
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionCaptureMetadata {
    operation_id: String,
    checked_revocation_set_digest: String,
    budget_commit: BudgetCommitMetadata,
    revocation_commit_index: u64,
    authority_commit_index: u64,
}

impl AdmissionCaptureMetadata {
    pub fn new(
        operation_id: String,
        checked_revocation_set_digest: String,
        budget_commit: BudgetCommitMetadata,
        revocation_commit_index: u64,
        authority_commit_index: u64,
    ) -> Result<Self, AdmissionCaptureError> {
        validate_identifier(&operation_id, "operation_id")?;
        validate_digest(
            &checked_revocation_set_digest,
            "checked revocation-set digest",
        )?;
        Ok(Self {
            operation_id,
            checked_revocation_set_digest,
            budget_commit,
            revocation_commit_index,
            authority_commit_index,
        })
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub fn checked_revocation_set_digest(&self) -> &str {
        &self.checked_revocation_set_digest
    }

    pub fn budget_commit(&self) -> &BudgetCommitMetadata {
        &self.budget_commit
    }

    pub fn revocation_commit_index(&self) -> u64 {
        self.revocation_commit_index
    }

    pub fn authority_commit_index(&self) -> u64 {
        self.authority_commit_index
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionCaptureDenialReason {
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionCaptureDenial {
    reason: AdmissionCaptureDenialReason,
    revoked_ids: Vec<String>,
    metadata: AdmissionCaptureMetadata,
}

impl AdmissionCaptureDenial {
    pub fn revoked(
        revoked_ids: Vec<String>,
        metadata: AdmissionCaptureMetadata,
    ) -> Result<Self, AdmissionCaptureError> {
        validate_revoked_ids(&revoked_ids)?;
        Ok(Self {
            reason: AdmissionCaptureDenialReason::Revoked,
            revoked_ids,
            metadata,
        })
    }

    pub fn reason(&self) -> AdmissionCaptureDenialReason {
        self.reason
    }

    pub fn revoked_ids(&self) -> &[String] {
        &self.revoked_ids
    }

    pub fn metadata(&self) -> &AdmissionCaptureMetadata {
        &self.metadata
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionCaptureDecision {
    Captured {
        budget: Box<BudgetHoldMutationDecision>,
        metadata: AdmissionCaptureMetadata,
    },
    Denied(AdmissionCaptureDenial),
}

pub trait AdmissionCaptureAuthority: Send + Sync {
    fn capture_admission(
        &self,
        request: AdmissionCaptureRequest,
    ) -> Result<AdmissionCaptureDecision, AdmissionCaptureError>;
}

fn validate_required_identifier(
    value: Option<&str>,
    label: &'static str,
) -> Result<(), AdmissionCaptureError> {
    let value = value
        .ok_or_else(|| AdmissionCaptureError::InvalidRequest(format!("{label} is required")))?;
    validate_identifier(value, label)
}

fn validate_identifier(value: &str, label: &'static str) -> Result<(), AdmissionCaptureError> {
    if value.is_empty()
        || value.len() > MAX_ADMISSION_IDENTIFIER_BYTES
        || value.bytes().any(|byte| byte == 0)
    {
        return Err(AdmissionCaptureError::InvalidRequest(format!(
            "{label} is empty, oversized, or contains NUL"
        )));
    }
    Ok(())
}

fn validate_digest(value: &str, label: &'static str) -> Result<(), AdmissionCaptureError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(AdmissionCaptureError::InvalidRequest(format!(
            "{label} must be lowercase SHA-256 hex"
        )));
    }
    Ok(())
}

fn validate_authorization_artifact_digests(
    digests: &[String],
) -> Result<(), AdmissionCaptureError> {
    if digests.is_empty() || digests.len() > MAX_AUTHORIZATION_ARTIFACT_DIGESTS_PER_ADMISSION {
        return Err(AdmissionCaptureError::InvalidRequest(format!(
            "authorization artifact digest count must be between 1 and {MAX_AUTHORIZATION_ARTIFACT_DIGESTS_PER_ADMISSION}"
        )));
    }
    for digest in digests {
        validate_digest(digest, "authorization artifact digest")?;
    }
    if digests.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(AdmissionCaptureError::InvalidRequest(
            "authorization artifact digests must be strictly sorted without duplicates".to_string(),
        ));
    }
    Ok(())
}

fn validate_revoked_ids(ids: &[String]) -> Result<(), AdmissionCaptureError> {
    if ids.is_empty() || ids.len() > MAX_REVOCATION_IDS_PER_ADMISSION {
        return Err(AdmissionCaptureError::InvalidRequest(
            "revoked ID set is empty or exceeds the admission limit".to_string(),
        ));
    }
    for id in ids {
        validate_identifier(id, "revoked capability ID")?;
    }
    if ids
        .windows(2)
        .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
    {
        return Err(AdmissionCaptureError::InvalidRequest(
            "revoked IDs must be strictly sorted without duplicates".to_string(),
        ));
    }
    Ok(())
}

fn invalid_revocation_set(error: SupplementalQuotaError) -> AdmissionCaptureError {
    AdmissionCaptureError::InvalidRequest(format!("invalid canonical revocation set: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget_store::{
        BudgetAuthorityProfile, BudgetCaptureInvocationRequest, BudgetCommitMetadata,
        BudgetEventAuthority, BudgetGuaranteeLevel, BudgetMeteringProfile,
    };
    use crate::supplemental_quota::CanonicalRevocationSet;

    fn capture_request() -> BudgetCaptureInvocationRequest {
        BudgetCaptureInvocationRequest {
            capability_id: "cap-leaf".to_string(),
            grant_index: 0,
            hold_id: Some("hold-1".to_string()),
            event_id: Some("event-capture-1".to_string()),
            authority: Some(BudgetEventAuthority {
                authority_id: "authority-1".to_string(),
                lease_id: "lease-1".to_string(),
                lease_epoch: 1,
            }),
        }
    }

    fn revocation_set() -> CanonicalRevocationSet {
        CanonicalRevocationSet::new(
            "cap-leaf",
            &["cap-ancestor".to_string()],
            &["broker-capability".to_string()],
        )
        .expect("canonical revocation set")
    }

    fn commit_metadata() -> BudgetCommitMetadata {
        BudgetCommitMetadata {
            authority: capture_request().authority,
            guarantee_level: BudgetGuaranteeLevel::SingleNodeAtomic,
            budget_profile: BudgetAuthorityProfile::AuthoritativeHoldEvent,
            metering_profile: BudgetMeteringProfile::MaxCostPreauthorizeThenReconcileActual,
            budget_commit_index: Some(7),
            event_id: Some("event-capture-1".to_string()),
        }
    }

    #[test]
    fn capture_request_validates_and_exposes_strong_bindings() {
        let revocations = revocation_set();
        let request = AdmissionCaptureRequest::new(
            "operation-1".to_string(),
            capture_request(),
            revocations.clone(),
            revocations.digest().to_string(),
            vec!["11".repeat(32), "22".repeat(32)],
            Some(5),
        )
        .expect("valid capture request");

        assert_eq!(request.operation_id(), "operation-1");
        assert_eq!(request.budget().hold_id.as_deref(), Some("hold-1"));
        assert_eq!(request.revocation_set(), &revocations);
        assert_eq!(request.bound_revocation_set_digest(), revocations.digest());
        assert_eq!(
            request.authorization_artifact_digests(),
            &["11".repeat(32), "22".repeat(32)]
        );
        assert_eq!(request.last_observed_revocation_index(), Some(5));
    }

    #[test]
    fn capture_request_rejects_mismatched_or_malformed_bindings() {
        let revocations = revocation_set();
        let mismatched = AdmissionCaptureRequest::new(
            "operation-1".to_string(),
            capture_request(),
            revocations.clone(),
            "00".repeat(32),
            vec!["11".repeat(32)],
            None,
        );
        assert!(matches!(
            mismatched,
            Err(AdmissionCaptureError::InvalidRequest(_))
        ));

        let malformed = AdmissionCaptureRequest::new(
            "operation-1".to_string(),
            capture_request(),
            revocations.clone(),
            revocations.digest().to_string(),
            vec!["not-a-digest".to_string()],
            None,
        );
        assert!(matches!(
            malformed,
            Err(AdmissionCaptureError::InvalidRequest(_))
        ));

        let duplicate = AdmissionCaptureRequest::new(
            "operation-1".to_string(),
            capture_request(),
            revocations.clone(),
            revocations.digest().to_string(),
            vec!["11".repeat(32), "11".repeat(32)],
            None,
        );
        assert!(matches!(
            duplicate,
            Err(AdmissionCaptureError::InvalidRequest(_))
        ));

        let missing_leaf = CanonicalRevocationSet::new(
            "other-leaf",
            &["cap-ancestor".to_string()],
            &["broker-capability".to_string()],
        )
        .expect("canonical set without request leaf");
        let missing_leaf = AdmissionCaptureRequest::new(
            "operation-1".to_string(),
            capture_request(),
            missing_leaf.clone(),
            missing_leaf.digest().to_string(),
            vec!["11".repeat(32)],
            None,
        );
        assert!(matches!(
            missing_leaf,
            Err(AdmissionCaptureError::InvalidRequest(_))
        ));
    }

    #[test]
    fn capture_metadata_and_denial_are_typed_and_validated() {
        let metadata = AdmissionCaptureMetadata::new(
            "operation-1".to_string(),
            "11".repeat(32),
            commit_metadata(),
            5,
            8,
        )
        .expect("capture metadata");
        let denial =
            AdmissionCaptureDenial::revoked(vec!["cap-ancestor".to_string()], metadata.clone())
                .expect("revocation denial");

        assert_eq!(denial.reason(), AdmissionCaptureDenialReason::Revoked);
        assert_eq!(denial.revoked_ids(), &["cap-ancestor".to_string()]);
        assert_eq!(denial.metadata(), &metadata);
        assert!(AdmissionCaptureDenial::revoked(Vec::new(), metadata).is_err());
    }

    #[test]
    fn admission_capture_authority_is_object_safe() {
        fn accept_object(_: &dyn AdmissionCaptureAuthority) {}

        struct FailingAuthority;

        impl AdmissionCaptureAuthority for FailingAuthority {
            fn capture_admission(
                &self,
                _request: AdmissionCaptureRequest,
            ) -> Result<AdmissionCaptureDecision, AdmissionCaptureError> {
                Err(AdmissionCaptureError::Unavailable(
                    "test authority unavailable".to_string(),
                ))
            }
        }

        accept_object(&FailingAuthority);
    }
}
