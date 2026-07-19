use crate::budget_store::{
    AuthorizedBudgetHold, BudgetCaptureInvocationRequest, BudgetCommitMetadata,
    BudgetEventAuthority, BudgetGuaranteeLevel, BudgetHoldMutationDecision,
    BudgetInvocationQuotaUsage, BudgetInvocationReservationState, BudgetQuotaProfile,
    BudgetStoreError, MAX_INVOCATION_QUOTAS_PER_ADMISSION,
};
use crate::supplemental_quota::{
    CanonicalRevocationSet, SupplementalQuotaError, MAX_REVOCATION_IDS_PER_ADMISSION,
};
use crate::RevocationStoreError;
use serde::Serialize;

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
    aggregate_root_capability_id: Option<String>,
    aggregate_root_binding_digest: Option<String>,
    last_observed_revocation_index: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionCaptureRequestInput {
    pub operation_id: String,
    pub budget: BudgetCaptureInvocationRequest,
    pub revocation_set: CanonicalRevocationSet,
    pub bound_revocation_set_digest: String,
    pub authorization_artifact_digests: Vec<String>,
    pub aggregate_root_capability_id: Option<String>,
    pub aggregate_root_binding_digest: Option<String>,
    pub last_observed_revocation_index: Option<u64>,
}

impl AdmissionCaptureRequest {
    pub fn new(input: AdmissionCaptureRequestInput) -> Result<Self, AdmissionCaptureError> {
        let AdmissionCaptureRequestInput {
            operation_id,
            budget,
            revocation_set,
            bound_revocation_set_digest,
            authorization_artifact_digests,
            aggregate_root_capability_id,
            aggregate_root_binding_digest,
            last_observed_revocation_index,
        } = input;
        validate_identifier(&operation_id, "operation_id")?;
        validate_identifier(&budget.capability_id, "capability_id")?;
        validate_required_identifier(budget.hold_id.as_deref(), "hold_id")?;
        validate_required_identifier(budget.event_id.as_deref(), "event_id")?;
        let budget_operation = budget.admission_operation.as_ref().ok_or_else(|| {
            AdmissionCaptureError::InvalidRequest(
                "budget capture is missing its admission operation binding".to_string(),
            )
        })?;
        if budget_operation.operation_id() != operation_id {
            return Err(AdmissionCaptureError::InvalidRequest(
                "budget capture operation_id does not match admission capture".to_string(),
            ));
        }
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
        validate_aggregate_root_evidence(
            aggregate_root_capability_id.as_deref(),
            aggregate_root_binding_digest.as_deref(),
        )?;
        if aggregate_root_capability_id
            .as_ref()
            .is_some_and(|root_id| {
                revocation_set
                    .ids()
                    .binary_search_by(|candidate| candidate.as_bytes().cmp(root_id.as_bytes()))
                    .is_err()
            })
        {
            return Err(AdmissionCaptureError::InvalidRequest(
                "canonical revocation set omits the aggregate root capability".to_string(),
            ));
        }

        Ok(Self {
            operation_id,
            budget,
            revocation_set,
            bound_revocation_set_digest,
            authorization_artifact_digests,
            aggregate_root_capability_id,
            aggregate_root_binding_digest,
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

    pub fn aggregate_root_capability_id(&self) -> Option<&str> {
        self.aggregate_root_capability_id.as_deref()
    }

    pub fn aggregate_root_binding_digest(&self) -> Option<&str> {
        self.aggregate_root_binding_digest.as_deref()
    }

    pub fn last_observed_revocation_index(&self) -> Option<u64> {
        self.last_observed_revocation_index
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionCaptureMetadata {
    operation_id: String,
    checked_revocation_set_digest: String,
    aggregate_root_capability_id: Option<String>,
    aggregate_root_binding_digest: Option<String>,
    budget_commit: BudgetCommitMetadata,
    revocation_commit_index: u64,
    authority_commit_index: u64,
    leader_epoch: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionCaptureMetadataInput {
    pub operation_id: String,
    pub checked_revocation_set_digest: String,
    pub aggregate_root_capability_id: Option<String>,
    pub aggregate_root_binding_digest: Option<String>,
    pub budget_commit: BudgetCommitMetadata,
    pub revocation_commit_index: u64,
    pub authority_commit_index: u64,
    pub leader_epoch: Option<u64>,
}

impl AdmissionCaptureMetadata {
    pub fn new(input: AdmissionCaptureMetadataInput) -> Result<Self, AdmissionCaptureError> {
        let AdmissionCaptureMetadataInput {
            operation_id,
            checked_revocation_set_digest,
            aggregate_root_capability_id,
            aggregate_root_binding_digest,
            budget_commit,
            revocation_commit_index,
            authority_commit_index,
            leader_epoch,
        } = input;
        validate_identifier(&operation_id, "operation_id")?;
        validate_digest(
            &checked_revocation_set_digest,
            "checked revocation-set digest",
        )?;
        validate_aggregate_root_evidence(
            aggregate_root_capability_id.as_deref(),
            aggregate_root_binding_digest.as_deref(),
        )?;
        match (budget_commit.guarantee_level, leader_epoch) {
            (crate::budget_store::BudgetGuaranteeLevel::HaLinearizable, Some(epoch))
                if epoch > 0 => {}
            (crate::budget_store::BudgetGuaranteeLevel::HaLinearizable, _) => {
                return Err(AdmissionCaptureError::InvalidRequest(
                    "HA-linearizable admission capture requires a nonzero leader epoch".to_string(),
                ));
            }
            (_, Some(_)) => {
                return Err(AdmissionCaptureError::InvalidRequest(
                    "non-HA admission capture must not claim a leader epoch".to_string(),
                ));
            }
            (_, None) => {}
        }
        Ok(Self {
            operation_id,
            checked_revocation_set_digest,
            aggregate_root_capability_id,
            aggregate_root_binding_digest,
            budget_commit,
            revocation_commit_index,
            authority_commit_index,
            leader_epoch,
        })
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub fn checked_revocation_set_digest(&self) -> &str {
        &self.checked_revocation_set_digest
    }

    pub fn aggregate_root_capability_id(&self) -> Option<&str> {
        self.aggregate_root_capability_id.as_deref()
    }

    pub fn aggregate_root_binding_digest(&self) -> Option<&str> {
        self.aggregate_root_binding_digest.as_deref()
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

    pub fn leader_epoch(&self) -> Option<u64> {
        self.leader_epoch
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdmissionCaptureQuotaKeyProjection {
    profile: String,
    owner_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    grant_index: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdmissionCaptureInvocationQuotaProjection {
    key: AdmissionCaptureQuotaKeyProjection,
    max_invocations: u32,
    reserved_invocations_before: u32,
    reserved_invocations_after: u32,
    captured_invocations_before: u32,
    captured_invocations_after: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdmissionCaptureAuthorityProjection {
    authority_id: String,
    lease_id: String,
    lease_epoch: u64,
}

impl AdmissionCaptureAuthorityProjection {
    pub(crate) fn from_budget_authority(
        authority: &BudgetEventAuthority,
    ) -> Result<Self, AdmissionCaptureError> {
        validate_identifier(&authority.authority_id, "capture authority_id")?;
        validate_identifier(&authority.lease_id, "capture lease_id")?;
        Ok(Self {
            authority_id: authority.authority_id.clone(),
            lease_id: authority.lease_id.clone(),
            lease_epoch: authority.lease_epoch,
        })
    }
}

/// Strict receipt projection of one authoritative budget and revocation capture.
///
/// The projection is constructed only from the authorization snapshot and the
/// durable capture result. Caller metadata is never accepted as input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CombinedAdmissionCaptureReceiptProjection {
    operation_id: String,
    hold_id: String,
    event_id: String,
    checked_revocation_set_digest: String,
    invocation_quotas: Vec<AdmissionCaptureInvocationQuotaProjection>,
    authorization_artifact_digests: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    aggregate_root_capability_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    aggregate_root_binding_digest: Option<String>,
    budget_commit_index: u64,
    revocation_commit_index: u64,
    authority_commit_index: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    leader_epoch: Option<u64>,
    guarantee_level: String,
    authority: AdmissionCaptureAuthorityProjection,
    invocation_state: String,
    monetary_state: String,
}

impl CombinedAdmissionCaptureReceiptProjection {
    pub fn from_capture(
        request: &AdmissionCaptureRequest,
        authorized: &AuthorizedBudgetHold,
        captured: &BudgetHoldMutationDecision,
        metadata: &AdmissionCaptureMetadata,
    ) -> Result<Self, AdmissionCaptureError> {
        let hold_id = request.budget().hold_id.as_deref().ok_or_else(|| {
            AdmissionCaptureError::InvalidRequest(
                "capture projection requires a budget hold_id".to_string(),
            )
        })?;
        let event_id = request.budget().event_id.as_deref().ok_or_else(|| {
            AdmissionCaptureError::InvalidRequest(
                "capture projection requires a budget event_id".to_string(),
            )
        })?;
        if authorized.hold_id.as_deref() != Some(hold_id)
            || captured.hold_id.as_deref() != Some(hold_id)
        {
            return Err(AdmissionCaptureError::InvalidRequest(
                "capture projection hold_id does not match the authoritative snapshots".to_string(),
            ));
        }
        if metadata.operation_id() != request.operation_id()
            || metadata.checked_revocation_set_digest() != request.bound_revocation_set_digest()
            || metadata.aggregate_root_capability_id() != request.aggregate_root_capability_id()
            || metadata.aggregate_root_binding_digest() != request.aggregate_root_binding_digest()
        {
            return Err(AdmissionCaptureError::InvalidRequest(
                "capture projection metadata does not match the admission request".to_string(),
            ));
        }
        if authorized.revocation_set.as_ref() != Some(request.revocation_set())
            || captured.revocation_set.as_ref() != Some(request.revocation_set())
        {
            return Err(AdmissionCaptureError::InvalidRequest(
                "capture projection revocation set does not match authorization".to_string(),
            ));
        }
        if captured.invocation_state != BudgetInvocationReservationState::Captured
            || authorized.invocation_state != BudgetInvocationReservationState::Authorized
            || captured.monetary_state != authorized.monetary_state
            || captured.invocation_count_after != authorized.invocation_count_after
        {
            return Err(AdmissionCaptureError::InvalidRequest(
                "capture projection reservation states do not describe an exact capture"
                    .to_string(),
            ));
        }
        validate_invocation_capture_monetary_snapshot(authorized, captured)?;
        if metadata.budget_commit() != &captured.metadata
            || captured.metadata.event_id.as_deref() != Some(event_id)
            || captured.metadata.authority != request.budget().authority
            || authorized.metadata.authority != request.budget().authority
            || captured.metadata.guarantee_level != authorized.metadata.guarantee_level
            || captured.metadata.budget_profile != authorized.metadata.budget_profile
            || captured.metadata.metering_profile != authorized.metadata.metering_profile
        {
            return Err(AdmissionCaptureError::InvalidRequest(
                "capture projection budget commit does not match the authoritative capture"
                    .to_string(),
            ));
        }
        if request
            .last_observed_revocation_index()
            .is_some_and(|observed| metadata.revocation_commit_index() < observed)
        {
            return Err(AdmissionCaptureError::InvalidRequest(
                "capture projection revocation commit predates the request fence".to_string(),
            ));
        }
        let budget_commit_index = captured.metadata.budget_commit_index.ok_or_else(|| {
            AdmissionCaptureError::InvalidRequest(
                "capture projection requires a budget commit index".to_string(),
            )
        })?;
        if budget_commit_index == 0
            || authorized
                .metadata
                .budget_commit_index
                .is_none_or(|index| index == 0 || index >= budget_commit_index)
        {
            return Err(AdmissionCaptureError::InvalidRequest(
                "capture projection budget commit index did not advance".to_string(),
            ));
        }
        if !matches!(
            captured.metadata.guarantee_level,
            BudgetGuaranteeLevel::SingleNodeAtomic | BudgetGuaranteeLevel::HaLinearizable
        ) {
            return Err(AdmissionCaptureError::InvalidRequest(
                "capture projection requires a hard budget guarantee".to_string(),
            ));
        }
        let authority = captured.metadata.authority.as_ref().ok_or_else(|| {
            AdmissionCaptureError::InvalidRequest(
                "capture projection requires fenced authority evidence".to_string(),
            )
        })?;
        let invocation_quotas = project_invocation_quota_transitions(
            &authorized.invocation_counts_after,
            &captured.invocation_counts_after,
        )?;
        let has_aggregate_family_quota = authorized.invocation_counts_after.iter().any(|usage| {
            usage.quota.key().profile() == BudgetQuotaProfile::AggregateFamilyInvocation
        });
        if has_aggregate_family_quota != request.aggregate_root_capability_id().is_some() {
            return Err(AdmissionCaptureError::InvalidRequest(
                "capture projection aggregate-family evidence does not match its quota set"
                    .to_string(),
            ));
        }

        Ok(Self {
            operation_id: request.operation_id().to_string(),
            hold_id: hold_id.to_string(),
            event_id: event_id.to_string(),
            checked_revocation_set_digest: metadata.checked_revocation_set_digest().to_string(),
            invocation_quotas,
            authorization_artifact_digests: request.authorization_artifact_digests().to_vec(),
            aggregate_root_capability_id: metadata
                .aggregate_root_capability_id()
                .map(str::to_string),
            aggregate_root_binding_digest: metadata
                .aggregate_root_binding_digest()
                .map(str::to_string),
            budget_commit_index,
            revocation_commit_index: metadata.revocation_commit_index(),
            authority_commit_index: metadata.authority_commit_index(),
            leader_epoch: metadata.leader_epoch(),
            guarantee_level: captured.metadata.guarantee_level.as_str().to_string(),
            authority: AdmissionCaptureAuthorityProjection::from_budget_authority(authority)?,
            invocation_state: captured.invocation_state.as_str().to_string(),
            monetary_state: captured.monetary_state.as_str().to_string(),
        })
    }
}

pub(crate) fn validate_invocation_capture_monetary_snapshot(
    authorized: &AuthorizedBudgetHold,
    captured: &BudgetHoldMutationDecision,
) -> Result<(), AdmissionCaptureError> {
    if captured.exposure_units != 0
        || captured.realized_spend_units != 0
        || captured.committed_cost_units_after != authorized.committed_cost_units_after
    {
        return Err(AdmissionCaptureError::InvalidRequest(
            "capture projection monetary snapshot changed during invocation capture".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn project_invocation_quota_transitions(
    authorized: &[BudgetInvocationQuotaUsage],
    captured: &[BudgetInvocationQuotaUsage],
) -> Result<Vec<AdmissionCaptureInvocationQuotaProjection>, AdmissionCaptureError> {
    if authorized.is_empty()
        || authorized.len() > MAX_INVOCATION_QUOTAS_PER_ADMISSION
        || authorized.len() != captured.len()
    {
        return Err(AdmissionCaptureError::InvalidRequest(
            "capture projection quota snapshots have an invalid cardinality".to_string(),
        ));
    }
    if authorized
        .windows(2)
        .any(|pair| pair[0].quota.key() >= pair[1].quota.key())
        || captured
            .windows(2)
            .any(|pair| pair[0].quota.key() >= pair[1].quota.key())
    {
        return Err(AdmissionCaptureError::InvalidRequest(
            "capture projection quota snapshots are not strictly sorted".to_string(),
        ));
    }

    authorized
        .iter()
        .zip(captured)
        .map(|(before, after)| {
            before.validate()?;
            after.validate()?;
            if before.quota != after.quota
                || before.reserved_invocations_after
                    != after
                        .reserved_invocations_after
                        .checked_add(1)
                        .ok_or_else(|| {
                            AdmissionCaptureError::InvalidRequest(
                                "capture projection reserved count overflowed".to_string(),
                            )
                        })?
                || after.captured_invocations_after
                    != before
                        .captured_invocations_after
                        .checked_add(1)
                        .ok_or_else(|| {
                            AdmissionCaptureError::InvalidRequest(
                                "capture projection captured count overflowed".to_string(),
                            )
                        })?
            {
                return Err(AdmissionCaptureError::InvalidRequest(
                    "capture projection quota snapshots are not an exact reservation capture"
                        .to_string(),
                ));
            }
            Ok(AdmissionCaptureInvocationQuotaProjection {
                key: AdmissionCaptureQuotaKeyProjection {
                    profile: before.quota.key().profile().as_str().to_string(),
                    owner_id: before.quota.key().owner_id().to_string(),
                    grant_index: before.quota.key().grant_index(),
                },
                max_invocations: before.quota.max_invocations(),
                reserved_invocations_before: before.reserved_invocations_after,
                reserved_invocations_after: after.reserved_invocations_after,
                captured_invocations_before: before.captured_invocations_after,
                captured_invocations_after: after.captured_invocations_after,
            })
        })
        .collect()
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
    /// Read an exact persisted capture outcome without creating one.
    ///
    /// Combined authorities used by crash-recoverable broker execution must
    /// override this method. The default is unavailable rather than a miss so
    /// callers cannot mistake a backend without point queries for an absent
    /// event.
    fn query_admission_capture(
        &self,
        _request: &AdmissionCaptureRequest,
    ) -> Result<Option<AdmissionCaptureDecision>, AdmissionCaptureError> {
        Err(AdmissionCaptureError::Unavailable(
            "admission capture point queries are unsupported".to_string(),
        ))
    }

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

fn validate_aggregate_root_evidence(
    root_capability_id: Option<&str>,
    root_binding_digest: Option<&str>,
) -> Result<(), AdmissionCaptureError> {
    match (root_capability_id, root_binding_digest) {
        (None, None) => Ok(()),
        (Some(root_capability_id), Some(root_binding_digest)) => {
            validate_identifier(root_capability_id, "aggregate root capability_id")?;
            validate_digest(root_binding_digest, "aggregate root binding digest")
        }
        _ => Err(AdmissionCaptureError::InvalidRequest(
            "aggregate root capability ID and binding digest must be present together".to_string(),
        )),
    }
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
        AuthorizedBudgetHold, BudgetAdmissionOperationBinding, BudgetAuthorityProfile,
        BudgetCaptureInvocationRequest, BudgetCommitMetadata, BudgetEventAuthority,
        BudgetGuaranteeLevel, BudgetHoldMutationDecision, BudgetInvocationQuota,
        BudgetInvocationQuotaUsage, BudgetMeteringProfile, BudgetMonetaryHoldState, BudgetQuotaKey,
        BudgetQuotaProfile,
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
            admission_operation: Some(
                BudgetAdmissionOperationBinding::new("operation-1".to_string(), "44".repeat(32))
                    .expect("admission operation binding"),
            ),
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

    fn vector_authority() -> BudgetEventAuthority {
        BudgetEventAuthority {
            authority_id: "https://leader-a.example".to_string(),
            lease_id: "https://leader-a.example#term-7".to_string(),
            lease_epoch: 7,
        }
    }

    fn vector_revocation_set() -> CanonicalRevocationSet {
        CanonicalRevocationSet::from_persisted_parts(
            vec![
                "aggregate-root-vector-1".to_string(),
                "broker-revocation-production-1".to_string(),
                "threshold-request-vector-1".to_string(),
            ],
            "19a2c540844a4a8c26fe43369f4833aafd29ec023cc9d368b113d12357ed82c2".to_string(),
        )
        .expect("canonical vector revocation set")
    }

    fn vector_quota_usages(
        reserved_invocations_after: u32,
        captured_invocations_after: u32,
    ) -> Vec<BudgetInvocationQuotaUsage> {
        [
            (
                BudgetQuotaProfile::GrantInvocation,
                "aggregate-root-vector-1".to_string(),
                Some(0),
                3,
            ),
            (
                BudgetQuotaProfile::AggregateFamilyInvocation,
                "99".repeat(32),
                None,
                7,
            ),
            (
                BudgetQuotaProfile::SupplementalBrokerExecution,
                "aa".repeat(32),
                None,
                2,
            ),
        ]
        .into_iter()
        .map(|(profile, owner_id, grant_index, max_invocations)| {
            let key = BudgetQuotaKey::from_persisted_parts(profile, owner_id, grant_index)
                .expect("vector quota key");
            BudgetInvocationQuotaUsage {
                quota: BudgetInvocationQuota::from_persisted_parts(key, max_invocations)
                    .expect("vector invocation quota"),
                reserved_invocations_after,
                captured_invocations_after,
            }
        })
        .collect()
    }

    fn vector_capture_request() -> AdmissionCaptureRequest {
        let revocation_set = vector_revocation_set();
        AdmissionCaptureRequest::new(AdmissionCaptureRequestInput {
            operation_id: "admission-operation-vector-1".to_string(),
            budget: BudgetCaptureInvocationRequest {
                capability_id: "aggregate-root-vector-1".to_string(),
                grant_index: 0,
                hold_id: Some("budget-hold-vector-1".to_string()),
                event_id: Some("budget-capture-vector-1".to_string()),
                authority: Some(vector_authority()),
                admission_operation: Some(
                    BudgetAdmissionOperationBinding::new(
                        "admission-operation-vector-1".to_string(),
                        "44".repeat(32),
                    )
                    .expect("vector admission operation binding"),
                ),
            },
            revocation_set: revocation_set.clone(),
            bound_revocation_set_digest: revocation_set.digest().to_string(),
            authorization_artifact_digests: vec![
                "7da382120539f5bfc7c0b751a74eb4851667624d1986c36b9aad1dfab191a40f".to_string(),
                "88".repeat(32),
                "8a0d072aa00cfdb7e4f9ec360505fdfc5c0c33101a60ebb6e0abc86c9a1f6f1a".to_string(),
            ],
            aggregate_root_capability_id: Some("aggregate-root-vector-1".to_string()),
            aggregate_root_binding_digest: Some(
                "85a773ba13e4d39a3a03197dcbd1d933c6b157a7fd0cae25ef9a346d07e73078".to_string(),
            ),
            last_observed_revocation_index: None,
        })
        .expect("vector capture request")
    }

    fn vector_authorized_hold() -> AuthorizedBudgetHold {
        AuthorizedBudgetHold {
            hold_id: Some("budget-hold-vector-1".to_string()),
            authorized_exposure_units: 100,
            committed_cost_units_after: 100,
            invocation_count_after: 1,
            invocation_counts_after: vector_quota_usages(1, 0),
            invocation_state: BudgetInvocationReservationState::Authorized,
            monetary_state: BudgetMonetaryHoldState::Exposed,
            revocation_set: Some(vector_revocation_set()),
            metadata: BudgetCommitMetadata {
                authority: Some(vector_authority()),
                guarantee_level: BudgetGuaranteeLevel::HaLinearizable,
                budget_profile: BudgetAuthorityProfile::AuthoritativeHoldEvent,
                metering_profile: BudgetMeteringProfile::MaxCostPreauthorizeThenReconcileActual,
                budget_commit_index: Some(41),
                event_id: Some("budget-authorize-vector-1".to_string()),
            },
        }
    }

    fn vector_captured_hold() -> BudgetHoldMutationDecision {
        BudgetHoldMutationDecision {
            hold_id: Some("budget-hold-vector-1".to_string()),
            exposure_units: 0,
            realized_spend_units: 0,
            committed_cost_units_after: 100,
            invocation_count_after: 1,
            invocation_counts_after: vector_quota_usages(0, 1),
            invocation_state: BudgetInvocationReservationState::Captured,
            monetary_state: BudgetMonetaryHoldState::Exposed,
            revocation_set: Some(vector_revocation_set()),
            metadata: BudgetCommitMetadata {
                authority: Some(vector_authority()),
                guarantee_level: BudgetGuaranteeLevel::HaLinearizable,
                budget_profile: BudgetAuthorityProfile::AuthoritativeHoldEvent,
                metering_profile: BudgetMeteringProfile::MaxCostPreauthorizeThenReconcileActual,
                budget_commit_index: Some(42),
                event_id: Some("budget-capture-vector-1".to_string()),
            },
        }
    }

    fn vector_capture_metadata(captured: &BudgetHoldMutationDecision) -> AdmissionCaptureMetadata {
        AdmissionCaptureMetadata::new(AdmissionCaptureMetadataInput {
            operation_id: "admission-operation-vector-1".to_string(),
            checked_revocation_set_digest:
                "19a2c540844a4a8c26fe43369f4833aafd29ec023cc9d368b113d12357ed82c2".to_string(),
            aggregate_root_capability_id: Some("aggregate-root-vector-1".to_string()),
            aggregate_root_binding_digest: Some(
                "85a773ba13e4d39a3a03197dcbd1d933c6b157a7fd0cae25ef9a346d07e73078".to_string(),
            ),
            budget_commit: captured.metadata.clone(),
            revocation_commit_index: 43,
            authority_commit_index: 44,
            leader_epoch: Some(7),
        })
        .expect("vector capture metadata")
    }

    #[test]
    fn capture_request_validates_and_exposes_strong_bindings() {
        let revocations = revocation_set();
        let request = AdmissionCaptureRequest::new(AdmissionCaptureRequestInput {
            operation_id: "operation-1".to_string(),
            budget: capture_request(),
            revocation_set: revocations.clone(),
            bound_revocation_set_digest: revocations.digest().to_string(),
            authorization_artifact_digests: vec!["11".repeat(32), "22".repeat(32)],
            aggregate_root_capability_id: Some("cap-ancestor".to_string()),
            aggregate_root_binding_digest: Some("33".repeat(32)),
            last_observed_revocation_index: Some(5),
        })
        .expect("valid capture request");

        assert_eq!(request.operation_id(), "operation-1");
        assert_eq!(request.budget().hold_id.as_deref(), Some("hold-1"));
        assert_eq!(request.revocation_set(), &revocations);
        assert_eq!(request.bound_revocation_set_digest(), revocations.digest());
        assert_eq!(
            request.authorization_artifact_digests(),
            &["11".repeat(32), "22".repeat(32)]
        );
        assert_eq!(request.aggregate_root_capability_id(), Some("cap-ancestor"));
        assert_eq!(
            request.aggregate_root_binding_digest(),
            Some("33".repeat(32).as_str())
        );
        assert_eq!(request.last_observed_revocation_index(), Some(5));
    }

    #[test]
    fn capture_request_rejects_mismatched_or_malformed_bindings() {
        let revocations = revocation_set();
        let mismatched = AdmissionCaptureRequest::new(AdmissionCaptureRequestInput {
            operation_id: "operation-1".to_string(),
            budget: capture_request(),
            revocation_set: revocations.clone(),
            bound_revocation_set_digest: "00".repeat(32),
            authorization_artifact_digests: vec!["11".repeat(32)],
            aggregate_root_capability_id: None,
            aggregate_root_binding_digest: None,
            last_observed_revocation_index: None,
        });
        assert!(matches!(
            mismatched,
            Err(AdmissionCaptureError::InvalidRequest(_))
        ));

        let malformed = AdmissionCaptureRequest::new(AdmissionCaptureRequestInput {
            operation_id: "operation-1".to_string(),
            budget: capture_request(),
            revocation_set: revocations.clone(),
            bound_revocation_set_digest: revocations.digest().to_string(),
            authorization_artifact_digests: vec!["not-a-digest".to_string()],
            aggregate_root_capability_id: None,
            aggregate_root_binding_digest: None,
            last_observed_revocation_index: None,
        });
        assert!(matches!(
            malformed,
            Err(AdmissionCaptureError::InvalidRequest(_))
        ));

        let duplicate = AdmissionCaptureRequest::new(AdmissionCaptureRequestInput {
            operation_id: "operation-1".to_string(),
            budget: capture_request(),
            revocation_set: revocations.clone(),
            bound_revocation_set_digest: revocations.digest().to_string(),
            authorization_artifact_digests: vec!["11".repeat(32), "11".repeat(32)],
            aggregate_root_capability_id: None,
            aggregate_root_binding_digest: None,
            last_observed_revocation_index: None,
        });
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
        let missing_leaf = AdmissionCaptureRequest::new(AdmissionCaptureRequestInput {
            operation_id: "operation-1".to_string(),
            budget: capture_request(),
            revocation_set: missing_leaf.clone(),
            bound_revocation_set_digest: missing_leaf.digest().to_string(),
            authorization_artifact_digests: vec!["11".repeat(32)],
            aggregate_root_capability_id: None,
            aggregate_root_binding_digest: None,
            last_observed_revocation_index: None,
        });
        assert!(matches!(
            missing_leaf,
            Err(AdmissionCaptureError::InvalidRequest(_))
        ));
    }

    #[test]
    fn capture_metadata_and_denial_are_typed_and_validated() {
        let metadata = AdmissionCaptureMetadata::new(AdmissionCaptureMetadataInput {
            operation_id: "operation-1".to_string(),
            checked_revocation_set_digest: "11".repeat(32),
            aggregate_root_capability_id: Some("cap-ancestor".to_string()),
            aggregate_root_binding_digest: Some("33".repeat(32)),
            budget_commit: commit_metadata(),
            revocation_commit_index: 5,
            authority_commit_index: 8,
            leader_epoch: None,
        })
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
    fn capture_metadata_requires_nonzero_ha_leader_epoch() {
        let mut commit = commit_metadata();
        commit.guarantee_level = BudgetGuaranteeLevel::HaLinearizable;
        assert!(
            AdmissionCaptureMetadata::new(AdmissionCaptureMetadataInput {
                operation_id: "operation-1".to_string(),
                checked_revocation_set_digest: "11".repeat(32),
                aggregate_root_capability_id: None,
                aggregate_root_binding_digest: None,
                budget_commit: commit.clone(),
                revocation_commit_index: 5,
                authority_commit_index: 8,
                leader_epoch: None,
            })
            .is_err()
        );
        assert!(
            AdmissionCaptureMetadata::new(AdmissionCaptureMetadataInput {
                operation_id: "operation-1".to_string(),
                checked_revocation_set_digest: "11".repeat(32),
                aggregate_root_capability_id: None,
                aggregate_root_binding_digest: None,
                budget_commit: commit.clone(),
                revocation_commit_index: 5,
                authority_commit_index: 8,
                leader_epoch: Some(0),
            })
            .is_err()
        );
        let metadata = AdmissionCaptureMetadata::new(AdmissionCaptureMetadataInput {
            operation_id: "operation-1".to_string(),
            checked_revocation_set_digest: "11".repeat(32),
            aggregate_root_capability_id: None,
            aggregate_root_binding_digest: None,
            budget_commit: commit,
            revocation_commit_index: 5,
            authority_commit_index: 8,
            leader_epoch: Some(9),
        })
        .expect("HA metadata with a nonzero leader epoch");
        assert_eq!(metadata.leader_epoch(), Some(9));
    }

    #[test]
    fn combined_capture_projection_matches_canonical_schema_fixture_bytes() {
        let request = vector_capture_request();
        let authorized = vector_authorized_hold();
        let captured = vector_captured_hold();
        let metadata = vector_capture_metadata(&captured);
        let projection = CombinedAdmissionCaptureReceiptProjection::from_capture(
            &request,
            &authorized,
            &captured,
            &metadata,
        )
        .expect("valid combined capture projection");
        let actual = chio_core::canonical::canonical_json_bytes(&projection)
            .expect("canonical projection bytes");
        let fixture = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../tests/bindings/vectors/security/protocol-primitives/positive/admission-capture-metadata-v1.json"
        ));
        let expected = fixture.strip_suffix(b"\n").unwrap_or(fixture);

        assert_eq!(actual.as_slice(), expected);
    }

    #[test]
    fn combined_capture_projection_rejects_post_capture_snapshot_substitution() {
        let request = vector_capture_request();
        let captured = vector_captured_hold();
        let metadata = vector_capture_metadata(&captured);
        let substituted = AuthorizedBudgetHold {
            hold_id: captured.hold_id.clone(),
            authorized_exposure_units: captured.exposure_units,
            committed_cost_units_after: captured.committed_cost_units_after,
            invocation_count_after: captured.invocation_count_after,
            invocation_counts_after: captured.invocation_counts_after.clone(),
            invocation_state: captured.invocation_state,
            monetary_state: captured.monetary_state,
            revocation_set: captured.revocation_set.clone(),
            metadata: captured.metadata.clone(),
        };

        let error = CombinedAdmissionCaptureReceiptProjection::from_capture(
            &request,
            &substituted,
            &captured,
            &metadata,
        )
        .expect_err("post-capture state cannot replace the authorization snapshot");

        assert!(error.to_string().contains("exact capture"), "{error}");
    }

    #[test]
    fn combined_capture_projection_rejects_monetary_snapshot_changes() {
        let request = vector_capture_request();
        let authorized = vector_authorized_hold();
        let captured = vector_captured_hold();

        for malformed in [
            BudgetHoldMutationDecision {
                exposure_units: 1,
                ..captured.clone()
            },
            BudgetHoldMutationDecision {
                realized_spend_units: 1,
                ..captured.clone()
            },
            BudgetHoldMutationDecision {
                committed_cost_units_after: authorized.committed_cost_units_after + 1,
                ..captured.clone()
            },
        ] {
            let metadata = vector_capture_metadata(&malformed);
            let error = CombinedAdmissionCaptureReceiptProjection::from_capture(
                &request,
                &authorized,
                &malformed,
                &metadata,
            )
            .expect_err("invocation capture cannot change the monetary snapshot");

            assert!(error.to_string().contains("monetary snapshot"), "{error}");
        }
    }

    #[test]
    fn combined_capture_projection_rejects_revocation_commit_before_request_fence() {
        let mut request = vector_capture_request();
        request.last_observed_revocation_index = Some(44);
        let authorized = vector_authorized_hold();
        let captured = vector_captured_hold();
        let metadata = vector_capture_metadata(&captured);

        let error = CombinedAdmissionCaptureReceiptProjection::from_capture(
            &request,
            &authorized,
            &captured,
            &metadata,
        )
        .expect_err("capture revocation commit cannot regress behind the request fence");

        assert!(error.to_string().contains("request fence"), "{error}");
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
