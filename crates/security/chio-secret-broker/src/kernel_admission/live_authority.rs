//! Live broker authority served over the existing authenticated authority RPC.
use super::capture::trusted_now_ms;
use super::{
    canonical, rejected, BrokerAdmissionParticipant, BrokerKernelAdmissionAuthority,
    BrokerNativeCaptureReader,
};
use crate::authority_ipc::{
    AuthorityOperation, AuthorityResult, BrokerAdmissionAuthority, BrokerAuthorityHandler,
};
use crate::budget::BrokerExecutionBudget;
use crate::revocation::{
    BrokerRevocationRequest, BrokerRevocationSnapshot, BrokerRevocations, CapabilityLiveness,
    CapabilityLivenessRequest, LiveParentCapability,
};
use crate::{validate_identifier, BrokerError, Result};
use chio_core_types::StoreMutationFence;
use chio_kernel::admission_operation::NativeSecurityAuthorityBindingV1;
use chio_kernel::{ChioKernel, RevocationStore};
use chio_store_sqlite::{SqliteAuthorityStore, SqliteRevocationStore};
use std::sync::Arc;

const MAX_REQUEST_AGE_SECONDS: u64 = 30;

/// Compose original admission custody with current kernel capability validation
/// and revocations from the same fenced SQLite authority. Install behind
/// `AuthorityRpcServer`, which authenticates the broker and signs each response.
/// Administrative issue/revoke/status operations remain denied by this port.
pub struct BrokerKernelAuthorityHandler {
    admission: BrokerKernelAdmissionAuthority,
    kernel: Arc<ChioKernel>,
    revocations: SqliteRevocationStore,
    fence: StoreMutationFence,
    audience: String,
    revocation_domain: String,
}

impl BrokerKernelAuthorityHandler {
    pub fn new(
        authority: &SqliteAuthorityStore,
        native: NativeSecurityAuthorityBindingV1,
        participant: Arc<BrokerAdmissionParticipant>,
        kernel: Arc<ChioKernel>,
    ) -> Result<Self> {
        kernel
            .validate_native_admission_configuration(
                &authority.mutation_fence(),
                &native,
                participant.binding(),
            )
            .map_err(|_| rejected())?;
        let audience = participant.audience.clone();
        let revocation_domain = participant.revocation_authority_domain().to_owned();
        let reader =
            BrokerNativeCaptureReader::new(authority, native, participant.binding().clone())?;
        Ok(Self {
            admission: BrokerKernelAdmissionAuthority::new(reader, participant)?,
            kernel,
            revocations: authority.revocation_store(),
            fence: authority.mutation_fence(),
            audience,
            revocation_domain,
        })
    }

    fn require_recent_request(request_time: u64) -> Result<()> {
        let now = trusted_now_ms()? / 1000;
        if now
            .checked_sub(request_time)
            .is_none_or(|age| age > MAX_REQUEST_AGE_SECONDS)
        {
            return Err(rejected());
        }
        Ok(())
    }

    fn revocation_cut(&self, ids: &[&str]) -> Result<(bool, u64)> {
        let mut cut = None;
        let mut revoked = false;
        for id in ids {
            validate_identifier(id, "revocation identity", 512)?;
            let observation = self
                .revocations
                .observe_revocation(id)
                .map_err(|_| unavailable())?;
            let commit = observation.commit.ok_or_else(unavailable)?;
            if commit.authority.authority_id != self.fence.store_uuid
                || commit.authority.lease_id != self.fence.lease_id
                || commit.authority.lease_epoch != self.fence.owner_epoch
                || cut.is_some_and(|index| index != commit.commit_index)
            {
                return Err(unavailable());
            }
            // Each read authenticates its authority anchor. A concurrent write
            // between reads refuses the mixed cut rather than inventing one.
            cut = Some(commit.commit_index);
            revoked |= observation.revoked;
        }
        Ok((revoked, cut.ok_or_else(unavailable)?))
    }
}

impl CapabilityLiveness for BrokerKernelAuthorityHandler {
    fn verify_live_parent(
        &self,
        request: &CapabilityLivenessRequest,
    ) -> Result<LiveParentCapability> {
        Self::require_recent_request(request.now_unix_seconds)?;
        validate_identifier(&request.parent_capability_id, "parent capability", 512)?;
        if request.expected_audience != self.audience {
            return Err(rejected());
        }
        let parent = self
            .kernel
            .verify_retained_capability_liveness(
                &request.parent_capability_id,
                &request.expected_subject,
            )
            .map_err(|_| rejected())?;
        let mut ancestors = parent
            .delegation_chain
            .iter()
            .map(|link| link.capability_id.clone())
            .collect::<Vec<_>>();
        ancestors.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        if ancestors.windows(2).any(|pair| pair[0] == pair[1])
            || ancestors.iter().any(|id| id == &parent.id)
        {
            return Err(rejected());
        }
        let mut ids = vec![parent.id.as_str()];
        ids.extend(ancestors.iter().map(String::as_str));
        let (revoked, commit_index) = self.revocation_cut(&ids)?;
        let now = trusted_now_ms()? / 1000;
        if revoked || now >= parent.expires_at {
            return Err(rejected());
        }
        let digest = chio_core_types::crypto::sha256_hex(&canonical(&serde_json::json!({
            "schema": "chio.secret-broker.native-parent-liveness.v1",
            "capability": parent,
            "audience": self.audience,
            "store_uuid": self.fence.store_uuid,
            "owner_epoch": self.fence.owner_epoch,
            "revocation_commit_index": commit_index,
            "verified_at_unix_seconds": now,
        }))?);
        Ok(LiveParentCapability {
            capability_id: parent.id,
            subject: parent.subject,
            audience: self.audience.clone(),
            delegation_ancestor_ids: ancestors,
            expires_at_unix_seconds: parent.expires_at,
            verified_at_unix_seconds: now,
            authority_snapshot_digest: digest,
        })
    }
}

impl BrokerRevocations for BrokerKernelAuthorityHandler {
    fn check_broker_revocation(
        &self,
        request: &BrokerRevocationRequest,
    ) -> Result<BrokerRevocationSnapshot> {
        Self::require_recent_request(request.now_unix_seconds)?;
        if request.broker_capability_id == request.revocation_id {
            return Err(rejected());
        }
        let (revoked, commit_index) =
            self.revocation_cut(&[&request.broker_capability_id, &request.revocation_id])?;
        Ok(BrokerRevocationSnapshot {
            revoked,
            observed_at_unix_seconds: trusted_now_ms()? / 1000,
            commit_index,
            authority_domain: self.revocation_domain.clone(),
        })
    }
}

impl BrokerAuthorityHandler for BrokerKernelAuthorityHandler {
    fn handle(&self, operation: &AuthorityOperation) -> Result<AuthorityResult> {
        match operation {
            AuthorityOperation::Capabilities => {
                Ok(AuthorityResult::Capabilities(self.admission.capabilities()))
            }
            AuthorityOperation::PrepareExecution(request) => {
                let context = self.admission.prepare_execution(request)?;
                self.verify_live_parent(&CapabilityLivenessRequest {
                    parent_capability_id: request.capability.body.parent_capability_id.clone(),
                    expected_subject: request.capability.body.subject.clone(),
                    expected_audience: self.audience.clone(),
                    now_unix_seconds: trusted_now_ms()? / 1000,
                })?;
                Ok(AuthorityResult::Prepared(context))
            }
            AuthorityOperation::VerifyLiveParent(request) => self
                .verify_live_parent(request)
                .map(AuthorityResult::LiveParent),
            AuthorityOperation::CheckBrokerRevocation(request) => self
                .check_broker_revocation(request)
                .map(AuthorityResult::Revocation),
            AuthorityOperation::QueryExecutionHold(request) => self
                .admission
                .query_execution_hold(request)
                .map(AuthorityResult::Hold),
            AuthorityOperation::AuthorizeExecutionHold(request) => self
                .admission
                .authorize_execution_hold(request)
                .map(AuthorityResult::Hold),
            AuthorityOperation::ReverseExecutionHold(request) => self
                .admission
                .reverse_execution_hold(request)
                .map(AuthorityResult::Hold),
            AuthorityOperation::CaptureExecutionHold(request) => self
                .admission
                .capture_execution_hold(request)
                .map(AuthorityResult::Hold),
            AuthorityOperation::Control(request) => self
                .admission
                .control(request.clone())
                .map(AuthorityResult::Control),
        }
    }
}

fn unavailable() -> BrokerError {
    BrokerError::AuthorityUnavailable("native broker revocation authority is unavailable".into())
}
