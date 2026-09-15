//! Immutable record and independent checks of its historical participants.
use super::*;
use chio_kernel::admission_operation::{
    dpop_claim::DpopReplayClaimHistoryV1, governed_approval_claim::GovernedApprovalClaimHistoryV1,
    runtime_participant::RuntimeParticipantClaimHistoryV1, PersistedAdmissionOperationV1,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub schema: String,
    pub operation: PersistedAdmissionOperationV1,
    pub lease: super::super::history::LeaseHistory,
    pub context: chio_kernel::SecurityInvocationContext,
    pub grant_index: u32,
    pub grant_digest: AdmissionDigest,
    pub live_request_digest: AdmissionDigest,
    pub policy: serde_json::Value,
    pub join_digest: AdmissionDigest,
    pub egress_acquisition: Option<AdmissionDigest>,
    pub egress_commitment: Option<AdmissionDigest>,
    pub runtime: Option<RuntimeParticipantClaimHistoryV1>,
    pub approval: Option<GovernedApprovalClaimHistoryV1>,
    pub dpop: Option<DpopReplayClaimHistoryV1>,
    pub observed_at: u64,
    pub decision_at: u64,
}

impl Record {
    pub(super) fn bytes(&self) -> Result<Vec<u8>, AdmissionOperationStoreError> {
        let bytes = canonical_json_bytes(self).map_err(invalid)?;
        if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
            return Err(invalid("native dispatch ledger record exceeds its bound"));
        }
        Ok(bytes)
    }

    pub(super) fn digest(&self) -> Result<AdmissionDigest, AdmissionOperationStoreError> {
        AdmissionDigest::try_new("native_dispatch_ledger_digest", sha256_hex(&self.bytes()?))
            .map_err(Into::into)
    }

    pub(super) fn evidence(
        &self,
    ) -> Result<NativeSecurityDispatchLedgerRecordV1, AdmissionOperationStoreError> {
        let operation = AdmissionOperationV1::from_persisted(self.operation.clone())?;
        Ok(NativeSecurityDispatchLedgerRecordV1 {
            operation_id: operation.binding().operation_id().clone(),
            record_digest: self.digest()?,
            canonical_record: self.bytes()?,
        })
    }

    pub(super) fn validate(&self, tx: &Connection) -> Result<(), AdmissionOperationStoreError> {
        let operation = AdmissionOperationV1::from_persisted(self.operation.clone())?;
        require_operation(&operation)?;
        if self.schema != SCHEMA {
            return Err(invalid("native dispatch ledger schema differs"));
        }
        self.lease
            .validate_operation(tx, &operation, self.observed_at, self.decision_at)?;
        let original =
            super::super::super::retained_request::load_retained_request_tx(tx, &operation)?
                .ok_or_else(|| invalid("native dispatch ledger lost its original request"))?;
        let grant_index = usize::try_from(self.grant_index).map_err(invalid)?;
        let grant = original
            .retained_matching_grant(grant_index)
            .ok_or_else(|| invalid("native dispatch ledger selected an unmatched grant"))?;
        if self.grant_digest.as_str() != sha256_hex(&canonical_json_bytes(grant).map_err(invalid)?)
        {
            return Err(invalid("native dispatch ledger changed its selected grant"));
        }
        let (_, policy) = policy::decode(&canonical_json_bytes(&self.policy).map_err(invalid)?)?;
        policy.validate_binding(
            &operation,
            &original,
            &self.context,
            &self.live_request_digest,
        )?;
        policy.validate_at(self.observed_at.max(self.decision_at))?;
        policy.validate_owned_declassification(tx, &operation, &self.policy)?;
        if self.observed_at < policy.inputs.observed_at_unix_ms
            || self.observed_at.max(self.decision_at) >= policy.inputs.valid_until_unix_ms
        {
            return Err(invalid(
                "native dispatch ledger was recorded outside policy validity",
            ));
        }
        let joined =
            super::super::history::load_for_operation(tx, operation.binding().operation_id())?
                .ok_or_else(|| invalid("native dispatch ledger lost its original join"))?;
        if self.join_digest.as_str() != joined.digest()?
            || joined.authority != *policy.inputs.native_authority.security_authority_id()
            || joined.initialization
                != policy
                    .inputs
                    .native_authority
                    .initialization_digest()
                    .as_str()
        {
            return Err(invalid("native dispatch ledger differs from original join"));
        }
        let history = super::super::egress::load_history(tx, operation.binding().operation_id())?;
        match (policy.decision.effective_egress, history) {
            (false, None)
                if self.egress_acquisition.is_none() && self.egress_commitment.is_none() => {}
            (true, Some(history)) => {
                let committed = history
                    .commitment
                    .ok_or_else(|| invalid("native dispatch ledger requires committed egress"))?;
                if history.binding != policy.inputs.native_authority
                    || history.live_request_hash != self.live_request_digest
                    || Some(&history.acquisition.event_digest) != self.egress_acquisition.as_ref()
                    || Some(&committed.event_digest) != self.egress_commitment.as_ref()
                    || history.acquisition.fence.key != policy.inputs.observation.key
                    || history.acquisition.fence.context_generation
                        != policy.inputs.observation.context_generation
                    || Some(history.acquisition.fence.expires_at_unix_ms)
                        != policy.decision.egress_expires_at_unix_ms
                {
                    return Err(invalid(
                        "native dispatch ledger differs from exact egress custody",
                    ));
                }
            }
            _ => {
                return Err(invalid(
                    "native dispatch ledger has inconsistent egress custody",
                ))
            }
        }
        let current = storage::current_operation(tx, &operation)?;
        let digest = self.digest()?;
        if current
            .native_dispatch_ledger_digest()
            .is_some_and(|attached| attached != &digest)
        {
            return Err(invalid(
                "native capture changed its original preparation attachment",
            ));
        }
        runtime_participant::verify_dispatch_snapshot(tx, &current, &self.runtime)?;
        governed_approval_claim::verify_dispatch_snapshot(tx, &current, &self.approval)?;
        dpop_claim::verify_dispatch_snapshot(tx, &current, &self.dpop)?;
        Ok(())
    }
}
