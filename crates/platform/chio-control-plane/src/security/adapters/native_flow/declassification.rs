//! The verified plan becomes consumed only after exact native commit readback.
//! No legacy use store or deserialized acknowledgement can construct this path.

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

pub(super) fn prepare_consumption(
    custody: &PreparedNativeSecurityEgress<'_>,
    flow: &chio_flow::PreparedFlowAdmission,
    policy: &NativeFlowPolicyEvidence,
    now: u64,
) -> Result<Option<DeclassificationConsumptionEvidenceCommit>, NativeFlowError> {
    let Some(verified) = flow.declassification() else {
        if custody.request().declassification_grant.is_some() {
            return Err(NativeFlowError::PolicyEvidence);
        }
        return Ok(None);
    };
    let signed = custody
        .request()
        .declassification_grant
        .as_ref()
        .ok_or(NativeFlowError::PolicyEvidence)?;
    let binding = DeclassificationTransitionBinding::Consumption {
        tenant_id: verified.tenant_id().clone(),
        grant_id: verified.grant_id().clone(),
        request_hash: verified.request_hash(),
        request_id: RequestId::new(&custody.request().request_id)
            .map_err(|_| NativeFlowError::PolicyEvidence)?,
    };
    let body = declassification_consumption_body(
        verified.tenant_id().clone(),
        ActiveDefensePolicyBinding {
            policy_version: RecordId::new("native-flow-dispatch-policy-v2")
                .map_err(|_| NativeFlowError::PolicyEvidence)?,
            policy_hash: policy.digest(),
        },
        verified.grant_id().clone(),
        declassification_grant_hash(signed)?,
        verified.request_hash(),
        now,
        &binding,
    )?;
    Ok(Some(DeclassificationConsumptionEvidenceCommit {
        consumption: DeclassificationConsumeRequest {
            tenant_id: verified.tenant_id().clone(),
            grant_id: verified.grant_id().clone(),
            request_hash: verified.request_hash(),
            consumed_at_unix_ms: now,
            grant_expires_at_unix_ms: verified
                .expires_at_unix_seconds()
                .checked_mul(1000)
                .ok_or(NativeFlowError::ClockChanged)?,
        },
        transition_binding: binding,
        receipt: active_defense_receipt_request(&body)?,
    }))
}

pub(super) fn confirm_consumption(
    flow: chio_flow::PreparedFlowAdmission,
    expected: Option<&DeclassificationConsumptionEvidenceCommit>,
    history: Option<&NativeSecurityEgressHistoryV1>,
) -> Result<FlowAdmission, NativeFlowError> {
    let actual = history
        .and_then(|history| history.commitment.as_ref())
        .and_then(|commitment| commitment.declassification.as_ref());
    if actual != expected || flow.declassification().is_some() != expected.is_some() {
        return Err(NativeFlowError::PolicyEvidence);
    }
    let Some(expected) = expected else {
        return flow.into_admission().map_err(Into::into);
    };
    // This bridge confirms the write just performed by the affine kernel
    // handle. It cannot record outcomes, select another request, or repeat use.
    struct Confirmation<'a> {
        expected: &'a DeclassificationConsumeRequest,
        used: AtomicBool,
    }
    impl DeclassificationUseStore for Confirmation<'_> {
        fn consume(
            &self,
            request: &DeclassificationConsumeRequest,
        ) -> PortResult<DeclassificationConsume> {
            if request != self.expected || self.used.swap(true, Ordering::AcqRel) {
                return Err(PortError::conflict());
            }
            Ok(DeclassificationConsume::Consumed)
        }

        fn record_outcome(&self, _: &DeclassificationOutcomeRequest) -> PortResult<()> {
            Err(PortError::invalid_data())
        }
    }
    flow.consume_declassification_at(
        &Confirmation {
            expected: &expected.consumption,
            used: AtomicBool::new(false),
        },
        expected.consumption.consumed_at_unix_ms,
    )
    .map_err(Into::into)
}
