//! Fenced recovery calls retain client causes before legacy String adapters.
use super::*;
use chio_kernel::admission_operation::{
    AdmissionOperationId, AdmissionRecoveryDeferralClear, AdmissionRecoveryDeferralWrite,
    AdmissionRecoveryPageQuery, AdmissionRecoveryPageV1, AdmissionRecoveryPortError,
    AdmissionRecoveryStatusV1, RemoteRecoveryFailureKind,
};

#[path = "recovery/transport.rs"]
mod transport;

const MAX_RECOVERY_CANDIDATES: usize = 256;
const MAX_RECOVERY_STATUS_BYTES: usize = 4096;
const MAX_I_JSON_INTEGER: u64 = (1_u64 << 53) - 1;

#[derive(Debug, thiserror::Error)]
enum RecoveryProtocolError {
    #[error("recovery authority fence does not match the client")]
    Fence,
    #[error("recovery candidate bound is invalid")]
    CandidateBound,
    #[error("recovery response schema is invalid")]
    ResponseSchema,
    #[error("recovery response must contain exactly one outcome")]
    ResponseOutcome,
    #[error("recovery response contains unrelated compaction metadata")]
    CompactionMetadata,
    #[error("recovery page count or cursor is invalid")]
    PageBounds,
    #[error("recovery status exceeds its canonical bound")]
    StatusBound,
    #[error("recovery status identity or retry schedule is invalid")]
    StatusBinding,
    #[error("recovery response changed its expected semantic identity")]
    ResponseIdentity,
    #[error("recovery authority has no usable endpoint")]
    Endpoint,
}

fn protocol_error(error: RecoveryProtocolError) -> AdmissionRecoveryPortError {
    AdmissionRecoveryPortError::remote(RemoteRecoveryFailureKind::Invariant, error)
}

fn validate_status(
    status: &AdmissionRecoveryStatusV1,
    operation_id: &AdmissionOperationId,
) -> Result<(), AdmissionRecoveryPortError> {
    let deferral = &status.deferral;
    let delay = 60_000_u64
        .saturating_mul(1_u64 << deferral.attempt_count.saturating_sub(1).min(3))
        .min(300_000);
    if &deferral.operation_id != operation_id
        || deferral.operation_version == 0
        || deferral.operation_version > MAX_I_JSON_INTEGER
        || deferral.attempt_count == 0
        || deferral.last_failure_unix_ms == 0
        || deferral.retry_not_before_unix_ms > MAX_I_JSON_INTEGER
        || deferral.last_failure_unix_ms.checked_add(delay)
            != Some(deferral.retry_not_before_unix_ms)
    {
        return Err(protocol_error(RecoveryProtocolError::StatusBinding));
    }
    let bytes = chio_core::canonical_json_bytes(status).map_err(|error| {
        AdmissionRecoveryPortError::remote(RemoteRecoveryFailureKind::Invariant, error)
    })?;
    if bytes.len() > MAX_RECOVERY_STATUS_BYTES {
        return Err(protocol_error(RecoveryProtocolError::StatusBound));
    }
    Ok(())
}

impl RemoteAdmissionAuthority {
    fn recovery_fence(&self, fence: &StoreMutationFence) -> Result<(), AdmissionRecoveryPortError> {
        if fence != &self.fence {
            return Err(AdmissionRecoveryPortError::remote(
                RemoteRecoveryFailureKind::Fenced,
                RecoveryProtocolError::Fence,
            ));
        }
        Ok(())
    }

    pub(super) fn recovery_page_rpc(
        &self,
        query: AdmissionRecoveryPageQuery<'_>,
    ) -> Result<AdmissionRecoveryPageV1, AdmissionRecoveryPortError> {
        self.recovery_fence(query.fence)?;
        if query.candidate_limit == 0 || query.candidate_limit > MAX_RECOVERY_CANDIDATES {
            return Err(protocol_error(RecoveryProtocolError::CandidateBound));
        }
        let page: RecoveryPageResponse = self.call_recovery(
            AdmissionAuthorityAction::RecoveryPage,
            &RecoveryPageRequest {
                candidate_limit: query.candidate_limit,
                after_operation_id: query.after_operation_id.cloned(),
                fence: query.fence.clone(),
            },
        )?;
        if page.scanned_candidates > query.candidate_limit
            || page.operations.len() > page.scanned_candidates
            || page.next_cursor.is_some() != (page.scanned_candidates == query.candidate_limit)
            || page.next_cursor.as_ref().is_some_and(|cursor| {
                query
                    .after_operation_id
                    .is_some_and(|after| cursor <= after)
            })
        {
            return Err(protocol_error(RecoveryProtocolError::PageBounds));
        }
        let mut previous = query.after_operation_id.cloned();
        let mut operations = Vec::with_capacity(page.operations.len());
        for persisted in page.operations {
            let operation = AdmissionOperationV1::from_persisted(persisted).map_err(|error| {
                AdmissionRecoveryPortError::remote(RemoteRecoveryFailureKind::Invariant, error)
            })?;
            let id = operation.binding().operation_id();
            if previous.as_ref().is_some_and(|previous| id <= previous)
                || page.next_cursor.as_ref().is_some_and(|cursor| id > cursor)
            {
                return Err(protocol_error(RecoveryProtocolError::PageBounds));
            }
            previous = Some(id.clone());
            operations.push(operation);
        }
        Ok(AdmissionRecoveryPageV1 {
            operations,
            scanned_candidates: page.scanned_candidates,
            next_cursor: page.next_cursor,
        })
    }

    pub(super) fn recovery_status_rpc(
        &self,
        operation_id: &AdmissionOperationId,
        fence: &StoreMutationFence,
    ) -> Result<Option<AdmissionRecoveryStatusV1>, AdmissionRecoveryPortError> {
        self.recovery_fence(fence)?;
        let status: Option<AdmissionRecoveryStatusV1> = self.call_recovery(
            AdmissionAuthorityAction::LoadRecoveryStatus,
            &RecoveryStatusRequest {
                operation_id: operation_id.clone(),
                fence: fence.clone(),
            },
        )?;
        if let Some(status) = status.as_ref() {
            validate_status(status, operation_id)?;
        }
        Ok(status)
    }

    pub(super) fn recovery_defer_rpc(
        &self,
        request: AdmissionRecoveryDeferralWrite<'_>,
    ) -> Result<AdmissionRecoveryStatusV1, AdmissionRecoveryPortError> {
        self.recovery_fence(request.fence)?;
        request.deferral.validate_for(request.operation)?;
        if let Some(expected) = request.expected {
            validate_status(expected, request.operation.binding().operation_id())?;
            expected.deferral.validate_for(request.operation)?;
        }
        let status: AdmissionRecoveryStatusV1 = self.call_recovery(
            AdmissionAuthorityAction::DeferRecovery,
            &RecoveryDeferralRequest {
                operation: request.operation.to_persisted(),
                recovery_claim: Self::recovery_claim(request.lease),
                expected: request.expected.cloned(),
                phase: request.deferral.phase,
                failure_kind: request.deferral.failure_kind,
                diagnostic_digest: request.deferral.diagnostic_digest.clone(),
                fence: request.fence.clone(),
            },
        )?;
        validate_status(&status, request.operation.binding().operation_id())?;
        status.deferral.validate_for(request.operation)?;
        let expected_attempt = request.expected.map_or(Some(1), |expected| {
            expected.deferral.attempt_count.checked_add(1)
        });
        if !status.quarantined
            || status.deferral.operation_version != request.operation.version()
            || Some(status.deferral.attempt_count) != expected_attempt
            || status.deferral.phase != request.deferral.phase
            || status.deferral.failure_kind != request.deferral.failure_kind
            || status.deferral.diagnostic_digest != request.deferral.diagnostic_digest
            || request.expected.is_some_and(|expected| {
                status.deferral.last_failure_unix_ms < expected.deferral.last_failure_unix_ms
            })
        {
            return Err(protocol_error(RecoveryProtocolError::ResponseIdentity));
        }
        Ok(status)
    }

    pub(super) fn recovery_clear_rpc(
        &self,
        request: AdmissionRecoveryDeferralClear<'_>,
    ) -> Result<(), AdmissionRecoveryPortError> {
        self.recovery_fence(request.fence)?;
        validate_status(request.expected, request.operation.binding().operation_id())?;
        request.expected.deferral.validate_for(request.operation)?;
        self.call_recovery(
            AdmissionAuthorityAction::ClearRecoveryDeferral,
            &RecoveryDeferralClearRequest {
                operation: request.operation.to_persisted(),
                recovery_claim: request.lease.map(Self::recovery_claim),
                expected: request.expected.clone(),
                fence: request.fence.clone(),
            },
        )
    }
}
