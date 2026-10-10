//! Recovery mutations use the serving backend clock and exact original claims.
use super::*;
use chio_kernel::admission_operation::{
    qualified_lease, AdmissionRecoveryDeferralClear, AdmissionRecoveryDeferralV1,
    AdmissionRecoveryDeferralWrite, AdmissionRecoveryLease, AdmissionRecoveryPageQuery,
    AdmissionRecoveryPortError, AdmissionRecoveryStatusV1, RecoveryClaimRequest,
    RemoteRecoveryFailureKind,
};
use std::error::Error;

pub(super) struct RecoveryAuthorityError {
    kind: RemoteRecoveryFailureKind,
    source: Box<dyn Error + Send + Sync>,
}

impl RecoveryAuthorityError {
    fn native(kind: RemoteRecoveryFailureKind, source: impl Error + Send + Sync + 'static) -> Self {
        Self {
            kind,
            source: Box::new(source),
        }
    }
    fn store(error: AdmissionOperationStoreError) -> Self {
        Self::from(AdmissionRecoveryPortError::from(error))
    }
}

impl From<AdmissionRecoveryPortError> for RecoveryAuthorityError {
    fn from(error: AdmissionRecoveryPortError) -> Self {
        Self::native(error.kind(), error)
    }
}

impl std::fmt::Debug for RecoveryAuthorityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecoveryAuthorityError")
            .field("kind", &self.kind)
            .finish()
    }
}
impl std::fmt::Display for RecoveryAuthorityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "recovery authority refused request ({:?})",
            self.kind
        )
    }
}
impl Error for RecoveryAuthorityError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

fn invalid_source(source: impl Error + Send + Sync + 'static) -> RecoveryAuthorityError {
    RecoveryAuthorityError::native(RemoteRecoveryFailureKind::Invariant, source)
}

fn decode_payload<T: DeserializeOwned>(
    value: serde_json::Value,
) -> Result<T, RecoveryAuthorityError> {
    serde_json::from_value(value).map_err(invalid_source)
}

fn encode_value<T: Serialize>(value: &T) -> Result<serde_json::Value, RecoveryAuthorityError> {
    serde_json::to_value(value).map_err(invalid_source)
}

fn check_fence(
    actual: &StoreMutationFence,
    expected: &StoreMutationFence,
) -> Result<(), RecoveryAuthorityError> {
    if actual != expected {
        return Err(RecoveryAuthorityError::store(
            AdmissionOperationStoreError::Fenced,
        ));
    }
    Ok(())
}

fn validate_status(
    status: &AdmissionRecoveryStatusV1,
    operation: &AdmissionOperationV1,
) -> Result<(), RecoveryAuthorityError> {
    status
        .deferral
        .validate_for(operation)
        .map_err(RecoveryAuthorityError::store)?;
    let canonical = chio_core::canonical_json_bytes(status).map_err(invalid_source)?;
    if canonical.len() > 4096 {
        return Err(RecoveryAuthorityError::store(
            AdmissionOperationStoreError::Invariant(
                "recovery status exceeds its canonical bound".into(),
            ),
        ));
    }
    Ok(())
}

pub(super) fn handle(
    action: AdmissionAuthorityAction,
    payload: serde_json::Value,
    fence: &StoreMutationFence,
    operations: &SqliteAdmissionOperationStore,
) -> Result<serde_json::Value, RecoveryAuthorityError> {
    match action {
        AdmissionAuthorityAction::RecoveryPage => {
            let request: RecoveryPageRequest = decode_payload(payload)?;
            check_fence(&request.fence, fence)?;
            if request.candidate_limit == 0 || request.candidate_limit > 256 {
                return Err(RecoveryAuthorityError::store(
                    AdmissionOperationStoreError::Invariant(
                        "recovery candidate limit must be between 1 and 256".into(),
                    ),
                ));
            }
            let now = operations
                .observed_authority_time()
                .map_err(RecoveryAuthorityError::store)?
                .get();
            let page = operations.recovery_page(AdmissionRecoveryPageQuery {
                not_after_unix_ms: now,
                candidate_limit: request.candidate_limit,
                after_operation_id: request.after_operation_id.as_ref(),
                fence,
            })?;
            encode_value(&RecoveryPageResponse {
                operations: page
                    .operations
                    .into_iter()
                    .map(|operation| operation.to_persisted())
                    .collect(),
                scanned_candidates: page.scanned_candidates,
                next_cursor: page.next_cursor,
            })
        }
        AdmissionAuthorityAction::LoadRecoveryStatus => {
            let request: RecoveryStatusRequest = decode_payload(payload)?;
            check_fence(&request.fence, fence)?;
            let now = operations
                .observed_authority_time()
                .map_err(RecoveryAuthorityError::store)?
                .get();
            encode_value(&operations.load_recovery_status(&request.operation_id, fence, now)?)
        }
        AdmissionAuthorityAction::DeferRecovery => {
            let request: RecoveryDeferralRequest = decode_payload(payload)?;
            check_fence(&request.fence, fence)?;
            let operation =
                AdmissionOperationV1::from_persisted(request.operation).map_err(invalid_source)?;
            if let Some(expected) = request.expected.as_ref() {
                validate_status(expected, &operation)?;
            }
            let now = operations
                .observed_authority_time()
                .map_err(RecoveryAuthorityError::store)?
                .get();
            let lease = original_lease(operations, &operation, request.recovery_claim, fence, now)?;
            let deferral = AdmissionRecoveryDeferralV1::after_failure(
                &operation,
                request.expected.as_ref().map(|status| &status.deferral),
                request.phase,
                request.failure_kind,
                request.diagnostic_digest,
                now,
            )
            .map_err(RecoveryAuthorityError::store)?;
            let status = operations.defer_recovery(AdmissionRecoveryDeferralWrite {
                operation: &operation,
                lease: &lease,
                expected: request.expected.as_ref(),
                deferral: &deferral,
                fence,
                trusted_now_unix_ms: now,
            })?;
            encode_value(&status)
        }
        AdmissionAuthorityAction::ClearRecoveryDeferral => {
            let request: RecoveryDeferralClearRequest = decode_payload(payload)?;
            check_fence(&request.fence, fence)?;
            let operation =
                AdmissionOperationV1::from_persisted(request.operation).map_err(invalid_source)?;
            validate_status(&request.expected, &operation)?;
            let now = operations
                .observed_authority_time()
                .map_err(RecoveryAuthorityError::store)?
                .get();
            let lease = request
                .recovery_claim
                .map(|claim| original_lease(operations, &operation, claim, fence, now))
                .transpose()?;
            operations.clear_recovery_deferral(AdmissionRecoveryDeferralClear {
                operation: &operation,
                lease: lease.as_ref(),
                expected: &request.expected,
                fence,
                trusted_now_unix_ms: now,
            })?;
            encode_value(&())
        }
        _ => Err(RecoveryAuthorityError::store(
            AdmissionOperationStoreError::Invariant(
                "unrelated operation reached the recovery adapter".into(),
            ),
        )),
    }
}

fn original_lease(
    operations: &SqliteAdmissionOperationStore,
    operation: &AdmissionOperationV1,
    wire: RecoveryClaimWire,
    fence: &StoreMutationFence,
    now: u64,
) -> Result<AdmissionRecoveryLease, RecoveryAuthorityError> {
    let claim = wire.into_claim().map_err(invalid_source)?;
    let stored = operations
        .load_by_operation_id(operation.binding().operation_id())
        .map_err(RecoveryAuthorityError::store)?
        .ok_or_else(|| RecoveryAuthorityError::store(AdmissionOperationStoreError::NotFound))?;
    if &stored != operation {
        return Err(RecoveryAuthorityError::store(
            AdmissionOperationStoreError::Fenced,
        ));
    }
    operations
        .revalidate_recovery_claim(&stored, &claim, now, fence)
        .map_err(RecoveryAuthorityError::store)?;
    let mut qualify = qualified_lease(
        RecoveryClaimRequest {
            operation_id: claim.operation_id(),
            expected_version: claim.claimed_version(),
            claimant_id: claim.claimant_id(),
            expires_at_unix_ms: claim.expires_at_unix_ms(),
            fence,
        },
        now,
    );
    qualify(&stored, claim.clone()).map_err(RecoveryAuthorityError::store)
}

pub(super) fn wire_projection(error: RecoveryAuthorityError) -> AdmissionAuthorityWireError {
    let code = match error.kind {
        RemoteRecoveryFailureKind::Unavailable => AdmissionAuthorityErrorCode::Unavailable,
        RemoteRecoveryFailureKind::Fenced => AdmissionAuthorityErrorCode::Fenced,
        RemoteRecoveryFailureKind::NotFound => AdmissionAuthorityErrorCode::NotFound,
        RemoteRecoveryFailureKind::Conflict => AdmissionAuthorityErrorCode::Conflict,
        RemoteRecoveryFailureKind::Invariant => AdmissionAuthorityErrorCode::Invariant,
        RemoteRecoveryFailureKind::OutcomeUnknown => AdmissionAuthorityErrorCode::OutcomeUnknown,
    };
    let cause_class = if error.source.is::<AdmissionRecoveryPortError>() {
        "recovery_store"
    } else if error.source.is::<serde_json::Error>() {
        "wire_json"
    } else if error
        .source
        .is::<chio_kernel::admission_operation::AdmissionOperationError>()
    {
        "operation_validation"
    } else {
        "canonical_validation"
    };
    // The original source remains local. Only closed categories cross HTTP or
    // enter this bounded operator event; diagnostic prose grants no authority.
    tracing::error!(
        ?code,
        cause_class,
        "admission recovery authority refused request"
    );
    wire_error(code, "admission recovery authority refused request")
}
