use base64::{engine::general_purpose::STANDARD, Engine as _};
use chio_kernel::admission_operation::{
    AdmissionBeginResult, AdmissionCommandResult, AdmissionOperationCommand,
    AdmissionOperationStore, AdmissionOperationStoreError, AdmissionOperationV1,
    QualifiedAdmissionOperationStoreExt, StoreMutationFence,
};
use chio_kernel::budget_store::{BudgetCaptureInvocationRequest, BudgetEventAuthority};
use chio_kernel::receipt_store::{
    QualifiedAdmissionProjectionStore, ReceiptStore, ReceiptStoreError,
};
use chio_kernel::tool_outcome::{
    CanonicalResolvedOutputBlobV1, PostReturnEvaluationRecordV1, RawInvocationOutcomeV1,
    ToolOutcomeInsertResultV1, ToolOutcomeRecordV1, ToolOutcomeStore, ToolOutcomeStoreError,
};
use chio_store_sqlite::{SqliteAdmissionOperationStore, SqliteToolOutcomeStore};
use serde::de::DeserializeOwned;
use serde::Serialize;

use super::super::report_validation::validate_service_auth;
use super::super::*;

pub(crate) async fn handle_admission_authority(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<AdmissionAuthorityRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let response = handle_request(&state, request);
    Json(response).into_response()
}

fn handle_request(
    state: &TrustServiceState,
    request: AdmissionAuthorityRequest,
) -> AdmissionAuthorityResponse {
    if !request.schema_is_valid() {
        return AdmissionAuthorityResponse::failure(
            AdmissionAuthorityErrorCode::InvalidRequest,
            "admission authority request schema is invalid",
        );
    }
    let Some(authority) = state.joint_authority_store.as_ref() else {
        return AdmissionAuthorityResponse::failure(
            AdmissionAuthorityErrorCode::Unavailable,
            "joint admission authority is not configured",
        );
    };
    if state.cluster.is_some() {
        return AdmissionAuthorityResponse::failure(
            AdmissionAuthorityErrorCode::Unavailable,
            "joint admission authority cannot run with the legacy cluster coordinator",
        );
    }
    let fence = authority.mutation_fence();
    if request.action != AdmissionAuthorityAction::Status
        && request.expected_fence.as_ref() != Some(&fence)
    {
        return AdmissionAuthorityResponse::failure(
            AdmissionAuthorityErrorCode::Fenced,
            "admission authority serving owner changed",
        );
    }
    let operations = authority.admission_operation_store();
    let outcomes = authority.tool_outcome_store();
    match handle_action(
        request.action,
        request.payload,
        &fence,
        &operations,
        &outcomes,
    ) {
        Ok(value) => AdmissionAuthorityResponse::success(&value).unwrap_or_else(|error| {
            AdmissionAuthorityResponse::failure(
                AdmissionAuthorityErrorCode::Invariant,
                format!("failed to encode admission authority response: {error}"),
            )
        }),
        Err(error) => AdmissionAuthorityResponse {
            schema: "chio.admission-authority-response.v1".to_owned(),
            result: None,
            error: Some(error),
        },
    }
}

fn handle_action(
    action: AdmissionAuthorityAction,
    payload: serde_json::Value,
    fence: &StoreMutationFence,
    operations: &SqliteAdmissionOperationStore,
    outcomes: &SqliteToolOutcomeStore,
) -> Result<serde_json::Value, AdmissionAuthorityWireError> {
    match action {
        AdmissionAuthorityAction::Status => encode(&AdmissionAuthorityStatusWire {
            fence: fence.clone(),
        }),
        AdmissionAuthorityAction::Begin => {
            let request: AdmissionBeginWire = decode(payload)?;
            let operation = AdmissionOperationV1::from_persisted(request.operation)
                .map_err(invalid_operation)?;
            let result = operations
                .begin(&operation, &request.fence, request.trusted_now_unix_ms)
                .map_err(operation_store_error)?;
            let result = match result {
                AdmissionBeginResult::Created(operation) => AdmissionBeginResultWire::Created {
                    operation: operation.to_persisted(),
                },
                AdmissionBeginResult::ExactReplay {
                    operation,
                    terminal_replay,
                } => AdmissionBeginResultWire::ExactReplay {
                    operation: operation.to_persisted(),
                    terminal_replay,
                },
                AdmissionBeginResult::Conflict {
                    existing_operation_id,
                } => AdmissionBeginResultWire::Conflict {
                    existing_operation_id,
                },
            };
            encode(&result)
        }
        AdmissionAuthorityAction::LoadByOperationId => {
            let request: OperationIdWire = decode(payload)?;
            let value = operations
                .load_by_operation_id(&request.operation_id)
                .map_err(operation_store_error)?
                .map(|operation| operation.to_persisted());
            encode(&value)
        }
        AdmissionAuthorityAction::LoadByReplayKey => {
            let request: ReplayKeyWire = decode(payload)?;
            let value = operations
                .load_by_replay_key(&request.replay_key)
                .map_err(operation_store_error)?
                .map(|operation| operation.to_persisted());
            encode(&value)
        }
        AdmissionAuthorityAction::CompareAndSwap => {
            let request: AdmissionCommandWire = decode(payload)?;
            let lease = qualify_lease(
                operations,
                request.recovery_claim,
                request.trusted_now_unix_ms,
                fence,
            )?;
            let command = AdmissionOperationCommand::new(
                request.operation_id,
                request.expected_version,
                lease,
                request.attachments,
                request.next_state,
                request.terminal_replay,
                request.last_error,
            )
            .map_err(invalid_operation)?;
            let result = operations
                .compare_and_swap(&command, request.trusted_now_unix_ms)
                .map_err(operation_store_error)?;
            let (applied, operation) = match result {
                AdmissionCommandResult::Applied(operation) => (true, operation),
                AdmissionCommandResult::Idempotent(operation) => (false, operation),
            };
            encode(&AdmissionCommandResultWire {
                applied,
                operation: operation.to_persisted(),
            })
        }
        AdmissionAuthorityAction::ClaimRecovery => {
            let request: ClaimRecoveryWire = decode(payload)?;
            let claim = operations
                .claim_recovery_untrusted(
                    &request.operation_id,
                    request.expected_version,
                    &request.claimant_id,
                    request.trusted_now_unix_ms,
                    request.expires_at_unix_ms,
                    &request.fence,
                )
                .map_err(operation_store_error)?;
            encode(&RecoveryClaimWire::from_claim(&claim))
        }
        AdmissionAuthorityAction::RevalidateRecoveryClaim => {
            let request: RevalidateRecoveryClaimWire = decode(payload)?;
            let operation = AdmissionOperationV1::from_persisted(request.operation)
                .map_err(invalid_operation)?;
            let claim = request.claim.into_claim().map_err(invalid_operation)?;
            operations
                .revalidate_recovery_claim(
                    &operation,
                    &claim,
                    request.trusted_now_unix_ms,
                    &request.current_fence,
                )
                .map_err(operation_store_error)?;
            encode(&())
        }
        AdmissionAuthorityAction::ListRecoverable => {
            let request: ListRecoverableWire = decode(payload)?;
            let operations = operations
                .list_recoverable(request.not_after_unix_ms, request.limit)
                .map_err(operation_store_error)?
                .into_iter()
                .map(|operation| operation.to_persisted())
                .collect::<Vec<_>>();
            encode(&operations)
        }
        AdmissionAuthorityAction::LoadTerminalReplay => {
            let request: ReplayKeyWire = decode(payload)?;
            let replay = operations
                .load_terminal_replay(&request.replay_key)
                .map_err(operation_store_error)?;
            encode(&replay)
        }
        AdmissionAuthorityAction::RecordToolReturned => {
            let request: RecordToolReturnedWire = decode(payload)?;
            let operation = AdmissionOperationV1::from_persisted(request.operation)
                .map_err(invalid_operation)?;
            let lease = qualify_lease(
                operations,
                request.recovery_claim,
                request.trusted_now_unix_ms,
                fence,
            )?;
            let raw =
                RawInvocationOutcomeV1::from_persisted(request.raw).map_err(invalid_outcome)?;
            let blob = raw.canonical_blob().map_err(invalid_outcome)?;
            let record =
                ToolOutcomeRecordV1::from_persisted(request.record).map_err(invalid_outcome)?;
            let result = outcomes
                .record_tool_returned(
                    &operation,
                    &lease,
                    &blob,
                    &record,
                    &request.active_fence,
                    request.trusted_now_unix_ms,
                )
                .map_err(outcome_store_error)?;
            let (inserted, outcome, operation) = match result {
                ToolOutcomeInsertResultV1::Inserted { outcome, operation } => {
                    (true, outcome, operation)
                }
                ToolOutcomeInsertResultV1::ExactReplay { outcome, operation } => {
                    (false, outcome, operation)
                }
            };
            encode(&ToolOutcomeInsertResultWire {
                inserted,
                outcome: outcome.to_persisted(),
                operation: operation.to_persisted(),
            })
        }
        AdmissionAuthorityAction::LookupToolOutcome => {
            let request: OperationIdWire = decode(payload)?;
            let value = outcomes
                .lookup_by_operation(&request.operation_id)
                .map_err(outcome_store_error)?
                .map(|outcome| outcome.to_persisted());
            encode(&value)
        }
        AdmissionAuthorityAction::LoadRawInvocation => {
            let request: OperationIdWire = decode(payload)?;
            let value = outcomes
                .load_raw_invocation_by_operation(&request.operation_id)
                .map_err(outcome_store_error)?
                .map(|raw| raw.to_persisted());
            encode(&value)
        }
        AdmissionAuthorityAction::LookupPostReturnEvaluation => {
            let request: OperationIdWire = decode(payload)?;
            let value = outcomes
                .lookup_post_return_evaluation(&request.operation_id)
                .map_err(outcome_store_error)?
                .map(|evaluation| evaluation.to_persisted());
            encode(&value)
        }
        AdmissionAuthorityAction::BeginPostReturnEvaluation => {
            let request: BeginPostReturnEvaluationWire = decode(payload)?;
            let lease = qualify_lease(
                operations,
                request.recovery_claim,
                request.trusted_now_unix_ms,
                fence,
            )?;
            let record = PostReturnEvaluationRecordV1::from_persisted(request.record)
                .map_err(invalid_outcome)?;
            let value = outcomes
                .begin_post_return_evaluation(
                    &lease,
                    &record,
                    &request.active_fence,
                    request.trusted_now_unix_ms,
                )
                .map_err(outcome_store_error)?;
            encode(&value.to_persisted())
        }
        AdmissionAuthorityAction::StagePostReturnEvaluation => {
            let request: StagePostReturnEvaluationWire = decode(payload)?;
            let lease = qualify_lease(
                operations,
                request.recovery_claim,
                request.trusted_now_unix_ms,
                fence,
            )?;
            let next = PostReturnEvaluationRecordV1::from_persisted(request.next)
                .map_err(invalid_outcome)?;
            let value = outcomes
                .stage_post_return_evaluation(
                    &request.operation_id,
                    request.expected_version,
                    &lease,
                    &next,
                    &request.active_fence,
                    request.trusted_now_unix_ms,
                )
                .map_err(outcome_store_error)?;
            encode(&value.to_persisted())
        }
        AdmissionAuthorityAction::FinalizePostReturn => {
            let request: FinalizePostReturnWire = decode(payload)?;
            let lease = qualify_lease(
                operations,
                request.recovery_claim,
                request.trusted_now_unix_ms,
                fence,
            )?;
            let terminal_evaluation =
                PostReturnEvaluationRecordV1::from_persisted(request.terminal_evaluation)
                    .map_err(invalid_outcome)?;
            let terminal_outcome = ToolOutcomeRecordV1::from_persisted(request.terminal_outcome)
                .map_err(invalid_outcome)?;
            let resolved_output = request
                .resolved_output
                .map(|value| {
                    STANDARD
                        .decode(value)
                        .map_err(|error| invalid_request(error.to_string()))
                        .and_then(|bytes| {
                            CanonicalResolvedOutputBlobV1::from_signing_preimage(bytes)
                                .map_err(invalid_outcome)
                        })
                })
                .transpose()?;
            let (evaluation, outcome) = outcomes
                .finalize_post_return(
                    &request.operation_id,
                    request.expected_evaluation_version,
                    &lease,
                    &terminal_evaluation,
                    request.expected_outcome_version,
                    &terminal_outcome,
                    resolved_output.as_ref(),
                    &request.active_fence,
                    request.trusted_now_unix_ms,
                )
                .map_err(outcome_store_error)?;
            encode(&FinalizePostReturnResultWire {
                evaluation: evaluation.to_persisted(),
                outcome: outcome.to_persisted(),
            })
        }
        AdmissionAuthorityAction::LoadResolvedOutput => {
            let request: OperationIdWire = decode(payload)?;
            let value = outcomes
                .load_resolved_output_by_operation(&request.operation_id)
                .map_err(outcome_store_error)?
                .map(|blob| STANDARD.encode(blob.bytes()));
            encode(&value)
        }
        AdmissionAuthorityAction::CaptureInvocationAndCommitDispatch => {
            let request: AdmissionDispatchCaptureWire = decode(payload)?;
            if request.active_fence != *fence {
                return Err(AdmissionAuthorityWireError {
                    code: AdmissionAuthorityErrorCode::Fenced,
                    message: "combined admission capture serving owner changed".to_owned(),
                });
            }
            let operation = AdmissionOperationV1::from_persisted(request.operation)
                .map_err(invalid_operation)?;
            let lease = qualify_lease(
                operations,
                request.recovery_claim,
                request.trusted_now_unix_ms,
                fence,
            )?;
            let updated = operations
                .capture_invocation_and_commit_dispatch(
                    &operation,
                    &lease,
                    BudgetCaptureInvocationRequest {
                        capability_id: request.capability_id,
                        grant_index: usize::try_from(request.grant_index).map_err(|_| {
                            AdmissionAuthorityWireError {
                                code: AdmissionAuthorityErrorCode::InvalidRequest,
                                message: "combined admission capture grant index overflowed"
                                    .to_owned(),
                            }
                        })?,
                        hold_id: request.hold_id,
                        event_id: request.event_id,
                        trusted_time: None,
                        authority: Some(BudgetEventAuthority {
                            authority_id: request.authority_id,
                            lease_id: request.authority_lease_id,
                            lease_epoch: request.authority_lease_epoch,
                        }),
                    },
                    &request.active_fence,
                    request.trusted_now_unix_ms,
                )
                .map_err(admission_capture_error)?;
            encode(&updated.to_persisted())
        }
        AdmissionAuthorityAction::CommitTerminalProjection => {
            let request: CommitTerminalProjectionWire = decode(payload)?;
            let terminal = operations
                .commit_signed_terminal_projection(&request.projection)
                .map_err(operation_store_error)?;
            encode(&AdmissionTerminalWire {
                operation_id: terminal.operation_id,
                state: terminal.state,
                replay: terminal.replay,
            })
        }
        AdmissionAuthorityAction::LoadAdmissionReceipt => {
            let request: ReceiptIdWire = decode(payload)?;
            let receipt = operations
                .load_chio_receipt(&request.receipt_id)
                .map_err(receipt_store_error)?;
            encode(&receipt)
        }
        AdmissionAuthorityAction::ListAdmissionReceipts => {
            let request: ListAdmissionReceiptsWire = decode(payload)?;
            let receipts = operations
                .list_admission_receipts_after(request.after_receipt_id.as_deref(), request.limit)
                .map_err(receipt_store_error)?;
            encode(&receipts)
        }
    }
}

fn qualify_lease(
    operations: &SqliteAdmissionOperationStore,
    wire: RecoveryClaimWire,
    trusted_now_unix_ms: u64,
    fence: &StoreMutationFence,
) -> Result<chio_kernel::admission_operation::AdmissionRecoveryLease, AdmissionAuthorityWireError> {
    let expected = wire.clone().into_claim().map_err(invalid_operation)?;
    let lease = operations
        .claim_recovery(
            expected.operation_id(),
            expected.claimed_version(),
            expected.claimant_id(),
            trusted_now_unix_ms,
            expected.expires_at_unix_ms(),
            fence,
        )
        .map_err(operation_store_error)?;
    if lease.untrusted_claim() != &expected {
        return Err(wire_error(
            AdmissionAuthorityErrorCode::Fenced,
            "recovery lease changed during remote qualification",
        ));
    }
    Ok(lease)
}

fn decode<T: DeserializeOwned>(
    payload: serde_json::Value,
) -> Result<T, AdmissionAuthorityWireError> {
    serde_json::from_value(payload).map_err(|error| invalid_request(error.to_string()))
}

fn encode<T: Serialize>(value: &T) -> Result<serde_json::Value, AdmissionAuthorityWireError> {
    serde_json::to_value(value).map_err(|error| {
        wire_error(
            AdmissionAuthorityErrorCode::Invariant,
            format!("failed to encode admission authority result: {error}"),
        )
    })
}

fn invalid_request(message: impl Into<String>) -> AdmissionAuthorityWireError {
    wire_error(AdmissionAuthorityErrorCode::InvalidRequest, message)
}

fn invalid_operation(
    error: chio_kernel::admission_operation::AdmissionOperationError,
) -> AdmissionAuthorityWireError {
    invalid_request(error.to_string())
}

fn invalid_outcome(
    error: chio_kernel::tool_outcome::ToolOutcomeError,
) -> AdmissionAuthorityWireError {
    invalid_request(error.to_string())
}

fn operation_store_error(error: AdmissionOperationStoreError) -> AdmissionAuthorityWireError {
    let code = match error {
        AdmissionOperationStoreError::Unavailable(_) => AdmissionAuthorityErrorCode::Unavailable,
        AdmissionOperationStoreError::Fenced => AdmissionAuthorityErrorCode::Fenced,
        AdmissionOperationStoreError::NotFound => AdmissionAuthorityErrorCode::NotFound,
        AdmissionOperationStoreError::Invariant(_) | AdmissionOperationStoreError::Operation(_) => {
            AdmissionAuthorityErrorCode::Invariant
        }
        AdmissionOperationStoreError::OutcomeUnknown(_) => {
            AdmissionAuthorityErrorCode::OutcomeUnknown
        }
    };
    wire_error(code, error.to_string())
}

fn admission_capture_error(
    error: chio_kernel::admission_operation::AdmissionCaptureError,
) -> AdmissionAuthorityWireError {
    use chio_kernel::admission_operation::AdmissionCaptureError;

    let code = match error {
        AdmissionCaptureError::Unavailable(_) => AdmissionAuthorityErrorCode::Unavailable,
        AdmissionCaptureError::Fenced => AdmissionAuthorityErrorCode::Fenced,
        AdmissionCaptureError::OutcomeUnknown(_) => AdmissionAuthorityErrorCode::OutcomeUnknown,
        AdmissionCaptureError::Invariant(_) | AdmissionCaptureError::Operation(_) => {
            AdmissionAuthorityErrorCode::Invariant
        }
    };
    wire_error(code, error.to_string())
}

fn outcome_store_error(error: ToolOutcomeStoreError) -> AdmissionAuthorityWireError {
    let code = match error {
        ToolOutcomeStoreError::Unavailable(_) => AdmissionAuthorityErrorCode::Unavailable,
        ToolOutcomeStoreError::Fenced => AdmissionAuthorityErrorCode::Fenced,
        ToolOutcomeStoreError::NotFound => AdmissionAuthorityErrorCode::NotFound,
        ToolOutcomeStoreError::Conflict => AdmissionAuthorityErrorCode::Conflict,
        ToolOutcomeStoreError::CasConflict => AdmissionAuthorityErrorCode::CasConflict,
        ToolOutcomeStoreError::Invariant(_) => AdmissionAuthorityErrorCode::Invariant,
    };
    wire_error(code, error.to_string())
}

fn receipt_store_error(error: ReceiptStoreError) -> AdmissionAuthorityWireError {
    let code = match error {
        ReceiptStoreError::Fenced => AdmissionAuthorityErrorCode::Fenced,
        ReceiptStoreError::OutcomeUnknown(_) => AdmissionAuthorityErrorCode::OutcomeUnknown,
        ReceiptStoreError::NotFound(_) => AdmissionAuthorityErrorCode::NotFound,
        ReceiptStoreError::Unsupported(_) => AdmissionAuthorityErrorCode::Unsupported,
        ReceiptStoreError::Timeout { .. } => AdmissionAuthorityErrorCode::Timeout,
        ReceiptStoreError::Conflict(_) => AdmissionAuthorityErrorCode::Conflict,
        _ => AdmissionAuthorityErrorCode::Unavailable,
    };
    wire_error(code, error.to_string())
}

fn wire_error(
    code: AdmissionAuthorityErrorCode,
    message: impl Into<String>,
) -> AdmissionAuthorityWireError {
    AdmissionAuthorityWireError {
        code,
        message: message.into(),
    }
}
