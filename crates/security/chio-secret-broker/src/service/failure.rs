use super::{
    broker_execute_request_registration_digest, broker_request_digest, canonical_json_bytes,
    capability_digest, derive_attempt_ids, failure_receipt_digest, sign_failure_receipt,
    validate_digest, validate_identifier, verify_failure_receipt, AttemptRecord, AttemptState,
    AttemptTransitionEvidence, BrokerDispatchKnowledge, BrokerError, BrokerExecuteFailure,
    BrokerExecuteRequest, BrokerFailureOutcome, BrokerFailureReceiptBody, BrokerFailureStage,
    BrokerService, Digest, ExecutionHoldState, QueryExecutionHoldRequest, Result, Sha256,
    BROKER_FAILURE_RECEIPT_SCHEMA, FAILURE_RECEIPT_REQUEST_DOMAIN,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FailureOrigin {
    Admission,
    Execution,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FailureProjection {
    pub(super) stage: BrokerFailureStage,
    pub(super) outcome: BrokerFailureOutcome,
    pub(super) dispatch_knowledge: BrokerDispatchKnowledge,
}

#[derive(Debug)]
pub(super) struct ExecutionFailure {
    pub(super) error: BrokerError,
    pub(super) projection: Option<FailureProjection>,
}

impl ExecutionFailure {
    pub(super) fn at(error: BrokerError, projection: FailureProjection) -> Self {
        Self {
            error,
            projection: Some(projection),
        }
    }
}

impl From<BrokerError> for ExecutionFailure {
    fn from(error: BrokerError) -> Self {
        Self {
            error,
            projection: None,
        }
    }
}

pub(super) type ExecutionResult<T> = std::result::Result<T, ExecutionFailure>;

pub(super) fn execution_failure_after_capture_release(
    error: BrokerError,
    released: Result<bool>,
) -> ExecutionFailure {
    let projection = released
        .ok()
        .filter(|released| *released)
        .map(|_| FailureProjection {
            stage: BrokerFailureStage::Capture,
            outcome: failure_outcome_before_dispatch(&error),
            dispatch_knowledge: BrokerDispatchKnowledge::NotCommitted,
        });
    ExecutionFailure { error, projection }
}

pub(super) fn validate_execution_projection_for_attempt(
    attempt: &AttemptRecord,
    projection: FailureProjection,
) -> Result<()> {
    let compatible = match (
        projection.stage,
        projection.outcome,
        projection.dispatch_knowledge,
    ) {
        (
            BrokerFailureStage::Capture,
            BrokerFailureOutcome::Denied | BrokerFailureOutcome::Failed,
            BrokerDispatchKnowledge::NotCommitted,
        ) => attempt.state == AttemptState::Captured && attempt.dispatch_claim_id.is_none(),
        (
            BrokerFailureStage::Dispatch,
            BrokerFailureOutcome::Unknown,
            BrokerDispatchKnowledge::Unknown,
        )
        | (
            BrokerFailureStage::Response | BrokerFailureStage::ReceiptPersistence,
            BrokerFailureOutcome::Failed,
            BrokerDispatchKnowledge::Committed,
        ) => {
            matches!(
                attempt.state,
                AttemptState::DispatchCommitted | AttemptState::UnknownOutcome
            ) && attempt_has_capture_evidence(attempt)
        }
        _ => false,
    };
    if !compatible {
        return Err(BrokerError::Conflict(
            "execution failure provenance conflicts with the durable attempt boundary".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn attempt_has_capture_evidence(attempt: &AttemptRecord) -> bool {
    attempt.revocation_set_digest.is_some()
        && attempt.budget_commit_index.is_some()
        && attempt.revocation_commit_index.is_some()
        && attempt.authority_commit_index.is_some()
        && attempt.leader_epoch.is_some()
}

pub(super) fn failure_projection_matches_attempt(
    attempt: &AttemptRecord,
    receipt: &BrokerFailureReceiptBody,
    target: AttemptState,
) -> bool {
    match attempt.state {
        AttemptState::Registered => {
            target == AttemptState::Failed
                && receipt.stage == BrokerFailureStage::Admission
                && receipt.dispatch_knowledge == BrokerDispatchKnowledge::NotStarted
                && matches!(
                    receipt.outcome,
                    BrokerFailureOutcome::Denied | BrokerFailureOutcome::Failed
                )
        }
        AttemptState::Prepared => {
            receipt.stage == BrokerFailureStage::Hold
                && receipt.dispatch_knowledge == BrokerDispatchKnowledge::NotCommitted
                && matches!(
                    receipt.outcome,
                    BrokerFailureOutcome::Denied
                        | BrokerFailureOutcome::Reversed
                        | BrokerFailureOutcome::Failed
                )
        }
        AttemptState::Held => {
            receipt.stage == BrokerFailureStage::Capture
                && receipt.dispatch_knowledge == BrokerDispatchKnowledge::NotCommitted
                && matches!(
                    receipt.outcome,
                    BrokerFailureOutcome::Denied
                        | BrokerFailureOutcome::Reversed
                        | BrokerFailureOutcome::Failed
                )
        }
        AttemptState::Captured => {
            target == AttemptState::Failed
                && attempt.dispatch_claim_id.is_none()
                && receipt.stage == BrokerFailureStage::Capture
                && receipt.dispatch_knowledge == BrokerDispatchKnowledge::NotCommitted
                && matches!(
                    receipt.outcome,
                    BrokerFailureOutcome::Denied | BrokerFailureOutcome::Failed
                )
        }
        AttemptState::DispatchCommitted | AttemptState::UnknownOutcome => {
            target == AttemptState::Failed
                && attempt_has_capture_evidence(attempt)
                && matches!(
                    (receipt.stage, receipt.outcome, receipt.dispatch_knowledge,),
                    (
                        BrokerFailureStage::Dispatch,
                        BrokerFailureOutcome::Unknown,
                        BrokerDispatchKnowledge::Unknown,
                    ) | (
                        BrokerFailureStage::Response | BrokerFailureStage::ReceiptPersistence,
                        BrokerFailureOutcome::Failed,
                        BrokerDispatchKnowledge::Committed,
                    )
                )
        }
        AttemptState::Failed => target == AttemptState::Failed,
        AttemptState::Reversed => target == AttemptState::Reversed,
        AttemptState::Completed => false,
    }
}

pub(super) fn execution_hold_query(attempt: &AttemptRecord) -> Result<QueryExecutionHoldRequest> {
    let query = QueryExecutionHoldRequest {
        operation_id: attempt.registration.ids.operation_id.clone(),
        invocation_id: attempt.registration.invocation_id.clone(),
        parent_capability_id: attempt.registration.parent_capability_id.clone(),
        broker_capability_id: attempt.registration.broker_capability_id.clone(),
        hold_id: attempt.registration.ids.hold_id.clone(),
        authorize_event_id: attempt.registration.ids.authorize_event_id.clone(),
        reverse_event_id: attempt.registration.ids.reverse_event_id.clone(),
        capture_event_id: attempt.registration.ids.capture_event_id.clone(),
    };
    query.validate()?;
    Ok(query)
}

pub(super) fn pre_dispatch_authority_projection(
    state: AttemptState,
    outcome: BrokerFailureOutcome,
) -> Result<FailureProjection> {
    let (stage, dispatch_knowledge) = match state {
        AttemptState::Registered if outcome == BrokerFailureOutcome::Denied => (
            BrokerFailureStage::Admission,
            BrokerDispatchKnowledge::NotStarted,
        ),
        AttemptState::Prepared => (
            BrokerFailureStage::Hold,
            BrokerDispatchKnowledge::NotCommitted,
        ),
        AttemptState::Held | AttemptState::Reversed => (
            BrokerFailureStage::Capture,
            BrokerDispatchKnowledge::NotCommitted,
        ),
        AttemptState::Failed if outcome == BrokerFailureOutcome::Denied => (
            BrokerFailureStage::Admission,
            BrokerDispatchKnowledge::NotStarted,
        ),
        AttemptState::Failed if outcome == BrokerFailureOutcome::Reversed => (
            BrokerFailureStage::Capture,
            BrokerDispatchKnowledge::NotCommitted,
        ),
        AttemptState::Registered
        | AttemptState::Captured
        | AttemptState::DispatchCommitted
        | AttemptState::UnknownOutcome
        | AttemptState::Completed
        | AttemptState::Failed => {
            return Err(BrokerError::Conflict(
                "authoritative pre-dispatch terminal conflicts with the local attempt state"
                    .to_string(),
            ));
        }
    };
    Ok(FailureProjection {
        stage,
        outcome,
        dispatch_knowledge,
    })
}

pub(super) fn failure_state_projection(
    state: AttemptState,
    error: &BrokerError,
) -> Result<FailureProjection> {
    Ok(match state {
        AttemptState::Registered => FailureProjection {
            stage: BrokerFailureStage::Admission,
            outcome: failure_outcome_before_dispatch(error),
            dispatch_knowledge: BrokerDispatchKnowledge::NotStarted,
        },
        AttemptState::Prepared => FailureProjection {
            stage: BrokerFailureStage::Hold,
            outcome: failure_outcome_before_dispatch(error),
            dispatch_knowledge: BrokerDispatchKnowledge::NotCommitted,
        },
        AttemptState::Held => FailureProjection {
            stage: BrokerFailureStage::Capture,
            outcome: failure_outcome_before_dispatch(error),
            dispatch_knowledge: BrokerDispatchKnowledge::NotCommitted,
        },
        AttemptState::Reversed => FailureProjection {
            stage: BrokerFailureStage::Capture,
            outcome: BrokerFailureOutcome::Reversed,
            dispatch_knowledge: BrokerDispatchKnowledge::NotCommitted,
        },
        AttemptState::Failed => FailureProjection {
            stage: BrokerFailureStage::Admission,
            outcome: failure_outcome_before_dispatch(error),
            dispatch_knowledge: BrokerDispatchKnowledge::NotStarted,
        },
        AttemptState::Captured
        | AttemptState::DispatchCommitted
        | AttemptState::UnknownOutcome
        | AttemptState::Completed => {
            return Err(BrokerError::Conflict(
                "post-capture broker attempt cannot emit a failure receipt".to_string(),
            ));
        }
    })
}

pub(super) fn failure_receipt_id(request: &BrokerExecuteRequest) -> Result<String> {
    failure_receipt_id_for_canonical_request_digest(&failure_receipt_key_digest(request)?)
}

pub(super) fn failure_receipt_key_digest(request: &BrokerExecuteRequest) -> Result<String> {
    match broker_execute_request_registration_digest(request) {
        Ok(digest) => Ok(digest),
        Err(_) => {
            let canonical = canonical_json_bytes(request).map_err(|error| {
                BrokerError::Invariant(format!("failure terminal request encoding failed: {error}"))
            })?;
            let mut hasher = Sha256::new();
            hasher.update(FAILURE_RECEIPT_REQUEST_DOMAIN);
            hasher.update(canonical);
            Ok(hex::encode(hasher.finalize()))
        }
    }
}

pub(crate) fn failure_receipt_id_for_canonical_request_digest(digest: &str) -> Result<String> {
    validate_digest(digest, "failure terminal canonical request digest")?;
    Ok(format!("broker-failure-terminal-{digest}"))
}

pub(super) fn failure_bound_request_digest(request: &BrokerExecuteRequest) -> Result<String> {
    broker_request_digest(request).or_else(|_| {
        let canonical = canonical_json_bytes(request).map_err(|error| {
            BrokerError::Invariant(format!("failure request fallback encoding failed: {error}"))
        })?;
        Ok(hex::encode(Sha256::digest(canonical)))
    })
}

pub(super) fn failure_outcome_before_dispatch(error: &BrokerError) -> BrokerFailureOutcome {
    if matches!(error, BrokerError::AuthorizationDenied(_)) {
        BrokerFailureOutcome::Denied
    } else {
        BrokerFailureOutcome::Failed
    }
}
impl BrokerService {
    /// Recover the exact first durable failure before consulting live
    /// admission authorities or allowing another dispatch attempt. The
    /// deterministic receipt ID binds the complete canonical execute request,
    /// including failures that occurred before an attempt was registered.
    pub fn replay_failure(
        &self,
        request: &BrokerExecuteRequest,
        now_unix_seconds: u64,
    ) -> Result<Option<BrokerExecuteFailure>> {
        let _operation_guard = self.attempt_operation_guard_for_request(request)?;
        self.replay_failure_locked(request, now_unix_seconds)
    }

    pub(super) fn replay_failure_locked(
        &self,
        request: &BrokerExecuteRequest,
        now_unix_seconds: u64,
    ) -> Result<Option<BrokerExecuteFailure>> {
        let receipt_id = failure_receipt_id(request)?;
        let Some(receipt) = self.receipt_sink.load_failure(&receipt_id)? else {
            return Ok(None);
        };
        verify_failure_receipt(&receipt, &self.receipt_signer.public_key())?;
        let request_digest = failure_bound_request_digest(request)?;
        let capability_digest = capability_digest(&request.capability).ok();
        if receipt.body.receipt_id != receipt_id
            || receipt.body.request_digest != request_digest
            || receipt.body.capability_digest != capability_digest
        {
            return Err(BrokerError::Storage(
                "durable broker failure receipt is misbound to its exact request".to_string(),
            ));
        }

        let ids = derive_attempt_ids(
            &request.capability.body.capability_id,
            &request.invocation_id,
            &request.proof.body.nonce,
            &request_digest,
        )
        .ok();
        let attempt = match ids.as_ref() {
            Some(ids) => self.attempts.load_attempt(&ids.attempt_id)?,
            None => None,
        };
        if let Some(attempt) = attempt.as_ref() {
            let expected = Self::expected_registration(request, &attempt.registration)?;
            if expected != attempt.registration {
                return Err(BrokerError::Conflict(
                    "durable broker failure request differs from its attempt registration"
                        .to_string(),
                ));
            }
            if receipt.body.attempt_id.is_some()
                && (receipt.body.attempt_id.as_deref()
                    != Some(attempt.registration.ids.attempt_id.as_str())
                    || receipt.body.invocation_id.as_deref()
                        != Some(attempt.registration.invocation_id.as_str())
                    || receipt.body.hold_id.as_deref()
                        != Some(attempt.registration.ids.hold_id.as_str())
                    || receipt.body.parent_capability_id.as_deref()
                        != Some(attempt.registration.parent_capability_id.as_str())
                    || receipt.body.broker_capability_id.as_deref()
                        != Some(attempt.registration.broker_capability_id.as_str()))
            {
                return Err(BrokerError::Storage(
                    "durable broker failure receipt is misbound to its attempt journal".to_string(),
                ));
            }
            self.terminalize_failure_attempt(attempt, &receipt.body, now_unix_seconds)?;
        }

        let reference = format!(
            "broker-failure-receipt-sha256-{}",
            failure_receipt_digest(&receipt)?
        );
        validate_identifier(&reference, "failure receipt reference", 512)?;
        Ok(Some(BrokerExecuteFailure {
            diagnostic_code: receipt.body.diagnostic_code.clone(),
            receipt_reference: reference,
            receipt,
        }))
    }

    pub fn persist_admission_failure(
        &self,
        request: &BrokerExecuteRequest,
        now_unix_seconds: u64,
        error: &BrokerError,
    ) -> Result<BrokerExecuteFailure> {
        let _operation_guard = self.attempt_operation_guard_for_request(request)?;
        self.persist_failure_for_origin(
            request,
            now_unix_seconds,
            error,
            FailureOrigin::Admission,
            None,
        )
    }

    pub(super) fn persist_failure_for_origin(
        &self,
        request: &BrokerExecuteRequest,
        now_unix_seconds: u64,
        error: &BrokerError,
        origin: FailureOrigin,
        known_projection: Option<FailureProjection>,
    ) -> Result<BrokerExecuteFailure> {
        if let Some(failure) = self.replay_failure_locked(request, now_unix_seconds)? {
            return Ok(failure);
        }
        let attempt = self.attempt_for_request(request)?;
        let projection = match attempt.as_ref() {
            Some(attempt) => {
                let expected = Self::expected_registration(request, &attempt.registration)?;
                if expected != attempt.registration {
                    return Err(BrokerError::Conflict(
                        "failure request differs from its durable attempt registration".to_string(),
                    ));
                }
                Some(match (origin, known_projection) {
                    (FailureOrigin::Admission, Some(_)) => {
                        return Err(BrokerError::Invariant(
                            "admission failure cannot carry execution-stage provenance".to_string(),
                        ));
                    }
                    (FailureOrigin::Admission, None) => {
                        self.authoritative_pre_dispatch_terminal(attempt, error, now_unix_seconds)?
                    }
                    (FailureOrigin::Execution, Some(projection)) => {
                        validate_execution_projection_for_attempt(attempt, projection)?;
                        projection
                    }
                    (FailureOrigin::Execution, None) => {
                        self.execution_failure_projection(attempt, error, now_unix_seconds)?
                    }
                })
            }
            None => {
                if matches!(error, BrokerError::AuthorityUnavailable(_)) {
                    return Err(BrokerError::AuthorityUnavailable(
                        "transient broker authority failure remains retryable".to_string(),
                    ));
                }
                None
            }
        };
        self.persist_terminal_failure(request, now_unix_seconds, error, projection)
    }

    fn attempt_for_request(&self, request: &BrokerExecuteRequest) -> Result<Option<AttemptRecord>> {
        let request_digest = failure_bound_request_digest(request)?;
        let ids = derive_attempt_ids(
            &request.capability.body.capability_id,
            &request.invocation_id,
            &request.proof.body.nonce,
            &request_digest,
        )?;
        self.attempts.load_attempt(&ids.attempt_id)
    }

    fn authoritative_pre_dispatch_terminal(
        &self,
        attempt: &AttemptRecord,
        _error: &BrokerError,
        now_unix_seconds: u64,
    ) -> Result<FailureProjection> {
        if matches!(
            attempt.state,
            AttemptState::Captured
                | AttemptState::DispatchCommitted
                | AttemptState::UnknownOutcome
                | AttemptState::Completed
        ) {
            return Err(BrokerError::AuthorityUnavailable(
                "post-capture broker attempt remains on its recovery path".to_string(),
            ));
        }
        let query = execution_hold_query(attempt)?;
        match self.budget.query_execution_hold(&query)? {
            ExecutionHoldState::Denied => {
                pre_dispatch_authority_projection(attempt.state, BrokerFailureOutcome::Denied)
            }
            ExecutionHoldState::Reversed => {
                pre_dispatch_authority_projection(attempt.state, BrokerFailureOutcome::Reversed)
            }
            ExecutionHoldState::Captured(commit) => {
                self.reconcile_captured_failure_boundary(attempt, commit, now_unix_seconds)?;
                Err(BrokerError::AuthorityUnavailable(
                    "authoritative broker capture requires recovery without a failure terminal"
                        .to_string(),
                ))
            }
            ExecutionHoldState::Unknown | ExecutionHoldState::Held => {
                Err(BrokerError::AuthorityUnavailable(
                    "broker admission remains nonterminal and retryable".to_string(),
                ))
            }
        }
    }

    fn reconcile_captured_failure_boundary(
        &self,
        attempt: &AttemptRecord,
        commit: crate::budget::CombinedCaptureCommit,
        now_unix_seconds: u64,
    ) -> Result<()> {
        let evidence = AttemptTransitionEvidence {
            revocation_set_digest: Some(commit.checked_revocation_set_digest),
            budget_commit_index: Some(commit.budget_commit_index),
            revocation_commit_index: Some(commit.revocation_commit_index),
            authority_commit_index: Some(commit.authority_commit_index),
            leader_epoch: Some(commit.leader_epoch),
            response_digest: None,
        };
        let current = if attempt.state == AttemptState::Registered {
            if self
                .attempts
                .claim_registered_attempt(&attempt.registration.ids.attempt_id, now_unix_seconds)?
            {
                self.attempts
                    .load_attempt(&attempt.registration.ids.attempt_id)?
                    .ok_or_else(|| {
                        BrokerError::Storage(
                            "captured broker attempt disappeared after preparation claim"
                                .to_string(),
                        )
                    })?
            } else {
                self.attempts
                    .load_attempt(&attempt.registration.ids.attempt_id)?
                    .ok_or_else(|| {
                        BrokerError::Storage(
                            "captured broker attempt disappeared during reconciliation".to_string(),
                        )
                    })?
            }
        } else {
            attempt.clone()
        };
        match current.state {
            AttemptState::Prepared | AttemptState::Held | AttemptState::Captured => {
                self.attempts.transition(
                    &current.registration.ids.attempt_id,
                    current.state,
                    AttemptState::Captured,
                    &evidence,
                    now_unix_seconds.max(current.updated_at_unix_seconds),
                )?;
                Ok(())
            }
            AttemptState::DispatchCommitted | AttemptState::UnknownOutcome => Ok(()),
            AttemptState::Registered
            | AttemptState::Reversed
            | AttemptState::Completed
            | AttemptState::Failed => Err(BrokerError::Conflict(
                "authoritative capture conflicts with the local broker attempt".to_string(),
            )),
        }
    }

    fn execution_failure_projection(
        &self,
        attempt: &AttemptRecord,
        error: &BrokerError,
        now_unix_seconds: u64,
    ) -> Result<FailureProjection> {
        match attempt.state {
            AttemptState::Captured if attempt.dispatch_claim_id.is_none() => {
                Ok(FailureProjection {
                    stage: BrokerFailureStage::Capture,
                    outcome: failure_outcome_before_dispatch(error),
                    dispatch_knowledge: BrokerDispatchKnowledge::NotCommitted,
                })
            }
            AttemptState::Captured => Err(BrokerError::AuthorityUnavailable(
                "captured broker attempt still has a live dispatch claim".to_string(),
            )),
            AttemptState::DispatchCommitted | AttemptState::UnknownOutcome => {
                Err(BrokerError::AuthorityUnavailable(
                    "post-dispatch broker failure lacks exact boundary provenance".to_string(),
                ))
            }
            AttemptState::Completed => Err(BrokerError::Conflict(
                "completed broker attempt cannot emit a failure terminal".to_string(),
            )),
            AttemptState::Registered
            | AttemptState::Prepared
            | AttemptState::Held
            | AttemptState::Reversed
            | AttemptState::Failed => {
                self.authoritative_pre_dispatch_terminal(attempt, error, now_unix_seconds)
            }
        }
    }

    fn persist_terminal_failure(
        &self,
        request: &BrokerExecuteRequest,
        now_unix_seconds: u64,
        error: &BrokerError,
        projection: Option<FailureProjection>,
    ) -> Result<BrokerExecuteFailure> {
        if let Some(failure) = self.replay_failure_locked(request, now_unix_seconds)? {
            return Ok(failure);
        }
        let receipt_id = failure_receipt_id(request)?;
        let request_digest = failure_bound_request_digest(request)?;
        let capability_digest = capability_digest(&request.capability).ok();
        let ids = derive_attempt_ids(
            &request.capability.body.capability_id,
            &request.invocation_id,
            &request.proof.body.nonce,
            &request_digest,
        )
        .ok();
        let attempt = match ids.as_ref() {
            Some(ids) => self.attempts.load_attempt(&ids.attempt_id)?,
            None => None,
        };
        if let Some(attempt) = attempt.as_ref() {
            let expected = Self::expected_registration(request, &attempt.registration)?;
            if expected != attempt.registration {
                return Err(BrokerError::Conflict(
                    "failure request differs from its durable attempt registration".to_string(),
                ));
            }
        }
        let (
            issued_at_unix_seconds,
            stage,
            outcome,
            dispatch_knowledge,
            attempt_id,
            invocation_id,
            hold_id,
            parent_capability_id,
            broker_capability_id,
            bound_request_digest,
        ) = match attempt.as_ref() {
            Some(attempt) => {
                let projection = match projection {
                    Some(projection) => projection,
                    None => failure_state_projection(attempt.state, error)?,
                };
                (
                    now_unix_seconds
                        .max(attempt.updated_at_unix_seconds)
                        .max(request.proof.body.issued_at_unix_seconds)
                        .max(1),
                    projection.stage,
                    projection.outcome,
                    projection.dispatch_knowledge,
                    Some(attempt.registration.ids.attempt_id.clone()),
                    Some(attempt.registration.invocation_id.clone()),
                    Some(attempt.registration.ids.hold_id.clone()),
                    Some(attempt.registration.parent_capability_id.clone()),
                    Some(attempt.registration.broker_capability_id.clone()),
                    attempt.registration.request_digest.clone(),
                )
            }
            None => (
                now_unix_seconds
                    .max(request.proof.body.issued_at_unix_seconds)
                    .max(1),
                BrokerFailureStage::Admission,
                failure_outcome_before_dispatch(error),
                BrokerDispatchKnowledge::NotStarted,
                None,
                None,
                None,
                None,
                None,
                request_digest,
            ),
        };
        let diagnostic_code = format!("chio.broker.{}", error.diagnostic_code());
        let receipt = sign_failure_receipt(
            BrokerFailureReceiptBody {
                schema: BROKER_FAILURE_RECEIPT_SCHEMA.to_string(),
                receipt_id,
                issued_at_unix_seconds,
                stage,
                outcome,
                diagnostic_code: diagnostic_code.clone(),
                request_digest: bound_request_digest,
                capability_digest,
                attempt_id,
                invocation_id,
                hold_id,
                parent_capability_id,
                broker_capability_id,
                dispatch_knowledge,
            },
            self.receipt_signer.as_ref(),
        )?;
        let reference = match self.receipt_sink.persist_failure(&receipt) {
            Ok(reference) => reference,
            Err(BrokerError::Conflict(_)) => {
                return self
                    .replay_failure_locked(request, now_unix_seconds)?
                    .ok_or_else(|| {
                        BrokerError::Conflict(
                            "broker attempt already has a different durable failure terminal"
                                .to_string(),
                        )
                    });
            }
            Err(error) => return Err(error),
        };
        validate_identifier(&reference, "failure receipt reference", 512)?;
        let expected_reference = format!(
            "broker-failure-receipt-sha256-{}",
            crate::receipt::failure_receipt_digest(&receipt)?
        );
        if reference != expected_reference {
            return Err(BrokerError::Invariant(
                "broker receipt sink returned an unbound failure receipt reference".to_string(),
            ));
        }
        if let Some(attempt) = attempt.as_ref() {
            self.terminalize_failure_attempt(attempt, &receipt.body, now_unix_seconds)?;
        }
        Ok(BrokerExecuteFailure {
            diagnostic_code,
            receipt_reference: reference,
            receipt,
        })
    }

    fn terminalize_failure_attempt(
        &self,
        attempt: &AttemptRecord,
        receipt: &BrokerFailureReceiptBody,
        now_unix_seconds: u64,
    ) -> Result<()> {
        let target = if receipt.outcome == BrokerFailureOutcome::Reversed {
            AttemptState::Reversed
        } else {
            AttemptState::Failed
        };
        if !failure_projection_matches_attempt(attempt, receipt, target) {
            return Err(BrokerError::Conflict(
                "broker failure receipt conflicts with the durable attempt boundary".to_string(),
            ));
        }
        match attempt.state {
            AttemptState::Registered | AttemptState::Prepared | AttemptState::Held => {
                if attempt.state == AttemptState::Registered && target == AttemptState::Reversed {
                    return Err(BrokerError::Conflict(
                        "registered broker attempt cannot claim an authoritative reversal"
                            .to_string(),
                    ));
                }
                self.attempts.transition(
                    &attempt.registration.ids.attempt_id,
                    attempt.state,
                    target,
                    &AttemptTransitionEvidence::default(),
                    now_unix_seconds.max(attempt.updated_at_unix_seconds),
                )?;
            }
            AttemptState::Captured
                if target == AttemptState::Failed
                    && attempt.dispatch_claim_id.is_none()
                    && receipt.stage == BrokerFailureStage::Capture
                    && receipt.dispatch_knowledge == BrokerDispatchKnowledge::NotCommitted =>
            {
                self.attempts.transition(
                    &attempt.registration.ids.attempt_id,
                    AttemptState::Captured,
                    AttemptState::Failed,
                    &AttemptTransitionEvidence {
                        revocation_set_digest: attempt.revocation_set_digest.clone(),
                        budget_commit_index: attempt.budget_commit_index,
                        revocation_commit_index: attempt.revocation_commit_index,
                        authority_commit_index: attempt.authority_commit_index,
                        leader_epoch: attempt.leader_epoch,
                        response_digest: None,
                    },
                    now_unix_seconds.max(attempt.updated_at_unix_seconds),
                )?;
            }
            AttemptState::DispatchCommitted | AttemptState::UnknownOutcome
                if target == AttemptState::Failed
                    && attempt_has_capture_evidence(attempt)
                    && matches!(
                        (receipt.stage, receipt.outcome, receipt.dispatch_knowledge,),
                        (
                            BrokerFailureStage::Dispatch,
                            BrokerFailureOutcome::Unknown,
                            BrokerDispatchKnowledge::Unknown,
                        ) | (
                            BrokerFailureStage::Response | BrokerFailureStage::ReceiptPersistence,
                            BrokerFailureOutcome::Failed,
                            BrokerDispatchKnowledge::Committed,
                        )
                    ) =>
            {
                self.attempts.transition(
                    &attempt.registration.ids.attempt_id,
                    attempt.state,
                    AttemptState::Failed,
                    &AttemptTransitionEvidence {
                        revocation_set_digest: attempt.revocation_set_digest.clone(),
                        budget_commit_index: attempt.budget_commit_index,
                        revocation_commit_index: attempt.revocation_commit_index,
                        authority_commit_index: attempt.authority_commit_index,
                        leader_epoch: attempt.leader_epoch,
                        response_digest: attempt.response_digest.clone(),
                    },
                    now_unix_seconds.max(attempt.updated_at_unix_seconds),
                )?;
            }
            AttemptState::Failed if target == AttemptState::Failed => {}
            AttemptState::Reversed if target == AttemptState::Reversed => {}
            AttemptState::Captured
            | AttemptState::DispatchCommitted
            | AttemptState::UnknownOutcome
            | AttemptState::Completed
            | AttemptState::Failed
            | AttemptState::Reversed => {
                return Err(BrokerError::Conflict(
                    "broker failure receipt conflicts with the durable attempt state".to_string(),
                ));
            }
        }
        self.discard_prepared_dispatch(&attempt.registration.ids.operation_id)?;
        Ok(())
    }
}
