use super::*;

impl BrokerService {


    pub fn execute(
        &self,
        request: &BrokerExecuteRequest,
        trusted: &TrustedExecutionContext,
        now_unix_seconds: u64,
    ) -> Result<BrokerExecuteResponse> {
        match self.execute_evidenced(request, trusted, now_unix_seconds)? {
            BrokerExecuteOutcome::Success(response) => Ok(*response),
            BrokerExecuteOutcome::Failure(failure) => {
                let failure = *failure;
                Err(BrokerError::AuthorizationDenied(failure.diagnostic_code))
            }
        }
    }

    /// Recover an exact durable completion before consulting live admission
    /// authorities. This path accepts only the canonical request that created
    /// the persisted attempt and the broker-signed completed response.
    pub fn replay_completed(
        &self,
        request: &BrokerExecuteRequest,
        now_unix_seconds: u64,
    ) -> Result<Option<BrokerExecuteResponse>> {
        let _operation_guard = self.attempt_operation_guard_for_request(request)?;
        request.validate_bounds()?;
        let request_digest = broker_request_digest(request)?;
        let provisional_ids = derive_attempt_ids(
            &request.capability.body.capability_id,
            &request.invocation_id,
            &request.proof.body.nonce,
            &request_digest,
        )?;
        let Some(attempt) = self.attempts.load_attempt(&provisional_ids.attempt_id)? else {
            return Ok(None);
        };
        if !matches!(
            attempt.state,
            AttemptState::DispatchCommitted
                | AttemptState::UnknownOutcome
                | AttemptState::Completed
        ) {
            return Ok(None);
        }
        let expected = Self::expected_registration(request, &attempt.registration)?;
        if expected != attempt.registration {
            return Err(BrokerError::Conflict(
                "completed replay request differs from its durable registration".to_string(),
            ));
        }
        let Some(response) = self
            .receipt_sink
            .load_completed(&attempt.registration.ids.attempt_id)?
        else {
            if attempt.state == AttemptState::Completed {
                return Err(BrokerError::Storage(
                    "completed broker attempt lacks its durable replay response".to_string(),
                ));
            }
            return Ok(None);
        };
        let trusted = TrustedExecutionContext {
            admission_operation_id: attempt.registration.ids.operation_id.clone(),
            prepared_dispatch_id: prepared_dispatch_id(&attempt.registration, request)?,
            quotas: attempt.registration.quotas.clone(),
            authority_metadata_digest: attempt.registration.authority_metadata_digest.clone(),
            revocation_authority_domain: attempt.registration.revocation_authority_domain.clone(),
            source_receipt_ids: response.receipt.body.source_receipt_ids.clone(),
        };
        trusted.validate_for(request)?;
        self.validate_completed_replay(request, &trusted, &attempt, &response)?;
        if attempt.state != AttemptState::Completed {
            self.attempts.transition(
                &attempt.registration.ids.attempt_id,
                attempt.state,
                AttemptState::Completed,
                &AttemptTransitionEvidence {
                    revocation_set_digest: attempt.revocation_set_digest,
                    budget_commit_index: attempt.budget_commit_index,
                    revocation_commit_index: attempt.revocation_commit_index,
                    authority_commit_index: attempt.authority_commit_index,
                    leader_epoch: attempt.leader_epoch,
                    response_digest: Some(response.evidence.response_body_sha256.clone()),
                },
                now_unix_seconds,
            )?;
        }
        Ok(Some(response))
    }

    pub fn execute_evidenced(
        &self,
        request: &BrokerExecuteRequest,
        trusted: &TrustedExecutionContext,
        now_unix_seconds: u64,
    ) -> Result<BrokerExecuteOutcome> {
        self.execute_evidenced_with_terminal_clock(request, trusted, now_unix_seconds, &|| {
            Ok(now_unix_seconds)
        })
    }

    pub(crate) fn execute_evidenced_with_terminal_clock(
        &self,
        request: &BrokerExecuteRequest,
        trusted: &TrustedExecutionContext,
        now_unix_seconds: u64,
        terminal_clock: &dyn Fn() -> Result<u64>,
    ) -> Result<BrokerExecuteOutcome> {
        let _operation_guard = self.attempt_operation_guard_for_request(request)?;
        if let Some(failure) = self.replay_failure_locked(request, now_unix_seconds)? {
            return Ok(BrokerExecuteOutcome::Failure(Box::new(failure)));
        }
        match self.execute_inner(request, trusted, now_unix_seconds, terminal_clock) {
            Ok(response) => Ok(BrokerExecuteOutcome::Success(Box::new(response))),
            Err(failure) => {
                if self.targets_completed_attempt(request)? {
                    return Err(failure.error);
                }
                let terminal_unix_seconds = terminal_clock()?.max(now_unix_seconds);
                self.persist_failure_for_origin(
                    request,
                    terminal_unix_seconds,
                    &failure.error,
                    FailureOrigin::Execution,
                    failure.projection,
                )
                .map(|failure| BrokerExecuteOutcome::Failure(Box::new(failure)))
            }
        }
    }

    pub(super) fn targets_completed_attempt(&self, request: &BrokerExecuteRequest) -> Result<bool> {
        let request_digest = broker_request_digest(request)?;
        let ids = derive_attempt_ids(
            &request.capability.body.capability_id,
            &request.invocation_id,
            &request.proof.body.nonce,
            &request_digest,
        )?;
        let Some(attempt) = self.attempts.load_attempt(&ids.attempt_id)? else {
            return Ok(false);
        };
        if attempt.state == AttemptState::Completed {
            return Ok(true);
        }
        if self.receipt_sink.supports_completed_replay()
            && matches!(
                attempt.state,
                AttemptState::DispatchCommitted | AttemptState::UnknownOutcome
            )
        {
            return Ok(self.receipt_sink.load_completed(&ids.attempt_id)?.is_some());
        }
        Ok(false)
    }pub(super) fn execute_inner(
        &self,
        request: &BrokerExecuteRequest,
        trusted: &TrustedExecutionContext,
        now_unix_seconds: u64,
        terminal_clock: &dyn Fn() -> Result<u64>,
    ) -> ExecutionResult<BrokerExecuteResponse> {
        self.budget.capabilities().require_production()?;
        trusted.validate_for(request)?;

        let request_digest = broker_request_digest(request)?;
        let capability_digest = capability_digest(&request.capability)?;
        let ids = derive_attempt_ids_for_operation(
            &request.capability.body.capability_id,
            &request.invocation_id,
            &request.proof.body.nonce,
            &request_digest,
            &trusted.admission_operation_id,
        )?;
        let existing = self
            .attempts
            .load_attempt(&ids.attempt_id)?
            .ok_or_else(|| {
                BrokerError::AuthorizationDenied(
                    "broker execution has no authenticated pre-registered attempt".to_string(),
                )
            })?;
        if existing.registration.ids.operation_id != trusted.admission_operation_id
            || existing.registration.quotas != trusted.quotas
            || existing.registration.authority_metadata_digest != trusted.authority_metadata_digest
            || existing.registration.revocation_authority_domain
                != trusted.revocation_authority_domain
        {
            return Err(BrokerError::AuthorizationDenied(
                "trusted kernel context differs from the registered attempt".to_string(),
            )
            .into());
        }
        let registration = Self::expected_registration(request, &existing.registration)?;
        if existing.registration != registration {
            return Err(BrokerError::Conflict(
                "pre-registered broker attempt differs from execution input".to_string(),
            )
            .into());
        }
        let expected_prepared_dispatch_id = prepared_dispatch_id(&registration, request)?;
        if trusted.prepared_dispatch_id != expected_prepared_dispatch_id {
            return Err(BrokerError::AuthorizationDenied(
                "trusted kernel context is not bound to the prepared broker dispatch".to_string(),
            )
            .into());
        }

        if matches!(
            existing.state,
            AttemptState::DispatchCommitted
                | AttemptState::UnknownOutcome
                | AttemptState::Completed
        ) {
            if let Some(response) = self.receipt_sink.load_completed(&ids.attempt_id)? {
                self.validate_completed_replay(request, trusted, &existing, &response)?;
                if existing.state != AttemptState::Completed {
                    self.attempts.transition(
                        &ids.attempt_id,
                        existing.state,
                        AttemptState::Completed,
                        &AttemptTransitionEvidence {
                            revocation_set_digest: existing.revocation_set_digest.clone(),
                            budget_commit_index: existing.budget_commit_index,
                            revocation_commit_index: existing.revocation_commit_index,
                            authority_commit_index: existing.authority_commit_index,
                            leader_epoch: existing.leader_epoch,
                            response_digest: Some(response.evidence.response_body_sha256.clone()),
                        },
                        now_unix_seconds,
                    )?;
                }
                return Ok(response);
            }
            if existing.state == AttemptState::Completed {
                return Err(BrokerError::Storage(
                    "completed broker attempt lacks its durable replay response".to_string(),
                )
                .into());
            }
            if existing.state == AttemptState::DispatchCommitted {
                self.attempts.transition(
                    &ids.attempt_id,
                    AttemptState::DispatchCommitted,
                    AttemptState::UnknownOutcome,
                    &AttemptTransitionEvidence {
                        revocation_set_digest: existing.revocation_set_digest.clone(),
                        budget_commit_index: existing.budget_commit_index,
                        revocation_commit_index: existing.revocation_commit_index,
                        authority_commit_index: existing.authority_commit_index,
                        leader_epoch: existing.leader_epoch,
                        response_digest: existing.response_digest.clone(),
                    },
                    now_unix_seconds,
                )?;
            }
            return Err(BrokerError::AuthorityUnavailable(
                "broker dispatch outcome is unknown and cannot be resent".to_string(),
            )
            .into());
        }

        self.validate_request_core(request, now_unix_seconds)?;

        let revocation_set = {
            let retained = self.retained_prepared_dispatches()?;
            retained.get(&ids.operation_id).and_then(|prepared| {
                (prepared.operation_id == ids.operation_id
                    && prepared.attempt_id == ids.attempt_id
                    && prepared.prepared_dispatch_id == expected_prepared_dispatch_id
                    && prepared.request_canonical_digest == registration.request_canonical_digest)
                    .then(|| prepared.revocation_set.clone())
            })
        };
        let Some(revocation_set) = revocation_set else {
            let unknown_from = match existing.state {
                AttemptState::Registered => {
                    if self
                        .attempts
                        .claim_registered_attempt(&ids.attempt_id, now_unix_seconds)?
                    {
                        Some(AttemptState::Prepared)
                    } else {
                        self.attempts
                            .load_attempt(&ids.attempt_id)?
                            .map(|record| record.state)
                    }
                }
                AttemptState::Prepared
                | AttemptState::Held
                | AttemptState::Captured
                | AttemptState::DispatchCommitted => Some(existing.state),
                _ => None,
            };
            if let Some(state) = unknown_from {
                if state.permits(AttemptState::UnknownOutcome) {
                    let _ = self.attempts.transition(
                        &ids.attempt_id,
                        state,
                        AttemptState::UnknownOutcome,
                        &AttemptTransitionEvidence::default(),
                        now_unix_seconds,
                    );
                }
            }
            return Err(BrokerError::AuthorityUnavailable(
                "kernel dispatch was committed without its retained prepared broker operation"
                    .to_string(),
            )
            .into());
        };

        let capture_request = CaptureExecutionHoldRequest {
            operation_id: ids.operation_id.clone(),
            invocation_id: request.invocation_id.clone(),
            parent_capability_id: request.capability.body.parent_capability_id.clone(),
            broker_capability_id: request.capability.body.capability_id.clone(),
            hold_id: ids.hold_id.clone(),
            capture_event_id: ids.capture_event_id.clone(),
            revocation_ids: revocation_set.ids().to_vec(),
            revocation_set_digest: revocation_set.digest().to_string(),
            authorization_artifact_digest: capability_digest.clone(),
            authority_metadata_digest: trusted.authority_metadata_digest.clone(),
        };
        capture_request.validate()?;
        self.require_migrations_enforced(request)?;
        let commit = match self.budget.capture_execution_hold(&capture_request) {
            Ok(ExecutionHoldState::Captured(commit)) => commit,
            Ok(ExecutionHoldState::Denied | ExecutionHoldState::Reversed) => {
                return Err(BrokerError::AuthorizationDenied(
                    "kernel admission was denied or reversed before dispatch".to_string(),
                )
                .into());
            }
            Ok(ExecutionHoldState::Unknown | ExecutionHoldState::Held) | Err(_) => {
                return Err(BrokerError::AuthorityUnavailable(
                    "kernel admission capture is unavailable or incomplete".to_string(),
                )
                .into());
            }
        };
        commit.validate_for(&capture_request)?;
        let capture_evidence = AttemptTransitionEvidence {
            revocation_set_digest: Some(commit.checked_revocation_set_digest.clone()),
            budget_commit_index: Some(commit.budget_commit_index),
            revocation_commit_index: Some(commit.revocation_commit_index),
            authority_commit_index: Some(commit.authority_commit_index),
            leader_epoch: Some(commit.leader_epoch),
            response_digest: None,
        };
        match existing.state {
            AttemptState::Prepared | AttemptState::Held => {
                self.attempts.transition(
                    &ids.attempt_id,
                    existing.state,
                    AttemptState::Captured,
                    &capture_evidence,
                    now_unix_seconds,
                )?;
            }
            AttemptState::Captured => {
                self.attempts.transition(
                    &ids.attempt_id,
                    AttemptState::Captured,
                    AttemptState::Captured,
                    &capture_evidence,
                    now_unix_seconds,
                )?;
            }
            _ => {
                return Err(BrokerError::Conflict(format!(
                    "prepared broker dispatch cannot resume from {}",
                    existing.state.as_str()
                ))
                .into());
            }
        }
        self.require_migrations_enforced(request)?;
        let dispatch_claim_id = self.next_dispatch_claim_id()?;
        if !self.attempts.claim_captured_attempt(
            &ids.attempt_id,
            &dispatch_claim_id,
            now_unix_seconds,
        )? {
            return Err(BrokerError::Conflict(
                "captured broker attempt is already owned by another execution path".to_string(),
            )
            .into());
        }

        let second_revocation = (|| {
            let observed = self.authority_observation_time(now_unix_seconds)?;
            let snapshot = self
                .revocations
                .check_broker_revocation(&BrokerRevocationRequest {
                    broker_capability_id: request.capability.body.capability_id.clone(),
                    revocation_id: request.capability.body.revocation_id.clone(),
                    now_unix_seconds: observed,
                })?;
            let observed = self.authority_observation_time(observed)?;
            self.validate_request_core(request, observed)?;
            validate_revocation_snapshot(
                &snapshot,
                observed,
                self.config.maximum_revocation_snapshot_age_seconds,
                &trusted.revocation_authority_domain,
            )
        })();
        if let Err(error) = second_revocation {
            let released = self.attempts.release_captured_attempt_claim(
                &ids.attempt_id,
                &dispatch_claim_id,
                now_unix_seconds,
            );
            return Err(execution_failure_after_capture_release(error, released));
        }

        if let Err(error) = self.require_migrations_enforced(request) {
            let released = self.attempts.release_captured_attempt_claim(
                &ids.attempt_id,
                &dispatch_claim_id,
                now_unix_seconds,
            );
            return Err(execution_failure_after_capture_release(error, released));
        }
        let boundary_commit = match self.budget.capture_execution_hold(&capture_request) {
            Ok(ExecutionHoldState::Captured(commit)) => commit,
            Ok(_) | Err(_) => {
                let released = self.attempts.release_captured_attempt_claim(
                    &ids.attempt_id,
                    &dispatch_claim_id,
                    now_unix_seconds,
                );
                return Err(execution_failure_after_capture_release(
                    BrokerError::AuthorityUnavailable(
                        "kernel dispatch commitment is unavailable at the network boundary"
                            .to_string(),
                    ),
                    released,
                ));
            }
        };
        if boundary_commit != commit {
            let released = self.attempts.release_captured_attempt_claim(
                &ids.attempt_id,
                &dispatch_claim_id,
                now_unix_seconds,
            );
            return Err(execution_failure_after_capture_release(
                BrokerError::Invariant(
                    "kernel capture evidence changed before network dispatch".to_string(),
                ),
                released,
            ));
        }
        if let Err(error) = self.require_migrations_enforced(request) {
            let released = self.attempts.release_captured_attempt_claim(
                &ids.attempt_id,
                &dispatch_claim_id,
                now_unix_seconds,
            );
            return Err(execution_failure_after_capture_release(error, released));
        }
        let retained = {
            let mut retained = self.retained_prepared_dispatches()?;
            retained.remove(&ids.operation_id)
        };
        let Some(retained) = retained else {
            let released = self.attempts.release_captured_attempt_claim(
                &ids.attempt_id,
                &dispatch_claim_id,
                now_unix_seconds,
            );
            return Err(execution_failure_after_capture_release(
                BrokerError::AuthorityUnavailable(
                    "retained prepared broker operation disappeared at the network boundary"
                        .to_string(),
                ),
                released,
            ));
        };
        if retained.operation_id != ids.operation_id
            || retained.attempt_id != ids.attempt_id
            || retained.prepared_dispatch_id != expected_prepared_dispatch_id
            || retained.request_canonical_digest != registration.request_canonical_digest
            || retained.revocation_set != revocation_set
        {
            let released = self.attempts.release_captured_attempt_claim(
                &ids.attempt_id,
                &dispatch_claim_id,
                now_unix_seconds,
            );
            return Err(execution_failure_after_capture_release(
                BrokerError::Invariant(
                    "retained prepared broker operation changed before dispatch".to_string(),
                ),
                released,
            ));
        }
        if let Err(error) = self.require_migrations_enforced(request) {
            let released = self.attempts.release_captured_attempt_claim(
                &ids.attempt_id,
                &dispatch_claim_id,
                now_unix_seconds,
            );
            return Err(execution_failure_after_capture_release(error, released));
        }
        let mut commit_started = false;
        let dispatch_commit = (|| {
            // Capture can block on remote authority. Its historical witness
            // cannot authorize dispatch after expiry or parent revocation.
            let authority_now = terminal_clock()?.max(now_unix_seconds);
            let current = self.validate_request_authorities(
                request,
                &trusted.revocation_authority_domain,
                authority_now,
                false,
            )?;
            if current.revocation_set != retained.revocation_set {
                return Err(BrokerError::AuthorizationDenied(
                    "credential ancestry changed after capture".to_string(),
                ));
            }
            self.backend.authorize_dispatch(
                &request.capability.body.credential,
                &retained.credential_version,
                || {
                    let dispatch_now = terminal_clock()?.max(authority_now);
                    self.validate_request_core(request, dispatch_now)?;
                    self.require_migrations_enforced(request)?;
                    commit_started = true;
                    self.attempts.commit_captured_attempt_dispatch(
                        &ids.attempt_id,
                        &dispatch_claim_id,
                        &capture_evidence,
                        dispatch_now,
                    )
                },
            )
        })();
        if let Err(error) = dispatch_commit {
            if !commit_started {
                let released = self.attempts.release_captured_attempt_claim(
                    &ids.attempt_id,
                    &dispatch_claim_id,
                    now_unix_seconds,
                );
                return Err(execution_failure_after_capture_release(error, released));
            }
            let _ = self.attempts.transition(
                &ids.attempt_id,
                AttemptState::Captured,
                AttemptState::UnknownOutcome,
                &capture_evidence,
                now_unix_seconds,
            );
            return Err(error.into());
        }

        let (status, headers, body) = match self.https.dispatch_evidenced(
            retained.dispatch,
            &request.capability.body.constraints,
            &retained.credential,
        ) {
            Ok(response) => response,
            Err(HttpsDispatchFailure::Transport(error)) => {
                let _ = self.attempts.transition(
                    &ids.attempt_id,
                    AttemptState::DispatchCommitted,
                    AttemptState::UnknownOutcome,
                    &capture_evidence,
                    now_unix_seconds,
                );
                return Err(ExecutionFailure::at(
                    error,
                    FailureProjection {
                        stage: BrokerFailureStage::Dispatch,
                        outcome: BrokerFailureOutcome::Unknown,
                        dispatch_knowledge: BrokerDispatchKnowledge::Unknown,
                    },
                ));
            }
            Err(HttpsDispatchFailure::Response(error)) => {
                let _ = self.attempts.transition(
                    &ids.attempt_id,
                    AttemptState::DispatchCommitted,
                    AttemptState::UnknownOutcome,
                    &capture_evidence,
                    now_unix_seconds,
                );
                return Err(ExecutionFailure::at(
                    error,
                    FailureProjection {
                        stage: BrokerFailureStage::Response,
                        outcome: BrokerFailureOutcome::Failed,
                        dispatch_knowledge: BrokerDispatchKnowledge::Committed,
                    },
                ));
            }
        };
        drop(retained.credential);
        let terminal_unix_seconds = terminal_clock()
            .map(|terminal| terminal.max(now_unix_seconds))
            .map_err(|error| {
                ExecutionFailure::at(
                    error,
                    FailureProjection {
                        stage: BrokerFailureStage::Response,
                        outcome: BrokerFailureOutcome::Failed,
                        dispatch_knowledge: BrokerDispatchKnowledge::Committed,
                    },
                )
            })?;
        let (response, response_body_sha256, expected_receipt_reference) =
            (|| -> Result<(BrokerExecuteResponse, String, String)> {
                let response_body_sha256 = response_digest(&body);
                let evidence = BrokerExecutionEvidence {
                    schema: BROKER_EVIDENCE_SCHEMA.to_string(),
                    attempt_id: ids.attempt_id.clone(),
                    invocation_id: request.invocation_id.clone(),
                    hold_id: ids.hold_id.clone(),
                    request_digest,
                    capability_digest,
                    revocation_set_digest: commit.checked_revocation_set_digest,
                    budget_commit_index: commit.budget_commit_index,
                    revocation_commit_index: commit.revocation_commit_index,
                    authority_commit_index: commit.authority_commit_index,
                    leader_epoch: commit.leader_epoch,
                    upstream_status: status,
                    response_body_sha256: response_body_sha256.clone(),
                    response_headers_sha256: crate::generic_https::response_header_digest(&headers)?,
                };
                let receipt_id = format!("broker-receipt-{}", ids.attempt_id);
                let receipt = sign_execution_receipt(
                    BrokerReceiptBody {
                        schema: BROKER_RECEIPT_SCHEMA.to_string(),
                        receipt_id,
                        issued_at_unix_seconds: terminal_unix_seconds,
                        evidence: evidence.clone(),
                        operation_id: ids.operation_id.clone(),
                        authorize_event_id: ids.authorize_event_id.clone(),
                        capture_event_id: ids.capture_event_id.clone(),
                        parent_capability_id: request.capability.body.parent_capability_id.clone(),
                        broker_capability_id: request.capability.body.capability_id.clone(),
                        subject: request.capability.body.subject.clone(),
                        credential_reference_hash: credential_reference_hash(
                            &request.capability.body.credential,
                        )?,
                        credential_version: request.capability.body.credential.version,
                        normalized_destination: request.request.destination.clone(),
                        request_body_sha256: request.proof.body.body_sha256.clone(),
                        caller_headers_sha256: request.proof.body.caller_headers_sha256.clone(),
                        caller_options_sha256: request.proof.body.caller_options_sha256.clone(),
                        quotas: trusted.quotas.clone(),
                        broker_quota_key_id: request.capability.body.broker_quota_key_id.clone(),
                        provider_adapter_id: request.capability.body.provider_adapter_id.clone(),
                        provider_adapter_version: request.capability.body.provider_adapter_version,
                        request_body_bytes: u64::try_from(request.request.body.len()).map_err(
                            |_| {
                                BrokerError::Invariant(
                                    "request body length does not fit u64".to_string(),
                                )
                            },
                        )?,
                        response_body_bytes: u64::try_from(body.len()).map_err(|_| {
                            BrokerError::Invariant(
                                "response body length does not fit u64".to_string(),
                            )
                        })?,
                        source_receipt_ids: trusted.source_receipt_ids.clone(),
                        outcome: BrokerExecutionOutcome::Completed,
                    },
                    self.receipt_signer.as_ref(),
                )?;
                let expected_receipt_reference =
                    format!("broker-receipt-sha256-{}", receipt_digest(&receipt)?);
                Ok((
                    BrokerExecuteResponse {
                        status,
                        headers,
                        body,
                        evidence,
                        receipt_reference: expected_receipt_reference.clone(),
                        receipt,
                    },
                    response_body_sha256,
                    expected_receipt_reference,
                ))
            })()
            .map_err(|error| {
                ExecutionFailure::at(
                    error,
                    FailureProjection {
                        stage: BrokerFailureStage::Response,
                        outcome: BrokerFailureOutcome::Failed,
                        dispatch_knowledge: BrokerDispatchKnowledge::Committed,
                    },
                )
            })?;
        let receipt_reference = match self.receipt_sink.persist_completed(&response) {
            Ok(reference) => reference,
            Err(error) => {
                let _ = self.attempts.transition(
                    &ids.attempt_id,
                    AttemptState::DispatchCommitted,
                    AttemptState::UnknownOutcome,
                    &capture_evidence,
                    terminal_unix_seconds,
                );
                return Err(ExecutionFailure::at(
                    error,
                    FailureProjection {
                        stage: BrokerFailureStage::ReceiptPersistence,
                        outcome: BrokerFailureOutcome::Failed,
                        dispatch_knowledge: BrokerDispatchKnowledge::Committed,
                    },
                ));
            }
        };
        if let Err(error) = validate_identifier(&receipt_reference, "receipt reference", 512) {
            let _ = self.attempts.transition(
                &ids.attempt_id,
                AttemptState::DispatchCommitted,
                AttemptState::UnknownOutcome,
                &capture_evidence,
                terminal_unix_seconds,
            );
            return Err(ExecutionFailure::at(
                error,
                FailureProjection {
                    stage: BrokerFailureStage::ReceiptPersistence,
                    outcome: BrokerFailureOutcome::Failed,
                    dispatch_knowledge: BrokerDispatchKnowledge::Committed,
                },
            ));
        }
        if receipt_reference != expected_receipt_reference {
            let _ = self.attempts.transition(
                &ids.attempt_id,
                AttemptState::DispatchCommitted,
                AttemptState::UnknownOutcome,
                &capture_evidence,
                terminal_unix_seconds,
            );
            return Err(ExecutionFailure::at(
                BrokerError::Invariant(
                    "broker receipt sink returned an unbound receipt reference".to_string(),
                ),
                FailureProjection {
                    stage: BrokerFailureStage::ReceiptPersistence,
                    outcome: BrokerFailureOutcome::Failed,
                    dispatch_knowledge: BrokerDispatchKnowledge::Committed,
                },
            ));
        }
        let completion = AttemptTransitionEvidence {
            response_digest: Some(response_body_sha256),
            ..capture_evidence
        };
        self.attempts.transition(
            &ids.attempt_id,
            AttemptState::DispatchCommitted,
            AttemptState::Completed,
            &completion,
            terminal_unix_seconds,
        )?;
        Ok(response)
    }

    pub(super) fn validate_completed_replay(
        &self,
        request: &BrokerExecuteRequest,
        trusted: &TrustedExecutionContext,
        attempt: &crate::store::AttemptRecord,
        response: &BrokerExecuteResponse,
    ) -> Result<()> {
        response.evidence.validate()?;
        verify_execution_receipt(&response.receipt, &self.receipt_signer.public_key())?;
        let receipt = &response.receipt.body;
        let evidence = &response.evidence;
        let request_digest = broker_request_digest(request)?;
        let capability_digest = capability_digest(&request.capability)?;
        let expected_reference = format!(
            "broker-receipt-sha256-{}",
            receipt_digest(&response.receipt)?
        );
        let request_body_bytes = u64::try_from(request.request.body.len()).map_err(|_| {
            BrokerError::Invariant("request body length does not fit u64".to_string())
        })?;
        let response_body_bytes = u64::try_from(response.body.len()).map_err(|_| {
            BrokerError::Invariant("response body length does not fit u64".to_string())
        })?;
        if response.receipt_reference != expected_reference
            || response.status != evidence.upstream_status
            || evidence.attempt_id != attempt.registration.ids.attempt_id
            || evidence.invocation_id != request.invocation_id
            || evidence.hold_id != attempt.registration.ids.hold_id
            || evidence.request_digest != request_digest
            || evidence.capability_digest != capability_digest
            || evidence.response_body_sha256 != response_digest(&response.body)
            || attempt.revocation_set_digest.as_ref() != Some(&evidence.revocation_set_digest)
            || attempt.budget_commit_index != Some(evidence.budget_commit_index)
            || attempt.revocation_commit_index != Some(evidence.revocation_commit_index)
            || attempt.authority_commit_index != Some(evidence.authority_commit_index)
            || attempt.leader_epoch != Some(evidence.leader_epoch)
            || attempt
                .response_digest
                .as_ref()
                .is_some_and(|digest| digest != &evidence.response_body_sha256)
            || receipt.receipt_id != format!("broker-receipt-{}", evidence.attempt_id)
            || receipt.evidence != *evidence
            || receipt.operation_id != attempt.registration.ids.operation_id
            || receipt.authorize_event_id != attempt.registration.ids.authorize_event_id
            || receipt.capture_event_id != attempt.registration.ids.capture_event_id
            || receipt.parent_capability_id != request.capability.body.parent_capability_id
            || receipt.broker_capability_id != request.capability.body.capability_id
            || receipt.subject != request.capability.body.subject
            || receipt.credential_reference_hash
                != credential_reference_hash(&request.capability.body.credential)?
            || receipt.credential_version != request.capability.body.credential.version
            || receipt.normalized_destination != request.request.destination
            || receipt.request_body_sha256 != request.proof.body.body_sha256
            || receipt.caller_headers_sha256 != request.proof.body.caller_headers_sha256
            || receipt.caller_options_sha256 != request.proof.body.caller_options_sha256
            || receipt.quotas != trusted.quotas
            || receipt.broker_quota_key_id != request.capability.body.broker_quota_key_id
            || receipt.provider_adapter_id != request.capability.body.provider_adapter_id
            || receipt.provider_adapter_version != request.capability.body.provider_adapter_version
            || receipt.request_body_bytes != request_body_bytes
            || receipt.response_body_bytes != response_body_bytes
            || receipt.source_receipt_ids != trusted.source_receipt_ids
            || receipt.outcome != BrokerExecutionOutcome::Completed
        {
            return Err(BrokerError::Storage(
                "durable completed broker response is misbound to its exact attempt".to_string(),
            ));
        }
        Ok(())
    }
}

