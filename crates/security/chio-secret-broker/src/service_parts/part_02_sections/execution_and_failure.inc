impl BrokerService {
    fn execute_inner(
        &self,
        request: &BrokerExecuteRequest,
        trusted: &TrustedExecutionContext,
        now_unix_seconds: u64,
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

        let revocation_request = BrokerRevocationRequest {
            broker_capability_id: request.capability.body.capability_id.clone(),
            revocation_id: request.capability.body.revocation_id.clone(),
            now_unix_seconds,
        };
        let second_revocation = self
            .revocations
            .check_broker_revocation(&revocation_request);
        if let Err(error) = second_revocation.and_then(|snapshot| {
            validate_revocation_snapshot(
                &snapshot,
                now_unix_seconds,
                self.config.maximum_revocation_snapshot_age_seconds,
                &trusted.revocation_authority_domain,
            )
        }) {
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
        if let Err(error) = self.attempts.commit_captured_attempt_dispatch(
            &ids.attempt_id,
            &dispatch_claim_id,
            &capture_evidence,
            now_unix_seconds,
        ) {
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
                };
                let receipt_id = format!("broker-receipt-{}", ids.attempt_id);
                let receipt = sign_execution_receipt(
                    BrokerReceiptBody {
                        schema: BROKER_RECEIPT_SCHEMA.to_string(),
                        receipt_id,
                        issued_at_unix_seconds: now_unix_seconds,
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
                    now_unix_seconds,
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
                now_unix_seconds,
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
                now_unix_seconds,
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
            now_unix_seconds,
        )?;
        Ok(response)
    }

    fn validate_completed_replay(
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

    fn persist_failure_for_origin(
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
        self.retained_prepared_dispatches()?
            .remove(&attempt.registration.ids.operation_id);
        Ok(())
    }
}
