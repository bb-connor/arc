pub const MAX_ACTIVE_RESPONSE_LEASE_DURATION_MS: u64 = 60_000;

const DISPATCH_ID_PREFIX: &str = "active_response_dispatch_";

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DurableActiveResponseExecutorConfigError {
    #[error("active-response execution lease duration must be nonzero")]
    ZeroLeaseDuration,
    #[error("active-response execution lease duration {actual_ms} exceeds maximum {maximum_ms}")]
    LeaseDurationTooLong { actual_ms: u64, maximum_ms: u64 },
    #[error("active-response executor authority identifier is invalid")]
    InvalidAuthorityId,
}

pub struct DurableActiveResponseExecutor<
    S: ResponseDispatchStore + ?Sized,
    E: EffectPort + ?Sized,
    R: SecurityReceiptSink + ActiveResponseReceiptProofSource + ?Sized,
    A: SecurityAlertPort + ?Sized,
> {
    identity: ActiveResponseExecutorAuthorityIdentity,
    lease_owner_id: LeaseOwnerId,
    store: Arc<S>,
    effects: Arc<E>,
    receipts: Arc<R>,
    alerts: Arc<A>,
    clock: Arc<dyn SecurityClock>,
    lease_duration_ms: u64,
    response_executor: ResponseExecutor<S, E, R, A>,
}

impl<
        S: ResponseDispatchStore + ?Sized,
        E: EffectPort + ?Sized,
        R: SecurityReceiptSink + ActiveResponseReceiptProofSource + ?Sized,
        A: SecurityAlertPort + ?Sized,
    > DurableActiveResponseExecutor<S, E, R, A>
{
    pub fn new(
        identity: ActiveResponseExecutorAuthorityIdentity,
        lease_owner_id: LeaseOwnerId,
        store: Arc<S>,
        effects: Arc<E>,
        receipts: Arc<R>,
        alerts: Arc<A>,
        clock: Arc<dyn SecurityClock>,
        lease_duration_ms: u64,
    ) -> Result<Self, DurableActiveResponseExecutorConfigError> {
        validate_lease_duration(lease_duration_ms)?;
        if decode_lower_hex_digest(identity.authority_id()).is_none() {
            return Err(DurableActiveResponseExecutorConfigError::InvalidAuthorityId);
        }
        let response_executor = ResponseExecutor::new(
            Arc::clone(&store),
            Arc::clone(&effects),
            Arc::clone(&receipts),
            Arc::clone(&alerts),
        );
        Ok(Self {
            identity,
            lease_owner_id,
            store,
            effects,
            receipts,
            alerts,
            clock,
            lease_duration_ms,
            response_executor,
        })
    }

    pub fn ensure_ready(&self) -> Result<(), ActiveResponseExecutorError> {
        readiness("dispatch store", self.store.ensure_dispatch_ready())?;
        readiness("effect port", self.effects.ensure_effects_ready())?;
        readiness("receipt sink", self.receipts.ensure_receipts_ready())?;
        self.receipts
            .ensure_active_response_receipt_proofs_ready()?;
        readiness("alert port", self.alerts.ensure_alerts_ready())
    }

    #[cfg(test)]
    pub(crate) fn execute_automatic_for_test(
        &self,
        response_plan: ResponsePlan,
        governed_intent_hash: Digest32,
        policy_decision_hash: Digest32,
        authorized_at_unix_ms: u64,
    ) -> Result<ActiveResponseExecutionEvidence, ActiveResponseExecutorError> {
        let authorization_capability_hash =
            hex::encode(response_plan.operator_capability.capability_digest.as_bytes());
        let governed_intent_hash = hex::encode(governed_intent_hash.as_bytes());
        let policy_decision_hash = hex::encode(policy_decision_hash.as_bytes());
        let approval = ActiveResponseExecutionApproval::Automatic;
        let dispatch_id = derive_active_response_dispatch_id(
            &response_plan,
            &self.identity,
            &authorization_capability_hash,
            &governed_intent_hash,
            &policy_decision_hash,
            authorized_at_unix_ms,
            &approval,
        )
        .map_err(|error| {
            ActiveResponseExecutorError::RejectedBeforeCommit(format!(
                "automatic test dispatch identifier is invalid: {error}"
            ))
        })?;
        let request = RawActiveResponseExecutionRequest {
            dispatch_id,
            request_id: response_plan.action_id.as_str().to_string(),
            plan_body_hash: hex::encode(response_plan.plan_hash.as_bytes()),
            authorization_capability_hash,
            governed_intent_hash,
            policy_decision_hash,
            expires_at_unix_ms: response_plan.expires_at_unix_ms,
            authorized_at_unix_ms,
            dispatch_committed_resume: false,
            response_plan,
            executor_authority: self.identity.clone(),
            approval,
        };
        self.execute_source(&request)
    }
}

struct ValidatedExecutionRequest {
    raw: RawActiveResponseExecutionRequest,
    authorization_capability_hash: Digest32,
    governed_intent_hash: Digest32,
    policy_decision_hash: Digest32,
    approval: ResponseDispatchApproval,
}

impl<
        S: ResponseDispatchStore + ?Sized,
        E: EffectPort + ?Sized,
        R: SecurityReceiptSink + ActiveResponseReceiptProofSource + ?Sized,
        A: SecurityAlertPort + ?Sized,
    > DurableActiveResponseExecutor<S, E, R, A>
{
    fn execute_source<Q: ActiveResponseRequestSource + ?Sized>(
        &self,
        source: &Q,
    ) -> Result<ActiveResponseExecutionEvidence, ActiveResponseExecutorError> {
        let request = self.validate_execution_request(source.raw_request())?;
        let key = ResponseDispatchKey {
            tenant_id: request.raw.response_plan.tenant_id.clone(),
            dispatch_id: request.raw.dispatch_id.clone(),
        };

        match self.store.load_dispatch(&key) {
            Ok(ResponseDispatchLoadOutcome::Found(record)) => {
                self.validate_existing_dispatch(&request, &record)?;
                self.drive_loaded_dispatch(&request, &record, true)
            }
            Ok(ResponseDispatchLoadOutcome::Missing) => self.commit_fresh_dispatch(request),
            Err(error) => Err(ActiveResponseExecutorError::OutcomeUnknown(format!(
                "dispatch lookup failed before idempotency could be established: {error}"
            ))),
        }
    }

    fn validate_execution_request(
        &self,
        raw: RawActiveResponseExecutionRequest,
    ) -> Result<ValidatedExecutionRequest, ActiveResponseExecutorError> {
        let reject =
            |reason: &str| ActiveResponseExecutorError::RejectedBeforeCommit(reason.to_string());
        if raw.executor_authority != self.identity
            || raw.request_id != raw.response_plan.action_id.as_str()
            || raw.expires_at_unix_ms != raw.response_plan.expires_at_unix_ms
            || raw.authorized_at_unix_ms < raw.response_plan.created_at_unix_ms
            || raw.authorized_at_unix_ms >= raw.response_plan.expires_at_unix_ms
            || raw
                .response_plan
                .operator_capability
                .executor_subject
                .as_str()
                != self.identity.subject().to_hex()
            || !valid_prefixed_digest_id(raw.dispatch_id.as_str(), DISPATCH_ID_PREFIX)
        {
            return Err(reject("active-response request binding is invalid"));
        }
        let plan_body_hash = decode_lower_hex_digest(&raw.plan_body_hash)
            .ok_or_else(|| reject("response plan hash is not canonical lowercase hex"))?;
        let authorization_capability_hash =
            decode_lower_hex_digest(&raw.authorization_capability_hash).ok_or_else(|| {
                reject("authorization capability hash is not canonical lowercase hex")
            })?;
        let governed_intent_hash = decode_lower_hex_digest(&raw.governed_intent_hash)
            .ok_or_else(|| reject("governed intent hash is not canonical lowercase hex"))?;
        let policy_decision_hash = decode_lower_hex_digest(&raw.policy_decision_hash)
            .ok_or_else(|| reject("policy decision hash is not canonical lowercase hex"))?;
        if plan_body_hash != raw.response_plan.plan_hash
            || authorization_capability_hash
                != raw.response_plan.operator_capability.capability_digest
            || digest_is_zero(&governed_intent_hash)
            || digest_is_zero(&policy_decision_hash)
        {
            return Err(reject("active-response digest binding is invalid"));
        }
        let approval = match (&raw.response_plan.approval_requirement, &raw.approval) {
            (
                ResponseApprovalRequirement::Automatic,
                ActiveResponseExecutionApproval::Automatic,
            ) => ResponseDispatchApproval::Automatic,
            (
                ResponseApprovalRequirement::Governed { .. },
                ActiveResponseExecutionApproval::Governed {
                    admission_operation_id,
                    admission_operation_version,
                    approval_set_hash,
                },
            ) => {
                let admission_operation_id = RecordId::new(admission_operation_id.clone())
                    .map_err(|_| reject("governed admission operation id is invalid"))?;
                let approval_set_hash = decode_lower_hex_digest(approval_set_hash)
                    .filter(|digest| !digest_is_zero(digest))
                    .ok_or_else(|| reject("approval set hash is invalid"))?;
                if *admission_operation_version == 0 {
                    return Err(reject("governed admission operation version is zero"));
                }
                ResponseDispatchApproval::Governed {
                    admission_operation_id,
                    admission_operation_version: *admission_operation_version,
                    approval_set_hash,
                }
            }
            _ => {
                return Err(reject(
                    "active-response approval mode does not match the plan",
                ))
            }
        };
        if raw.dispatch_committed_resume
            && !matches!(&approval, ResponseDispatchApproval::Governed { .. })
        {
            return Err(reject(
                "dispatch-committed resume requires governed approval",
            ));
        }
        let expected_dispatch_id = derive_active_response_dispatch_id(
            &raw.response_plan,
            &raw.executor_authority,
            &raw.authorization_capability_hash,
            &raw.governed_intent_hash,
            &raw.policy_decision_hash,
            raw.authorized_at_unix_ms,
            &raw.approval,
        )
        .map_err(|_| reject("active-response dispatch identifier derivation failed"))?;
        if expected_dispatch_id != raw.dispatch_id {
            return Err(reject(
                "active-response dispatch identifier is not canonical for the request",
            ));
        }

        Ok(ValidatedExecutionRequest {
            raw,
            authorization_capability_hash,
            governed_intent_hash,
            policy_decision_hash,
            approval,
        })
    }

    fn commit_fresh_dispatch(
        &self,
        request: ValidatedExecutionRequest,
    ) -> Result<ActiveResponseExecutionEvidence, ActiveResponseExecutorError> {
        let now_unix_ms = self.execution_time_before_commit()?;
        let resumed_after_expiry = now_unix_ms >= request.raw.response_plan.expires_at_unix_ms;
        if now_unix_ms < request.raw.response_plan.created_at_unix_ms
            || request.raw.authorized_at_unix_ms > now_unix_ms
            || (resumed_after_expiry && !request.raw.dispatch_committed_resume)
        {
            return Err(ActiveResponseExecutorError::RejectedBeforeCommit(
                "active-response plan is not live".to_string(),
            ));
        }
        let lease_base_unix_ms = if resumed_after_expiry {
            request.raw.authorized_at_unix_ms
        } else {
            now_unix_ms
        };
        let lease_expires_at_unix_ms = self
            .lease_expiry(
                lease_base_unix_ms,
                request.raw.response_plan.expires_at_unix_ms,
            )
            .ok_or_else(|| {
                ActiveResponseExecutorError::RejectedBeforeCommit(
                    "active-response execution lease is invalid".to_string(),
                )
            })?;
        let executor_authority_id = RecordId::new(self.identity.authority_id()).map_err(|_| {
            ActiveResponseExecutorError::RejectedBeforeCommit(
                "active-response executor authority id is invalid".to_string(),
            )
        })?;
        let prepared = prepare_response_dispatch(ResponseDispatchPreparationRequest {
            plan: request.raw.response_plan.clone(),
            dispatch_id: request.raw.dispatch_id.clone(),
            authorization_capability_hash: request.authorization_capability_hash,
            governed_intent_hash: request.governed_intent_hash,
            policy_decision_hash: request.policy_decision_hash,
            executor_authority_id,
            executor_authority_generation: self.identity.generation(),
            approval: request.approval.clone(),
            authorized_at_unix_ms: request.raw.authorized_at_unix_ms,
            initial_lease: ResponseDispatchLease {
                lease_owner_id: self.lease_owner_id.clone(),
                lease_expires_at_unix_ms,
            },
            commit_mode: if resumed_after_expiry {
                ResponseDispatchCommitMode::GovernedCommittedExpiredResume
            } else if request.raw.dispatch_committed_resume {
                ResponseDispatchCommitMode::GovernedCommittedResume
            } else {
                ResponseDispatchCommitMode::Fresh
            },
        })
        .map_err(|error| {
            ActiveResponseExecutorError::RejectedBeforeCommit(format!(
                "active-response dispatch preparation failed: {error}"
            ))
        })?;

        match self.store.commit_dispatch(&prepared) {
            Ok(ResponseDispatchCommitOutcome::Committed(record)) => {
                self.drive_committed_dispatch(&request, &record, false)
            }
            Ok(ResponseDispatchCommitOutcome::Existing(record)) => {
                self.validate_existing_dispatch(&request, &record)?;
                self.drive_committed_dispatch(&request, &record, true)
            }
            Err(commit_error) => self.reconcile_commit_error(&request, commit_error),
        }
    }

    fn reconcile_commit_error(
        &self,
        request: &ValidatedExecutionRequest,
        commit_error: chio_security_types::ports::PortError,
    ) -> Result<ActiveResponseExecutionEvidence, ActiveResponseExecutorError> {
        let key = ResponseDispatchKey {
            tenant_id: request.raw.response_plan.tenant_id.clone(),
            dispatch_id: request.raw.dispatch_id.clone(),
        };
        match self.store.load_dispatch(&key) {
            Ok(ResponseDispatchLoadOutcome::Found(record)) => {
                self.validate_existing_dispatch(request, &record)?;
                self.drive_committed_dispatch(
                    request,
                    &record,
                    true,
                )
            }
            Ok(ResponseDispatchLoadOutcome::Missing) => {
                use chio_security_types::ports::PortErrorKind;
                match commit_error.kind() {
                    PortErrorKind::Conflict | PortErrorKind::InvalidData => {
                        Err(ActiveResponseExecutorError::RejectedBeforeCommit(format!(
                            "active-response dispatch commit rejected: {commit_error}"
                        )))
                    }
                    PortErrorKind::Unavailable | PortErrorKind::IntegrityFailure => {
                        Err(ActiveResponseExecutorError::OutcomeUnknown(format!(
                            "active-response dispatch commit outcome is uncertain: {commit_error}"
                        )))
                    }
                }
            }
            Err(load_error) => Err(ActiveResponseExecutorError::OutcomeUnknown(format!(
                "active-response dispatch commit failed and recovery lookup failed: {commit_error}; {load_error}"
            ))),
        }
    }

    fn validate_existing_dispatch(
        &self,
        request: &ValidatedExecutionRequest,
        record: &ResponseDispatchRecord,
    ) -> Result<(), ActiveResponseExecutorError> {
        let body = &record.authorization.body;
        let snapshot = decode_response_record(&record.response_plan).map_err(|error| {
            ActiveResponseExecutorError::OutcomeUnknown(format!(
                "stored response dispatch is invalid: {error}"
            ))
        })?;
        self.response_executor
            .validate_dispatch_authorization(&record.response_plan, &record.authorization)
            .map_err(|error| {
                ActiveResponseExecutorError::OutcomeUnknown(format!(
                    "stored response dispatch authorization is invalid: {error}"
                ))
            })?;
        let exact = body.key.tenant_id == request.raw.response_plan.tenant_id
            && body.key.dispatch_id == request.raw.dispatch_id
            && body.action_id == request.raw.response_plan.action_id
            && body.plan_hash == request.raw.response_plan.plan_hash
            && body.authorization_capability_hash == request.authorization_capability_hash
            && body.governed_intent_hash == request.governed_intent_hash
            && body.policy_decision_hash == request.policy_decision_hash
            && body.executor_authority_id.as_str() == self.identity.authority_id()
            && body.executor_authority_generation == self.identity.generation()
            && body.approval == request.approval
            && body.authorized_at_unix_ms == request.raw.authorized_at_unix_ms
            && snapshot.execution_dispatch.as_ref().is_some_and(|binding| {
                binding.schema_version == body.schema_version
                    && binding.tenant_id == body.key.tenant_id
                    && binding.dispatch_id == body.key.dispatch_id
                    && binding.action_id == body.action_id
                    && binding.plan_hash == body.plan_hash
                    && binding.executor_authority_id == body.executor_authority_id
                    && binding.executor_authority_generation == body.executor_authority_generation
                    && binding.authorization_capability_hash == body.authorization_capability_hash
                    && binding.governed_intent_hash == body.governed_intent_hash
                    && binding.policy_decision_hash == body.policy_decision_hash
                    && binding.approval == body.approval
                    && binding.authorized_at_unix_ms == body.authorized_at_unix_ms
            })
            && snapshot.plan == request.raw.response_plan
            && record.initial_work.tenant_id == request.raw.response_plan.tenant_id
            && record.initial_work.action_id == request.raw.response_plan.action_id
            && record.initial_work.fencing_token > 0
            && record.initial_work.lease_expires_at_unix_ms
                <= request.raw.response_plan.expires_at_unix_ms;
        if exact {
            Ok(())
        } else {
            Err(ActiveResponseExecutorError::RejectedBeforeCommit(
                "dispatch id is already bound to a different active-response command".to_string(),
            ))
        }
    }

    fn drive_dispatch(
        &self,
        request: &ValidatedExecutionRequest,
        dispatch: &ResponseDispatchRecord,
        recovered: bool,
    ) -> Result<ActiveResponseExecutionEvidence, ActiveResponseExecutorError> {
        let now_unix_ms = self.execution_time_after_commit()?;
        let key = ResponsePlanKey {
            tenant_id: request.raw.response_plan.tenant_id.clone(),
            action_id: request.raw.response_plan.action_id.clone(),
        };
        let current = self.store.load_plan(&key).map_err(|error| {
            ActiveResponseExecutorError::OutcomeUnknown(format!(
                "active-response plan lookup failed after dispatch commitment: {error}"
            ))
        })?;
        let current = current.ok_or_else(|| {
            ActiveResponseExecutorError::OutcomeUnknown(
                "active-response plan is missing after dispatch commitment".to_string(),
            )
        })?;
        let snapshot = decode_response_record(&current).map_err(|error| {
            ActiveResponseExecutorError::OutcomeUnknown(format!(
                "active-response plan is invalid after dispatch commitment: {error}"
            ))
        })?;
        if snapshot.plan != request.raw.response_plan {
            return Err(ActiveResponseExecutorError::OutcomeUnknown(
                "active-response plan changed after dispatch commitment".to_string(),
            ));
        }
        if has_durable_execution_proof(&snapshot) {
            return self.map_active_evidence(request, dispatch, &current, recovered);
        }
        if snapshot.state != ResponseState::Applying {
            return Err(ActiveResponseExecutorError::OutcomeUnknown(format!(
                "committed active response is durably {:?}, not active",
                snapshot.state
            )));
        }

        let work = if recovered {
            self.recover_work(request, dispatch, &current, now_unix_ms)?
        } else {
            dispatch.initial_work.clone()
        };
        self.validate_execution_work(&work)?;
        let completed = self
            .response_executor
            .execute(&current, &work, now_unix_ms)
            .map_err(|error| {
                ActiveResponseExecutorError::OutcomeUnknown(format!(
                    "active-response execution did not produce a durable acknowledgement: {error}"
                ))
            })?;
        let completed_snapshot = decode_response_record(&completed).map_err(|error| {
            ActiveResponseExecutorError::OutcomeUnknown(format!(
                "completed active-response record is invalid: {error}"
            ))
        })?;
        if !has_durable_execution_proof(&completed_snapshot) {
            return Err(ActiveResponseExecutorError::OutcomeUnknown(format!(
                "committed active response completed in {:?}",
                completed_snapshot.state
            )));
        }
        self.map_active_evidence(request, dispatch, &completed, recovered)
    }

    fn recover_work(
        &self,
        request: &ValidatedExecutionRequest,
        dispatch: &ResponseDispatchRecord,
        current: &ResponsePlanRecord,
        now_unix_ms: u64,
    ) -> Result<ScheduledWork, ActiveResponseExecutorError> {
        let lease_expires_at_unix_ms = self
            .lease_expiry(now_unix_ms, request.raw.response_plan.expires_at_unix_ms)
            .ok_or_else(|| {
                ActiveResponseExecutorError::OutcomeUnknown(
                    "active-response recovery lease cannot be acquired before expiry".to_string(),
                )
            })?;
        self.recover_work_with_expiry(
            request,
            dispatch,
            current,
            now_unix_ms,
            lease_expires_at_unix_ms,
        )
    }

    fn recover_expired_work(
        &self,
        request: &ValidatedExecutionRequest,
        dispatch: &ResponseDispatchRecord,
        current: &ResponsePlanRecord,
        now_unix_ms: u64,
    ) -> Result<ScheduledWork, ActiveResponseExecutorError> {
        let lease_expires_at_unix_ms = now_unix_ms
            .checked_add(self.lease_duration_ms)
            .ok_or_else(|| {
                ActiveResponseExecutorError::OutcomeUnknown(
                    "expired active-response recovery lease overflowed".to_string(),
                )
            })?;
        self.recover_work_with_expiry(
            request,
            dispatch,
            current,
            now_unix_ms,
            lease_expires_at_unix_ms,
        )
    }

    fn recover_work_with_expiry(
        &self,
        request: &ValidatedExecutionRequest,
        dispatch: &ResponseDispatchRecord,
        current: &ResponsePlanRecord,
        now_unix_ms: u64,
        lease_expires_at_unix_ms: u64,
    ) -> Result<ScheduledWork, ActiveResponseExecutorError> {
        let recovery_id = recovery_id(
            &request.raw.dispatch_id,
            current,
            now_unix_ms,
            lease_expires_at_unix_ms,
        )?;
        let work_key = SchedulerWorkKey {
            tenant_id: request.raw.response_plan.tenant_id.clone(),
            action_id: request.raw.response_plan.action_id.clone(),
        };
        let expected_fencing_token = self
            .store
            .load_dispatch_work(&work_key)
            .map_err(|error| {
                ActiveResponseExecutorError::OutcomeUnknown(format!(
                    "active-response recovery fence lookup failed: {error}"
                ))
            })?
            .map_or(dispatch.initial_work.fencing_token, |work| work.fencing_token);
        let outcome = self
            .store
            .recover_dispatch_work(&ResponseDispatchRecoveryRequest {
                key: dispatch.authorization.body.key.clone(),
                action_id: request.raw.response_plan.action_id.clone(),
                recovery_id,
                lease_owner_id: self.lease_owner_id.clone(),
                expected_fencing_token: Some(expected_fencing_token),
                now_unix_ms,
                lease_expires_at_unix_ms,
            })
            .map_err(|error| {
                ActiveResponseExecutorError::OutcomeUnknown(format!(
                    "active-response scheduler recovery failed: {error}"
                ))
            })?;
        let work = match outcome {
            ResponseDispatchRecoveryOutcome::LiveLease(work)
            | ResponseDispatchRecoveryOutcome::Takeover(work) => work,
        };
        self.validate_execution_work(&work)?;
        Ok(work)
    }

    fn validate_execution_work(
        &self,
        work: &ScheduledWork,
    ) -> Result<(), ActiveResponseExecutorError> {
        if work.lease_owner_id != self.lease_owner_id || work.fencing_token == 0 {
            return Err(ActiveResponseExecutorError::OutcomeUnknown(
                "active-response execution lease is not owned by this worker".to_string(),
            ));
        }
        self.store
            .validate_lease_identity(
                &work.tenant_id,
                &work.action_id,
                &self.lease_owner_id,
                work.fencing_token,
            )
            .map_err(|error| {
                ActiveResponseExecutorError::OutcomeUnknown(format!(
                    "active-response execution lease binding is no longer current: {error}"
                ))
            })
    }

    fn map_active_evidence(
        &self,
        request: &ValidatedExecutionRequest,
        dispatch: &ResponseDispatchRecord,
        current: &ResponsePlanRecord,
        recovered: bool,
    ) -> Result<ActiveResponseExecutionEvidence, ActiveResponseExecutorError> {
        let evidence = self
            .response_executor
            .dispatch_bound_execution_evidence(current, &dispatch.authorization)
            .map_err(|error| {
                ActiveResponseExecutorError::OutcomeUnknown(format!(
                    "active-response evidence reconstruction failed: {error}"
                ))
            })?;
        let signed_evidence_id = self
            .receipts
            .sign_and_append(&evidence.completion_receipt_request)
            .map_err(|error| {
                ActiveResponseExecutorError::OutcomeUnknown(format!(
                    "dispatch-bound active-response completion proof persistence failed: {error}"
                ))
            })?;
        if signed_evidence_id != evidence.completion_evidence_id {
            return Err(ActiveResponseExecutorError::OutcomeUnknown(
                "dispatch-bound completion proof returned a different evidence ID".to_string(),
            ));
        }
        let completion_receipt = self
            .receipts
            .load_signed_active_response_receipt(&evidence.completion_evidence_id)?
            .ok_or_else(|| {
                ActiveResponseExecutorError::OutcomeUnknown(
                    "signed active-response completion receipt is missing".to_string(),
                )
            })?;
        let effects = evidence
            .effects
            .into_iter()
            .map(|effect| {
                ActiveResponseEffectEvidence::new(
                    effect.effect_id,
                    effect.transition_id,
                    effect.generation,
                    effect.resulting_version_hash,
                )
            })
            .collect();
        let failure = evidence.failure.as_ref().map(|failure| {
            ActiveResponseFailureEvidence::new(
                failure.error_code().clone(),
                failure.failed_effect().map(|effect| {
                    ActiveResponseFailedEffectEvidence::new(
                        effect.effect_id().clone(),
                        effect.transition_id().clone(),
                        effect.generation(),
                    )
                }),
            )
        });
        Ok(ActiveResponseExecutionEvidence::new(
            ActiveResponseExecutionEvidenceParts {
                outcome: match evidence.outcome {
                    DurableActiveResponseOutcome::Activated => {
                        ActiveResponseExecutionOutcome::Activated
                    }
                    DurableActiveResponseOutcome::FailedBeforeAnyEffect => {
                        ActiveResponseExecutionOutcome::FailedBeforeAnyEffect
                    }
                    DurableActiveResponseOutcome::RolledBackAfterPartial => {
                        ActiveResponseExecutionOutcome::RolledBackAfterPartial
                    }
                },
                dispatch_id: request.raw.dispatch_id.clone(),
                tenant_id: evidence.tenant_id,
                action_id: evidence.action_id,
                plan_hash: evidence.plan_hash,
                executor_authority_generation: self.identity.generation(),
                response_generation: evidence.response_generation,
                response_transition_id: evidence.response_transition_id,
                response_body_hash: evidence.response_body_hash,
                response_record: evidence.response_record,
                dispatch_authorization: dispatch.authorization.clone(),
                proof_evidence_id: evidence.completion_evidence_id,
                proof_body_hash: evidence.completion_body_hash,
                completion_receipt,
                effects,
                failure,
                recovered,
            },
        ))
    }

    fn execution_time_before_commit(&self) -> Result<u64, ActiveResponseExecutorError> {
        self.clock.now_unix_ms().map_err(|error| {
            ActiveResponseExecutorError::RejectedBeforeCommit(format!(
                "active-response clock is unavailable: {error}"
            ))
        })
    }

    fn validate_automatic_dispatch_fence_request(
        &self,
        response_plan: &ResponsePlan,
        binding: &PreparedActiveResponseDispatchBinding,
    ) -> Result<(), ActiveResponseExecutorError> {
        let reject =
            |reason: &str| ActiveResponseExecutorError::RejectedBeforeCommit(reason.to_string());
        binding
            .validate_for_plan(response_plan)
            .map_err(|_| reject("automatic active-response dispatch fence binding is invalid"))?;
        if !matches!(
            &response_plan.approval_requirement,
            ResponseApprovalRequirement::Automatic
        ) || !matches!(&binding.approval, ResponseDispatchApproval::Automatic)
            || binding.executor_authority_id.as_str() != self.identity.authority_id()
            || binding.executor_authority_generation != self.identity.generation()
            || response_plan.operator_capability.executor_subject.as_str()
                != self.identity.subject().to_hex()
            || !valid_prefixed_digest_id(binding.dispatch_id.as_str(), DISPATCH_ID_PREFIX)
        {
            return Err(reject(
                "automatic active-response dispatch fence authority binding is invalid",
            ));
        }
        let expected_dispatch_id = derive_active_response_dispatch_id(
            response_plan,
            &self.identity,
            &hex::encode(binding.authorization_capability_hash.as_bytes()),
            &hex::encode(binding.governed_intent_hash.as_bytes()),
            &hex::encode(binding.policy_decision_hash.as_bytes()),
            binding.authorized_at_unix_ms,
            &ActiveResponseExecutionApproval::Automatic,
        )
        .map_err(|_| reject("automatic active-response dispatch fence id derivation failed"))?;
        if expected_dispatch_id != binding.dispatch_id {
            return Err(reject(
                "automatic active-response dispatch fence id is not canonical for the binding",
            ));
        }
        Ok(())
    }

    fn validate_committed_fence_outcome(
        &self,
        response_plan: &ResponsePlan,
        binding: &PreparedActiveResponseDispatchBinding,
        record: &ResponseDispatchRecord,
    ) -> Result<(), ActiveResponseExecutorError> {
        let snapshot = decode_response_record(&record.response_plan).map_err(|error| {
            ActiveResponseExecutorError::OutcomeUnknown(format!(
                "committed automatic dispatch fence record is invalid: {error}"
            ))
        })?;
        let committed_binding = prepared_binding_from_dispatch_record(record);
        if &snapshot.plan != response_plan || &committed_binding != binding {
            return Err(ActiveResponseExecutorError::OutcomeUnknown(
                "committed automatic dispatch fence record does not match the request".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_fenced_fence_outcome(
        &self,
        binding: &PreparedActiveResponseDispatchBinding,
        record: &chio_security_types::ports::AutomaticResponseDispatchFenceRecord,
    ) -> Result<(), ActiveResponseExecutorError> {
        let canonical = chio_core::canonical_json_bytes(binding).map_err(|error| {
            ActiveResponseExecutorError::OutcomeUnknown(format!(
                "automatic dispatch fence binding canonicalization failed: {error}"
            ))
        })?;
        let expected_hash = Digest32::new(*chio_core::sha256(&canonical).as_bytes());
        if &record.prepared_dispatch_binding != binding
            || record.binding_hash != expected_hash
            || record.fenced_at_unix_ms == 0
        {
            return Err(ActiveResponseExecutorError::OutcomeUnknown(
                "automatic dispatch fence record does not match the request".to_string(),
            ));
        }
        Ok(())
    }

    fn execution_time_after_commit(&self) -> Result<u64, ActiveResponseExecutorError> {
        self.clock.now_unix_ms().map_err(|error| {
            ActiveResponseExecutorError::OutcomeUnknown(format!(
                "active-response clock is unavailable after dispatch commitment: {error}"
            ))
        })
    }

    fn lease_expiry(&self, now_unix_ms: u64, plan_expiry_unix_ms: u64) -> Option<u64> {
        let requested = now_unix_ms.checked_add(self.lease_duration_ms)?;
        let expires_at = requested.min(plan_expiry_unix_ms);
        (expires_at > now_unix_ms).then_some(expires_at)
    }
}

impl<
        S: ResponseDispatchStore + ?Sized,
        E: EffectPort + ?Sized,
        R: SecurityReceiptSink + ActiveResponseReceiptProofSource + ?Sized,
        A: SecurityAlertPort + ?Sized,
    > ActiveResponseExecutorAuthority for DurableActiveResponseExecutor<S, E, R, A>
{
    fn identity(&self) -> ActiveResponseExecutorAuthorityIdentity {
        self.identity.clone()
    }

    fn ensure_ready(&self) -> Result<(), ActiveResponseExecutorError> {
        DurableActiveResponseExecutor::ensure_ready(self)
    }

    fn load_committed_active_response_dispatch(
        &self,
        tenant_id: &chio_security_types::ports::TenantId,
        dispatch_id: &RecordId,
    ) -> Result<Option<ActiveResponseCommittedDispatch>, ActiveResponseExecutorError> {
        committed_readback::load_committed_active_response_dispatch(
            self.store.as_ref(),
            &self.identity,
            tenant_id,
            dispatch_id,
        )
    }

    fn fence_uncommitted_automatic_dispatch(
        &self,
        response_plan: &ResponsePlan,
        binding: &PreparedActiveResponseDispatchBinding,
    ) -> Result<AutomaticActiveResponseDispatchFenceOutcome, ActiveResponseExecutorError> {
        self.validate_automatic_dispatch_fence_request(response_plan, binding)?;
        let request = AutomaticResponseDispatchFenceRequest {
            response_plan: response_plan.clone(),
            prepared_dispatch_binding: binding.clone(),
        };
        match self.store.fence_uncommitted_automatic_dispatch(&request) {
            Ok(
                AutomaticResponseDispatchFenceOutcome::Fenced(record)
                | AutomaticResponseDispatchFenceOutcome::ExistingFence(record),
            ) => {
                self.validate_fenced_fence_outcome(binding, &record)?;
                Ok(AutomaticActiveResponseDispatchFenceOutcome::Fenced)
            }
            Ok(AutomaticResponseDispatchFenceOutcome::Committed(record)) => {
                self.validate_committed_fence_outcome(response_plan, binding, &record)?;
                Ok(AutomaticActiveResponseDispatchFenceOutcome::DispatchCommitted)
            }
            Err(error) => match error.kind() {
                PortErrorKind::Conflict | PortErrorKind::InvalidData => {
                    Err(ActiveResponseExecutorError::RejectedBeforeCommit(format!(
                        "automatic active-response dispatch fence rejected: {error}"
                    )))
                }
                PortErrorKind::Unavailable | PortErrorKind::IntegrityFailure => {
                    Err(ActiveResponseExecutorError::OutcomeUnknown(format!(
                        "automatic active-response dispatch fence outcome is uncertain: {error}"
                    )))
                }
            },
        }
    }

    fn execute_active_response(
        &self,
        request: &ActiveResponseExecutionRequest,
    ) -> Result<ActiveResponseExecutionEvidence, ActiveResponseExecutorError> {
        self.execute_source(request)
    }
}

fn prepared_binding_from_dispatch_record(
    record: &ResponseDispatchRecord,
) -> PreparedActiveResponseDispatchBinding {
    let authorization = &record.authorization.body;
    PreparedActiveResponseDispatchBinding {
        schema_version: PREPARED_ACTIVE_RESPONSE_DISPATCH_BINDING_SCHEMA_VERSION,
        tenant_id: authorization.key.tenant_id.clone(),
        action_id: authorization.action_id.clone(),
        plan_hash: authorization.plan_hash,
        dispatch_id: authorization.key.dispatch_id.clone(),
        executor_authority_id: authorization.executor_authority_id.clone(),
        executor_authority_generation: authorization.executor_authority_generation,
        authorized_at_unix_ms: authorization.authorized_at_unix_ms,
        authorization_capability_hash: authorization.authorization_capability_hash,
        governed_intent_hash: authorization.governed_intent_hash,
        policy_decision_hash: authorization.policy_decision_hash,
        approval: authorization.approval.clone(),
    }
}
