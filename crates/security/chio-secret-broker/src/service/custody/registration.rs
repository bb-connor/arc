use super::super::{
    prepared_dispatch_id, AttemptRegistration, AttemptState, AttemptTransitionEvidence,
    BrokerError, BrokerExecuteRequest, BrokerService, PrepareDispatchAcknowledgement,
    RegisterAttemptAcknowledgement, RegisterAttemptOutcome, ReleaseAttemptAcknowledgement, Result,
    MAX_RETAINED_PREPARED_DISPATCHES,
};
use super::RetainedPreparedDispatch;

impl BrokerService {
    /// Persist and fsync a kernel-authorized attempt before any budget
    /// authority mutation or credential materialization.
    pub fn register_attempt(
        &self,
        registration: &AttemptRegistration,
        request: &BrokerExecuteRequest,
        now_unix_seconds: u64,
    ) -> Result<RegisterAttemptAcknowledgement> {
        let _operation_guard = self.attempt_operation_guard_for_request(request)?;
        self.budget.capabilities().require_production()?;
        if let Some(failure) = self.replay_failure_locked(request, now_unix_seconds)? {
            return Err(BrokerError::AuthorizationDenied(failure.diagnostic_code));
        }
        if let Some(existing) = self.attempts.load_attempt(&registration.ids.attempt_id)? {
            if existing.registration != *registration {
                return Err(BrokerError::Conflict(
                    "register-attempt differs from its durable registration".to_string(),
                ));
            }
            if existing.state != AttemptState::Registered {
                return Err(BrokerError::AuthorizationDenied(
                    "broker attempt is no longer registerable".to_string(),
                ));
            }
        }
        let _ =
            self.validate_authenticated_registration(registration, request, now_unix_seconds)?;
        self.require_migrations_enforced(request)?;
        let outcome = self
            .attempts
            .register_intent(registration, now_unix_seconds)?;
        let registered_state = match &outcome {
            RegisterAttemptOutcome::Inserted(record)
            | RegisterAttemptOutcome::ExactRetry(record) => record.state,
        };
        if registered_state != AttemptState::Registered {
            return Err(BrokerError::AuthorizationDenied(
                "broker attempt was durably tombstoned before registration completed".to_string(),
            ));
        }
        RegisterAttemptAcknowledgement::from_outcome(outcome, now_unix_seconds)
    }

    /// Revalidate authority state, materialize the credential, resolve and pin
    /// DNS, and retain the exact outbound operation before kernel capture.
    pub fn prepare_dispatch(
        &self,
        registration: &AttemptRegistration,
        request: &BrokerExecuteRequest,
        now_unix_seconds: u64,
    ) -> Result<PrepareDispatchAcknowledgement> {
        let _operation_guard = self.attempt_operation_guard_for_request(request)?;
        self.budget.capabilities().require_production()?;
        if let Some(failure) = self.replay_failure_locked(request, now_unix_seconds)? {
            return Err(BrokerError::AuthorizationDenied(failure.diagnostic_code));
        }
        registration.validate()?;
        let expected = Self::expected_registration(request, registration)?;
        if expected != *registration {
            return Err(BrokerError::AuthorizationDenied(
                "authenticated registration does not match the canonical broker execute request"
                    .to_string(),
            ));
        }
        let expected_prepared_dispatch_id = prepared_dispatch_id(registration, request)?;
        let existing = self
            .attempts
            .load_attempt(&registration.ids.attempt_id)?
            .ok_or_else(|| {
                BrokerError::AuthorizationDenied(
                    "prepare-dispatch has no authenticated registered attempt".to_string(),
                )
            })?;
        if existing.registration != *registration {
            return Err(BrokerError::Conflict(
                "prepare-dispatch differs from its authenticated registration".to_string(),
            ));
        }
        if !matches!(
            existing.state,
            AttemptState::Registered | AttemptState::Prepared
        ) {
            return Err(BrokerError::Conflict(format!(
                "broker attempt cannot prepare from {}",
                existing.state.as_str()
            )));
        }
        let revocation_set = self
            .validate_request_authorities(
                request,
                &registration.revocation_authority_domain,
                now_unix_seconds,
                true,
            )?
            .into_revocation_set();

        let mut retained = self.retained_prepared_dispatches()?;
        if let Some(prepared) = retained.get(&registration.ids.operation_id) {
            if prepared.operation_id != registration.ids.operation_id
                || prepared.attempt_id != registration.ids.attempt_id
                || prepared.prepared_dispatch_id != expected_prepared_dispatch_id
                || prepared.request_canonical_digest != registration.request_canonical_digest
            {
                return Err(BrokerError::Conflict(
                    "kernel operation ID was reused for a different prepared dispatch".to_string(),
                ));
            }
            return PrepareDispatchAcknowledgement::new(
                registration,
                request,
                prepared.prepared_at_unix_seconds,
            );
        }
        if retained.len() >= MAX_RETAINED_PREPARED_DISPATCHES {
            return Err(BrokerError::AuthorityUnavailable(
                "retained prepared-dispatch capacity is exhausted".to_string(),
            ));
        }

        self.require_migrations_enforced(request)?;
        let (credential, credential_version) = self
            .backend
            .materialize_for_dispatch(&request.capability.body.credential)?;
        let dispatch = self.https.prepare(
            self.provider.as_ref(),
            &request.request,
            &request.capability.body.constraints,
            &credential,
        )?;
        self.require_migrations_enforced(request)?;
        if existing.state == AttemptState::Registered
            && !self
                .attempts
                .claim_registered_attempt(&registration.ids.attempt_id, now_unix_seconds)?
        {
            let raced = self
                .attempts
                .load_attempt(&registration.ids.attempt_id)?
                .ok_or_else(|| {
                    BrokerError::Conflict(
                        "registered attempt disappeared during preparation".to_string(),
                    )
                })?;
            if raced.registration != *registration || raced.state != AttemptState::Prepared {
                return Err(BrokerError::Conflict(
                    "registered attempt was claimed by a different preparation".to_string(),
                ));
            }
        }
        retained.insert(
            registration.ids.operation_id.clone(),
            RetainedPreparedDispatch {
                operation_id: registration.ids.operation_id.clone(),
                attempt_id: registration.ids.attempt_id.clone(),
                prepared_dispatch_id: expected_prepared_dispatch_id,
                request_canonical_digest: registration.request_canonical_digest.clone(),
                prepared_at_unix_seconds: now_unix_seconds,
                dispatch,
                credential,
                credential_version,
                revocation_set,
            },
        );
        PrepareDispatchAcknowledgement::new(registration, request, now_unix_seconds)
    }

    /// Tombstone a registered attempt only while it remains pre-budget and
    /// pre-dispatch. Later states require normal authority reconciliation.
    pub fn release_attempt(
        &self,
        registration: &AttemptRegistration,
        request: &BrokerExecuteRequest,
        now_unix_seconds: u64,
    ) -> Result<ReleaseAttemptAcknowledgement> {
        let _operation_guard = self.attempt_operation_guard_for_request(request)?;
        registration.validate()?;
        let expected = Self::expected_registration(request, registration)?;
        if expected != *registration {
            return Err(BrokerError::AuthorizationDenied(
                "release target does not match the canonical broker execute request".to_string(),
            ));
        }
        let existing = match self.attempts.load_attempt(&registration.ids.attempt_id)? {
            Some(existing) => existing,
            None => match self
                .attempts
                .register_intent(registration, now_unix_seconds)?
            {
                RegisterAttemptOutcome::Inserted(record)
                | RegisterAttemptOutcome::ExactRetry(record) => record,
            },
        };
        if existing.registration != *registration {
            return Err(BrokerError::Conflict(
                "release target differs from its registered attempt".to_string(),
            ));
        }
        let tombstone = match existing.state {
            AttemptState::Registered | AttemptState::Prepared => self.attempts.transition(
                &registration.ids.attempt_id,
                existing.state,
                AttemptState::Failed,
                &AttemptTransitionEvidence::default(),
                now_unix_seconds,
            )?,
            AttemptState::Failed => existing,
            _ => {
                return Err(BrokerError::Conflict(
                    "release target is no longer a pre-capture broker attempt".to_string(),
                ));
            }
        };
        // Only the pre-capture release winner may discard retained dispatch
        // material. A stale compensation request that observes Captured or a
        // later state must be a complete no-op against the dispatch owner.
        self.retained_prepared_dispatches()?
            .remove(&registration.ids.operation_id);
        ReleaseAttemptAcknowledgement::new(registration, tombstone.updated_at_unix_seconds)
    }
}
