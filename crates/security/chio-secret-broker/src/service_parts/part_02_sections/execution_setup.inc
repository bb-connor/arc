impl BrokerService {
    pub(crate) fn new_production(
        config: BrokerServiceConfig,
        attempts: ProductionSqliteAttemptStore,
        authorities: BrokerServiceAuthorityBundle,
    ) -> Result<Self> {
        Self::from_authorities(config, attempts.into_attempt_store()?, authorities)
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(
        config: BrokerServiceConfig,
        attempts: Arc<dyn AttemptStore>,
        authorities: BrokerServiceAuthorityBundle,
    ) -> Result<Self> {
        Self::from_authorities(config, attempts, authorities)
    }

    fn from_authorities(
        config: BrokerServiceConfig,
        attempts: Arc<dyn AttemptStore>,
        authorities: BrokerServiceAuthorityBundle,
    ) -> Result<Self> {
        config.validate()?;
        authorities.validate_for_production()?;
        let BrokerServiceAuthorityBundle {
            trusted_issuer,
            backend,
            provider,
            https,
            budget,
            liveness,
            revocations,
            receipt_sink,
            receipt_signer,
            migration_enforcer,
        } = authorities;
        Ok(Self {
            config,
            trusted_issuer,
            backend,
            provider,
            https,
            attempts,
            budget,
            liveness,
            revocations,
            receipt_sink,
            receipt_signer,
            migration_enforcer,
            attempt_operation_gates: std::array::from_fn(|_| Mutex::new(())),
            retained_prepared_dispatches: Mutex::new(BTreeMap::new()),
            dispatch_claim_counter: AtomicU64::new(0),
        })
    }

    fn retained_prepared_dispatches(
        &self,
    ) -> Result<MutexGuard<'_, BTreeMap<String, RetainedPreparedDispatch>>> {
        self.retained_prepared_dispatches.lock().map_err(|_| {
            BrokerError::Invariant("retained prepared-dispatch lock is poisoned".to_string())
        })
    }

    fn attempt_operation_guard_for_digest(&self, digest: &str) -> Result<MutexGuard<'_, ()>> {
        let gate_index = attempt_operation_gate_index(digest)?;
        self.attempt_operation_gates[gate_index]
            .lock()
            .map_err(|_| {
                BrokerError::Invariant("broker attempt operation gate is poisoned".to_string())
            })
    }

    fn attempt_operation_guard_for_request(
        &self,
        request: &BrokerExecuteRequest,
    ) -> Result<MutexGuard<'_, ()>> {
        self.attempt_operation_guard_for_digest(&failure_receipt_key_digest(request)?)
    }

    fn next_dispatch_claim_id(&self) -> Result<String> {
        let previous = self
            .dispatch_claim_counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| BrokerError::Invariant("dispatch claim counter overflowed".to_string()))?;
        let sequence = previous + 1;
        Ok(format!(
            "broker-dispatch-claim-{}-{sequence}",
            std::process::id()
        ))
    }

    pub(crate) fn require_migrations_for_provider(
        &self,
        credential_provider: &str,
    ) -> Result<()> {
        self.migration_enforcer
            .require_provider_enforced(credential_provider)
    }

    fn require_migrations_enforced(&self, request: &BrokerExecuteRequest) -> Result<()> {
        self.migration_enforcer
            .require_provider_enforced(&request.capability.body.credential.provider)
    }

    fn validate_request_core(
        &self,
        request: &BrokerExecuteRequest,
        now_unix_seconds: u64,
    ) -> Result<()> {
        request.validate_bounds()?;
        verify_capability(
            &request.capability,
            &self.trusted_issuer,
            &self.config.audience,
            now_unix_seconds,
            true,
        )?;
        if self.provider.adapter_id() != request.capability.body.provider_adapter_id
            || self.provider.adapter_version() != request.capability.body.provider_adapter_version
            || request.request.destination != request.capability.body.destination
        {
            return Err(BrokerError::AuthorizationDenied(
                "provider or destination does not match the signed capability".to_string(),
            ));
        }
        verify_request_proof(
            &request.proof,
            &request.capability,
            &request.request,
            now_unix_seconds,
            self.config.maximum_clock_skew_seconds,
        )?;
        self.provider
            .validate_request(&request.request, &request.capability.body.constraints)?;
        Ok(())
    }

    fn validate_request_authorities(
        &self,
        request: &BrokerExecuteRequest,
        revocation_authority_domain: &str,
        now_unix_seconds: u64,
        resolve_destination: bool,
    ) -> Result<ValidatedBrokerAuthorities> {
        self.validate_request_core(request, now_unix_seconds)?;
        if resolve_destination {
            self.https.preflight(
                &request.request,
                &request.capability.body.constraints,
                &request.proof,
            )?;
        }
        let live_request = CapabilityLivenessRequest {
            parent_capability_id: request.capability.body.parent_capability_id.clone(),
            expected_subject: request.capability.body.subject.clone(),
            expected_audience: self.config.parent_audience.clone(),
            now_unix_seconds,
        };
        let live_parent = self.liveness.verify_live_parent(&live_request)?;
        validate_parent_liveness(
            &live_request,
            &live_parent,
            self.config.maximum_liveness_snapshot_age_seconds,
        )?;
        let revocation_request = BrokerRevocationRequest {
            broker_capability_id: request.capability.body.capability_id.clone(),
            revocation_id: request.capability.body.revocation_id.clone(),
            now_unix_seconds,
        };
        let revocation_snapshot = self
            .revocations
            .check_broker_revocation(&revocation_request)?;
        validate_revocation_snapshot(
            &revocation_snapshot,
            now_unix_seconds,
            self.config.maximum_revocation_snapshot_age_seconds,
            revocation_authority_domain,
        )?;
        let revocation_set = CanonicalBrokerRevocationSet::new(
            &request.capability.body.parent_capability_id,
            &live_parent.delegation_ancestor_ids,
            &request.capability.body.capability_id,
            &request.capability.body.revocation_id,
        )?;
        Ok(ValidatedBrokerAuthorities {
            revocation_set,
        })
    }

    fn validate_audit_request_authorities(
        &self,
        request: &BrokerExecuteRequest,
        revocation_authority_domain: &str,
        now_unix_seconds: u64,
    ) -> Result<ValidatedBrokerAuditAuthorities> {
        self.validate_request_core(request, now_unix_seconds)?;
        let live_request = CapabilityLivenessRequest {
            parent_capability_id: request.capability.body.parent_capability_id.clone(),
            expected_subject: request.capability.body.subject.clone(),
            expected_audience: self.config.parent_audience.clone(),
            now_unix_seconds,
        };
        let liveness_exchange = self
            .liveness
            .verify_live_parent_with_audit_evidence(&live_request)?;
        if liveness_exchange.request().body.operation
            != crate::authority_ipc::AuthorityOperation::VerifyLiveParent(live_request.clone())
        {
            return Err(BrokerError::AuthorizationDenied(
                "liveness authority audit evidence is rebound".to_string(),
            ));
        }
        let crate::authority_ipc::AuthorityResult::LiveParent(live_parent) =
            &liveness_exchange.response().body.result
        else {
            return Err(BrokerError::AuthorityUnavailable(
                "liveness authority returned the wrong audit result".to_string(),
            ));
        };
        validate_parent_liveness(
            &live_request,
            live_parent,
            self.config.maximum_liveness_snapshot_age_seconds,
        )?;

        let revocation_request = BrokerRevocationRequest {
            broker_capability_id: request.capability.body.capability_id.clone(),
            revocation_id: request.capability.body.revocation_id.clone(),
            now_unix_seconds,
        };
        let revocation_exchange = self
            .revocations
            .check_broker_revocation_with_audit_evidence(&revocation_request)?;
        if revocation_exchange.request().body.operation
            != crate::authority_ipc::AuthorityOperation::CheckBrokerRevocation(
                revocation_request.clone(),
            )
        {
            return Err(BrokerError::AuthorizationDenied(
                "revocation authority audit evidence is rebound".to_string(),
            ));
        }
        let crate::authority_ipc::AuthorityResult::Revocation(revocation_snapshot) =
            &revocation_exchange.response().body.result
        else {
            return Err(BrokerError::AuthorityUnavailable(
                "revocation authority returned the wrong audit result".to_string(),
            ));
        };
        validate_revocation_snapshot(
            revocation_snapshot,
            now_unix_seconds,
            self.config.maximum_revocation_snapshot_age_seconds,
            revocation_authority_domain,
        )?;
        if liveness_exchange.trusted_authority()
            != revocation_exchange.trusted_authority()
        {
            return Err(BrokerError::AuthorizationDenied(
                "broker audit authority responses use different trust roots".to_string(),
            ));
        }
        Ok(ValidatedBrokerAuditAuthorities {
            liveness_exchange,
            revocation_exchange,
        })
    }

    /// Compare the exact broker-prepared HTTP request with a privileged legacy
    /// reference without registering an attempt, mutating quota state, or
    /// crossing the network boundary. The secret-bearing requests and random
    /// blinding salts are destroyed before the signed artifact is returned.
    pub(crate) fn audit_compare_outbound_request(
        &self,
        request: &BrokerExecuteRequest,
        reference: crate::audit::BrokerAuditReferenceRequest,
        runner_authorization: crate::audit::VerifiedBrokerAuditRunnerAuthorization,
        admin_authorization: &AdminAuthorization,
        admin_authorizer: &GovernedAdminAuthorizer,
        now_unix_seconds: u64,
    ) -> Result<crate::audit::CompletedBrokerAuditComparison> {
        reference.validate()?;
        let governed_audit_intent_sha256 =
            runner_authorization.governed_intent_sha256().to_string();
        let audit_id_sha256 = runner_authorization.audit_id_sha256().to_string();
        let runner_authorization_sha256 = runner_authorization
            .runner_authorization_sha256()
            .to_string();
        let reference_source_sha256 = runner_authorization
            .reference_source_sha256()
            .to_string();
        let revocation_authority_domain = runner_authorization.revocation_authority_domain();
        validate_identifier(
            revocation_authority_domain,
            "audit revocation authority domain",
            512,
        )?;
        if now_unix_seconds == 0 {
            return Err(BrokerError::InvalidRequest(
                "broker audit comparison time is invalid".to_string(),
            ));
        }
        let authorities = self.validate_audit_request_authorities(
            request,
            revocation_authority_domain,
            now_unix_seconds,
        )?;
        let audit_authorization_sha256 = admin_authorizer.authorize_intent_digest(
            admin_authorization,
            &governed_audit_intent_sha256,
        )?;
        let capability_sha256 = capability_digest(&request.capability)?;
        let proof_sha256 = proof_digest(&request.proof)?;
        let canonical_request_sha256 =
            broker_execute_request_registration_digest(request)?;
        let receipt_signer = self.receipt_signer.public_key();
        let trust = crate::audit::BrokerAuditTrustConfiguration {
            trusted_capability_issuer: &self.trusted_issuer,
            broker_audience: &self.config.audience,
            parent_audience: &self.config.parent_audience,
            provider_adapter_id: self.provider.adapter_id(),
            provider_adapter_version: self.provider.adapter_version(),
            receipt_signer: &receipt_signer,
            maximum_clock_skew_seconds: self.config.maximum_clock_skew_seconds,
            maximum_liveness_snapshot_age_seconds: self
                .config
                .maximum_liveness_snapshot_age_seconds,
            maximum_revocation_snapshot_age_seconds: self
                .config
                .maximum_revocation_snapshot_age_seconds,
            trusted_authority: authorities.liveness_exchange.trusted_authority(),
            deployment_id: runner_authorization.deployment_id(),
            broker_instance_id: runner_authorization.broker_instance_id(),
            tenant_scope: runner_authorization.tenant_scope(),
            runner_id: runner_authorization.runner_id(),
            trusted_runner: runner_authorization.trusted_runner(),
            governed_admin_policy: admin_authorizer.policy(),
        };
        let authority_context_sha256 = crate::audit::broker_audit_authority_context_digest(
            request,
            crate::audit::BrokerAuditAuthorityEvidence {
                liveness: &authorities.liveness_exchange,
                revocation: &authorities.revocation_exchange,
            },
            trust,
            revocation_authority_domain,
            now_unix_seconds,
        )?;
        let comparison = {
            let comparison_salt = crate::audit::BrokerAuditComparisonSalt::generate()?;
            self.require_migrations_enforced(request)?;
            let credential = self
                .backend
                .materialize(&request.capability.body.credential)?;
            self.https.compare_prepared_request_for_audit(
                self.provider.as_ref(),
                &request.request,
                &request.capability.body.constraints,
                &credential,
                &comparison_salt,
                reference,
            )?
        };
        let signed_comparison = crate::audit::sign_broker_audit_comparison(
            crate::audit::BrokerAuditComparisonBody {
                schema: crate::audit::BROKER_AUDIT_COMPARISON_SCHEMA.to_string(),
                issued_at_unix_seconds: now_unix_seconds,
                capability_sha256,
                proof_sha256,
                canonical_request_sha256,
                authority_context_sha256,
                audit_id_sha256,
                governed_audit_intent_sha256,
                audit_authorization_sha256,
                runner_authorization_sha256,
                reference_source_sha256,
                broker_outbound_projection_commitment_sha256: comparison
                    .broker_projection_commitment_sha256,
                reference_outbound_projection_commitment_sha256: comparison
                    .reference_projection_commitment_sha256,
                projections_equal: comparison.projections_equal,
                network_dispatch_count: 0,
                accounting_mutation_count: 0,
                raw_credential_returned: false,
            },
            self.receipt_signer.as_ref(),
        )?;
        Ok(crate::audit::CompletedBrokerAuditComparison {
            comparison: signed_comparison,
            liveness_authority_exchange: authorities.liveness_exchange,
            revocation_authority_exchange: authorities.revocation_exchange,
        })
    }

    fn expected_registration(
        request: &BrokerExecuteRequest,
        authenticated: &AttemptRegistration,
    ) -> Result<AttemptRegistration> {
        let request_digest = broker_request_digest(request)?;
        let ids = derive_attempt_ids_for_operation(
            &request.capability.body.capability_id,
            &request.invocation_id,
            &request.proof.body.nonce,
            &request_digest,
            &authenticated.ids.operation_id,
        )?;
        let nonce_expires_at_unix_seconds = request
            .proof
            .body
            .issued_at_unix_seconds
            .checked_add(request.capability.body.proof.nonce_ttl_seconds)
            .ok_or_else(|| BrokerError::InvalidRequest("nonce expiry overflow".to_string()))?;
        Ok(AttemptRegistration {
            ids,
            invocation_id: request.invocation_id.clone(),
            parent_capability_id: request.capability.body.parent_capability_id.clone(),
            broker_capability_id: request.capability.body.capability_id.clone(),
            request_digest,
            request_canonical_digest: broker_execute_request_registration_digest(request)?,
            proof_digest: proof_digest(&request.proof)?,
            proof_key_id: request.proof.body.authority_key.to_hex(),
            proof_nonce: request.proof.body.nonce.clone(),
            nonce_expires_at_unix_seconds,
            quotas: authenticated.quotas.clone(),
            authority_metadata_digest: authenticated.authority_metadata_digest.clone(),
            revocation_authority_domain: authenticated.revocation_authority_domain.clone(),
        })
    }

    fn validate_authenticated_registration(
        &self,
        registration: &AttemptRegistration,
        request: &BrokerExecuteRequest,
        now_unix_seconds: u64,
    ) -> Result<CanonicalBrokerRevocationSet> {
        registration.validate()?;
        let expected = Self::expected_registration(request, registration)?;
        if expected != *registration {
            return Err(BrokerError::AuthorizationDenied(
                "authenticated registration does not match the canonical broker execute request"
                    .to_string(),
            ));
        }
        self.validate_request_authorities(
            request,
            &registration.revocation_authority_domain,
            now_unix_seconds,
            true,
        )
        .map(|authorities| authorities.revocation_set)
    }

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
            .revocation_set;

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
        let credential = self
            .backend
            .materialize(&request.capability.body.credential)?;
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

    fn replay_failure_locked(
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

    fn targets_completed_attempt(&self, request: &BrokerExecuteRequest) -> Result<bool> {
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

}
