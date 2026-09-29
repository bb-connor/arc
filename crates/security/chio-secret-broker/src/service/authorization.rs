use super::{
    broker_execute_request_registration_digest, broker_request_digest, capability_digest,
    derive_attempt_ids_for_operation, proof_digest, validate_identifier, validate_parent_liveness,
    validate_revocation_snapshot, verify_capability, verify_request_proof, AdminAuthorization,
    AttemptRegistration, BrokerError, BrokerExecuteRequest, BrokerRevocationRequest, BrokerService,
    CanonicalBrokerRevocationSet, CapabilityLivenessRequest, GovernedAdminAuthorizer,
    ProviderAdapter, Result, SecretBackend,
};

impl BrokerService {
    pub(super) fn authority_observation_time(&self, previous: u64) -> Result<u64> {
        let observed = match &self.authority_clock {
            Some(clock) => clock
                .unix_millis()
                .map(chio_security_types::clock::UnixMillis::as_secs)?,
            None => previous,
        };
        if observed < previous {
            return Err(BrokerError::AuthorityUnavailable(
                "broker authority observation clock moved backwards".into(),
            ));
        }
        Ok(observed)
    }

    pub(super) fn require_migrations_enforced(&self, request: &BrokerExecuteRequest) -> Result<()> {
        self.migration_enforcer
            .require_provider_enforced(&request.capability.body.credential.provider)
    }

    pub(super) fn validate_request_core(
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

    pub(super) fn validate_request_authorities(
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
        let now_unix_seconds = self.authority_observation_time(now_unix_seconds)?;
        let live_request = CapabilityLivenessRequest {
            parent_capability_id: request.capability.body.parent_capability_id.clone(),
            expected_subject: request.capability.body.subject.clone(),
            expected_audience: self.config.parent_audience.clone(),
            now_unix_seconds,
        };
        let live_parent = self.liveness.verify_live_parent(&live_request)?;
        let now_unix_seconds = self.authority_observation_time(now_unix_seconds)?;
        validate_parent_liveness(
            &CapabilityLivenessRequest {
                now_unix_seconds,
                ..live_request.clone()
            },
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
        let now_unix_seconds = self.authority_observation_time(now_unix_seconds)?;
        self.validate_request_core(request, now_unix_seconds)?;
        validate_parent_liveness(
            &CapabilityLivenessRequest {
                now_unix_seconds,
                ..live_request
            },
            &live_parent,
            self.config.maximum_liveness_snapshot_age_seconds,
        )?;
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
        Ok(ValidatedBrokerAuthorities { revocation_set })
    }

    fn validate_audit_request_authorities(
        &self,
        request: &BrokerExecuteRequest,
        revocation_authority_domain: &str,
        now_unix_seconds: u64,
    ) -> Result<ValidatedBrokerAuditAuthorities> {
        self.validate_request_core(request, now_unix_seconds)?;
        let now_unix_seconds = self.authority_observation_time(now_unix_seconds)?;
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
        let now_unix_seconds = self.authority_observation_time(now_unix_seconds)?;
        validate_parent_liveness(
            &CapabilityLivenessRequest {
                now_unix_seconds,
                ..live_request.clone()
            },
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
        let now_unix_seconds = self.authority_observation_time(now_unix_seconds)?;
        self.validate_request_core(request, now_unix_seconds)?;
        validate_parent_liveness(
            &CapabilityLivenessRequest {
                now_unix_seconds,
                ..live_request
            },
            live_parent,
            self.config.maximum_liveness_snapshot_age_seconds,
        )?;
        validate_revocation_snapshot(
            revocation_snapshot,
            now_unix_seconds,
            self.config.maximum_revocation_snapshot_age_seconds,
            revocation_authority_domain,
        )?;
        if liveness_exchange.trusted_authority() != revocation_exchange.trusted_authority() {
            return Err(BrokerError::AuthorizationDenied(
                "broker audit authority responses use different trust roots".to_string(),
            ));
        }
        Ok(ValidatedBrokerAuditAuthorities {
            liveness_exchange,
            revocation_exchange,
            validated_at_unix_seconds: now_unix_seconds,
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
        let reference_source_sha256 = runner_authorization.reference_source_sha256().to_string();
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
        let now_unix_seconds = authorities.validated_at_unix_seconds;
        let audit_authorization_sha256 = admin_authorizer
            .authorize_intent_digest(admin_authorization, &governed_audit_intent_sha256)?;
        let capability_sha256 = capability_digest(&request.capability)?;
        let proof_sha256 = proof_digest(&request.proof)?;
        let canonical_request_sha256 = broker_execute_request_registration_digest(request)?;
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

    pub(super) fn expected_registration(
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

    pub(super) fn validate_authenticated_registration(
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
}

pub(super) struct ValidatedBrokerAuthorities {
    revocation_set: CanonicalBrokerRevocationSet,
}

impl ValidatedBrokerAuthorities {
    pub(super) fn revocation_set(&self) -> &CanonicalBrokerRevocationSet {
        &self.revocation_set
    }

    pub(super) fn into_revocation_set(self) -> CanonicalBrokerRevocationSet {
        self.revocation_set
    }
}
struct ValidatedBrokerAuditAuthorities {
    liveness_exchange: crate::authority_ipc::VerifiedAuthorityExchange,
    revocation_exchange: crate::authority_ipc::VerifiedAuthorityExchange,
    validated_at_unix_seconds: u64,
}
