#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::capability::features::{
        CapabilityNegotiation, SUPPLEMENTAL_BROKER_EXECUTION_QUOTA,
    };
    use chio_core::crypto::{Ed25519Backend, Keypair};
    use chio_kernel::budget_store::{BudgetInvocationQuota, BudgetQuotaKey};
    use chio_kernel::supplemental_quota::CanonicalRevocationSet;
    use chio_kernel::{
        AdmissionCleanupAction, AdmissionCleanupActionKind, AdmissionOperationCasOutcome,
        AdmissionOperationCreateOutcome, PreparedAdmissionOperation,
    };
    use chio_secret_broker::budget::{
        AuthorizeExecutionHoldRequest, CaptureExecutionHoldRequest, ExecutionHoldState,
        QueryExecutionHoldRequest, ReverseExecutionHoldRequest,
    };
    use chio_secret_broker::capability::issue_capability;
    use chio_secret_broker::proof::{body_digest, issue_request_proof};
    use chio_secret_broker::protocol::{
        AttemptConsumption, BrokerCapabilityBody, BrokerDestination, BrokerExecuteRequest,
        BrokerRequest, CallerOptions, CredentialRef, ProofBinding, ProofMode, RedirectPolicy,
        RequestConstraints, BROKER_CAPABILITY_SCHEMA, BROKER_EXECUTE_SCHEMA,
    };
    use chio_secret_broker::provision::{AdminClock, GovernedAdminAuthorizer, GovernedAdminPolicy};
    use chio_secret_broker::receipt::SqliteBrokerReceiptSink;
    use chio_secret_broker::sqlite::SqliteAttemptStore;
    use chio_secret_broker::store::{AttemptState, AttemptStore, AttemptTransitionEvidence};

    fn must<T, E: std::fmt::Debug>(result: Result<T, E>, context: &str) -> T {
        result.unwrap_or_else(|error| panic!("{context}: {error:?}"))
    }

    fn rejected<T: std::fmt::Debug, E>(result: Result<T, E>, context: &str) -> E {
        match result {
            Ok(value) => panic!("{context}: {value:?}"),
            Err(error) => error,
        }
    }

    fn test_migration_enforcer() -> Arc<dyn BrokerMigrationEnforcer> {
        TestBrokerMigrationEnforcer::new(["generic-https".to_string()])
    }

    struct FixedClock(u64);

    impl AdminClock for FixedClock {
        fn now_unix_seconds(&self) -> chio_secret_broker::Result<u64> {
            Ok(self.0)
        }
    }

    struct InProcessAttemptRegistration {
        store: SqliteAttemptStore,
        _directory: tempfile::TempDir,
        now_unix_seconds: u64,
    }

    impl InProcessAttemptRegistration {
        fn fixture() -> Self {
            let directory = must(tempfile::tempdir(), "create attempt store directory");
            let trusted_directory = must(
                std::fs::canonicalize(directory.path()),
                "canonicalize attempt store directory",
            );
            let store = must(
                SqliteAttemptStore::open(trusted_directory.join("attempts.sqlite3")),
                "open durable attempt store",
            );
            Self {
                store,
                _directory: directory,
                now_unix_seconds: 100,
            }
        }

        fn production_fixture() -> Arc<dyn BrokerAttemptRegistrationPort> {
            Arc::new(Self::fixture())
        }
    }

    impl BrokerAttemptRegistrationPort for InProcessAttemptRegistration {
        fn register_attempt(
            &self,
            registration: &AttemptRegistration,
            _request: &BrokerExecuteRequest,
        ) -> BrokerResult<RegisterAttemptAcknowledgement> {
            RegisterAttemptAcknowledgement::from_outcome(
                self.store
                    .register_intent(registration, self.now_unix_seconds)?,
                self.now_unix_seconds,
            )
        }

        fn prepare_dispatch(
            &self,
            registration: &AttemptRegistration,
            request: &BrokerExecuteRequest,
        ) -> BrokerResult<PrepareDispatchAcknowledgement> {
            PrepareDispatchAcknowledgement::new(registration, request, self.now_unix_seconds)
        }

        fn release_attempt(
            &self,
            registration: &AttemptRegistration,
            _request: &BrokerExecuteRequest,
        ) -> BrokerResult<ReleaseAttemptAcknowledgement> {
            let existing = match self.store.load_attempt(&registration.ids.attempt_id)? {
                Some(existing) => existing,
                None => match self
                    .store
                    .register_intent(registration, self.now_unix_seconds)?
                {
                    chio_secret_broker::store::RegisterAttemptOutcome::Inserted(record)
                    | chio_secret_broker::store::RegisterAttemptOutcome::ExactRetry(record) => {
                        record
                    }
                },
            };
            if existing.state == AttemptState::Registered {
                let tombstone = self.store.transition(
                    &registration.ids.attempt_id,
                    AttemptState::Registered,
                    AttemptState::Failed,
                    &AttemptTransitionEvidence::default(),
                    self.now_unix_seconds,
                )?;
                return ReleaseAttemptAcknowledgement::new(
                    registration,
                    tombstone.updated_at_unix_seconds,
                );
            }
            ReleaseAttemptAcknowledgement::new(registration, existing.updated_at_unix_seconds)
        }
    }

    struct LoseFirstReleaseAcknowledgement {
        inner: InProcessAttemptRegistration,
        lose_next_release_acknowledgement: std::sync::atomic::AtomicBool,
    }

    impl LoseFirstReleaseAcknowledgement {
        fn production_fixture() -> Arc<Self> {
            Arc::new(Self {
                inner: InProcessAttemptRegistration::fixture(),
                lose_next_release_acknowledgement: std::sync::atomic::AtomicBool::new(true),
            })
        }
    }

    impl BrokerAttemptRegistrationPort for LoseFirstReleaseAcknowledgement {
        fn register_attempt(
            &self,
            registration: &AttemptRegistration,
            request: &BrokerExecuteRequest,
        ) -> BrokerResult<RegisterAttemptAcknowledgement> {
            self.inner.register_attempt(registration, request)
        }

        fn prepare_dispatch(
            &self,
            registration: &AttemptRegistration,
            request: &BrokerExecuteRequest,
        ) -> BrokerResult<PrepareDispatchAcknowledgement> {
            self.inner.prepare_dispatch(registration, request)
        }

        fn release_attempt(
            &self,
            registration: &AttemptRegistration,
            request: &BrokerExecuteRequest,
        ) -> BrokerResult<ReleaseAttemptAcknowledgement> {
            let acknowledgement = self.inner.release_attempt(registration, request)?;
            if self
                .lose_next_release_acknowledgement
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(BrokerError::AuthorityUnavailable(
                    "injected release acknowledgement loss".to_string(),
                ));
            }
            Ok(acknowledgement)
        }
    }

    fn execution_fixture() -> (Keypair, Keypair, BrokerExecuteRequest) {
        let issuer = Keypair::from_seed(&[51; 32]);
        let caller = Keypair::from_seed(&[52; 32]);
        let destination = must(
            BrokerDestination::parse("https://example.com/v1", "post", false),
            "parse broker destination",
        );
        let request = BrokerRequest {
            destination: destination.clone(),
            headers: Vec::new(),
            body: b"production-body".to_vec(),
            approved_preview_sha256: None,
            options: CallerOptions {
                timeout_ms: 1_000,
                streaming: false,
                response_limit_bytes: 4_096,
            },
        };
        let capability = must(
            issue_capability(
                BrokerCapabilityBody {
                    schema: BROKER_CAPABILITY_SCHEMA.to_string(),
                    issuer: issuer.public_key(),
                    capability_id: "broker-capability-production-1".to_string(),
                    parent_capability_id: "parent-capability-production-1".to_string(),
                    subject: caller.public_key(),
                    audience: "broker-service-production".to_string(),
                    issued_at_unix_seconds: 90,
                    not_before_unix_seconds: 90,
                    expires_at_unix_seconds: 120,
                    credential: CredentialRef {
                        provider: "generic-https".to_string(),
                        credential_id: "credential-production-1".to_string(),
                        version: 1,
                    },
                    provider_adapter_id: "generic-bearer".to_string(),
                    provider_adapter_version: 1,
                    destination,
                    constraints: RequestConstraints {
                        allowed_caller_headers: Vec::new(),
                        provider_owned_headers: vec!["authorization".to_string()],
                        maximum_body_bytes: 4_096,
                        required_body_sha256: body_digest(&request.body),
                        required_preview_sha256: None,
                        redirect_policy: RedirectPolicy::Disabled,
                        maximum_response_bytes: 4_096,
                        streaming_allowed: false,
                        maximum_timeout_ms: 1_000,
                    },
                    broker_quota_key_id: "signed-broker-quota-production-1".to_string(),
                    maximum_executions: 2,
                    consumption: AttemptConsumption::CaptureBeforeDispatch,
                    revocation_id: "broker-revocation-production-1".to_string(),
                    proof: ProofBinding {
                        mode: ProofMode::PublicKey,
                        caller_public_key: caller.public_key(),
                        nonce_ttl_seconds: 30,
                    },
                },
                &Ed25519Backend::new(issuer.clone()),
                true,
            ),
            "issue broker capability",
        );
        let proof = must(
            issue_request_proof(
                &capability,
                &request,
                "nonce-production-123456789".to_string(),
                100,
                &caller,
            ),
            "issue broker request proof",
        );
        (
            issuer,
            caller,
            BrokerExecuteRequest {
                schema: BROKER_EXECUTE_SCHEMA.to_string(),
                invocation_id: "invocation-production-1".to_string(),
                capability,
                proof,
                request,
            },
        )
    }

    fn supplemental_context(
        request: &BrokerExecuteRequest,
        subject: PublicKey,
    ) -> SupplementalQuotaVerificationContext {
        let mut negotiated_features = CapabilityNegotiation::t1_default();
        negotiated_features
            .features
            .insert(SUPPLEMENTAL_BROKER_EXECUTION_QUOTA.to_string(), true);
        SupplementalQuotaVerificationContext {
            capability_id: request.capability.body.parent_capability_id.clone(),
            capability_digest: "11".repeat(32),
            subject,
            request_id: "request-production-1".to_string(),
            destination: must(
                SupplementalQuotaDestination::new("broker", "execute"),
                "construct supplemental destination",
            ),
            arguments_digest: "22".repeat(32),
            request_binding_hash: "33".repeat(32),
            now: 100,
            negotiated_profile: BudgetQuotaProfile::SupplementalBrokerExecution,
            negotiated_features,
        }
    }

    #[test]
    fn supplemental_verifier_rejects_noncanonical_and_context_swapped_artifacts() {
        let (issuer, caller, request) = execution_fixture();
        let verifier = must(
            BrokerSupplementalQuotaVerifier::new(
                issuer.public_key(),
                "broker-service-production".to_string(),
                must(
                    SupplementalQuotaDestination::new("broker", "execute"),
                    "construct supplemental destination",
                ),
                true,
                "broker-capability-verifier-v1".to_string(),
            ),
            "construct supplemental verifier",
        );
        let canonical = must(
            canonical_json_bytes(&request.capability),
            "canonicalize capability",
        );
        let artifact = must(
            OpaqueSignedSupplementalQuota::new(canonical.clone()),
            "construct opaque quota",
        );
        let context = supplemental_context(&request, caller.public_key());
        let claim = must(verifier.verify(&artifact, &context), "verify opaque quota");
        assert_eq!(
            claim.broker_capability_id,
            request.capability.body.capability_id
        );
        assert_eq!(claim.max_invocations, 2);

        let mut noncanonical = canonical;
        noncanonical.push(b'\n');
        let noncanonical_artifact = must(
            OpaqueSignedSupplementalQuota::new(noncanonical),
            "construct noncanonical quota artifact",
        );
        assert!(verifier.verify(&noncanonical_artifact, &context).is_err());

        let swapped = supplemental_context(&request, Keypair::from_seed(&[53; 32]).public_key());
        assert!(verifier.verify(&artifact, &swapped).is_err());
    }

    fn revocation_set(request: &BrokerExecuteRequest) -> CanonicalRevocationSet {
        revocation_set_with_ancestors(request, &[])
    }

    fn revocation_set_with_ancestors(
        request: &BrokerExecuteRequest,
        additional_ancestors: &[String],
    ) -> CanonicalRevocationSet {
        let mut ids = vec![
            request.capability.body.parent_capability_id.clone(),
            request.capability.body.capability_id.clone(),
            request.capability.body.revocation_id.clone(),
        ];
        ids.extend_from_slice(additional_ancestors);
        ids.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        ids.dedup();
        let canonical = must(canonical_json_bytes(&ids), "canonicalize revocation ids");
        let mut input = b"chio.revocation-set.v1\0".to_vec();
        input.extend_from_slice(&canonical);
        must(
            CanonicalRevocationSet::from_persisted_parts(ids, sha256_hex(&input)),
            "construct canonical revocation set",
        )
    }

    fn invocation_quotas(request: &BrokerExecuteRequest) -> Vec<BudgetInvocationQuota> {
        let mut quotas = vec![
            must(
                BudgetInvocationQuota::from_persisted_parts(
                    must(
                        BudgetQuotaKey::from_persisted_parts(
                            BudgetQuotaProfile::GrantInvocation,
                            request.capability.body.parent_capability_id.clone(),
                            Some(0),
                        ),
                        "construct grant quota key",
                    ),
                    10,
                ),
                "construct grant quota",
            ),
            must(
                BudgetInvocationQuota::from_persisted_parts(
                    must(
                        BudgetQuotaKey::from_persisted_parts(
                            BudgetQuotaProfile::SupplementalBrokerExecution,
                            "ab".repeat(32),
                            None,
                        ),
                        "construct supplemental quota key",
                    ),
                    request.capability.body.maximum_executions,
                ),
                "construct supplemental quota",
            ),
        ];
        quotas.sort_unstable_by(|left, right| left.key().cmp(right.key()));
        quotas
    }

    fn create_broker_admission_operation(
        path: &Path,
        request: &BrokerExecuteRequest,
        provisional_ids: &AttemptIds,
        request_binding_hash: &str,
    ) -> (SqliteAdmissionOperationStore, AdmissionOperation) {
        let store = must(
            SqliteAdmissionOperationStore::open(path),
            "open admission operation store",
        );
        let operation = must(
            AdmissionOperation::prepared(PreparedAdmissionOperation {
                kind: AdmissionOperationKind::ToolDispatch,
                coordinator_authority_id: "kernel-coordinator-production".to_string(),
                request_id: request.invocation_id.clone(),
                capability_id: request.capability.body.parent_capability_id.clone(),
                authorization_capability_hash: must(
                    capability_digest(&request.capability),
                    "digest authorization capability",
                ),
                request_binding_hash: request_binding_hash.to_string(),
                policy_hash: "55".repeat(32),
                broker_attempt_id: Some(provisional_ids.attempt_id.clone()),
                budget_hold_id: Some(provisional_ids.hold_id.clone()),
                approval_set_hash: None,
                execution_nonce_id: None,
                coordinator_lease_epoch: 7,
            }),
            "prepare admission operation",
        );
        assert!(matches!(
            must(
                store.create_prepared(operation.clone()),
                "persist admission operation"
            ),
            AdmissionOperationCreateOutcome::Created(_)
        ));
        (store, operation)
    }

    fn advance_broker_admission_operation(
        store: &SqliteAdmissionOperationStore,
        operation_id: &str,
        state: AdmissionOperationState,
        dispatch_state: AdmissionDispatchState,
    ) -> AdmissionOperation {
        let current = must(store.load(operation_id), "load admission operation")
            .unwrap_or_else(|| panic!("admission operation is missing"));
        let request = AdmissionOperationCompareAndSwap {
            operation_id,
            expected_version: current.version(),
            coordinator_lease_epoch: current.coordinator_lease_epoch(),
            next_state: state,
            next_dispatch_state: dispatch_state,
            next_coordinator_lease_epoch: current.coordinator_lease_epoch(),
            last_error: None,
        };
        let outcome = if state == AdmissionOperationState::CompensationPending
            || state.is_terminal()
        {
            let terminal_receipt = must(
                AdmissionCleanupAction::pending(
                    &current,
                    AdmissionCleanupActionKind::TerminalReceipt,
                    &serde_json::json!({
                        "operation_id": current.operation_id(),
                        "request_binding_hash": current.request_binding_hash(),
                    }),
                ),
                "construct terminal receipt action",
            );
            store.compare_and_swap_with_cleanup_action(request, terminal_receipt)
        } else {
            store.compare_and_swap(request)
        };
        match must(outcome, "advance admission operation") {
            AdmissionOperationCasOutcome::Applied(operation) => operation,
            other => panic!("unexpected admission operation transition: {other:?}"),
        }
    }

    #[test]
    fn broker_send_requires_durable_dispatch_commit_and_survives_authority_restart() {
        let directory = must(tempfile::tempdir(), "create authority directory");
        let (_, _, request) = execution_fixture();
        let authority_path = directory.path().join("authority.sqlite3");
        let operation_path = directory.path().join("operations.sqlite3");
        let registration = InProcessAttemptRegistration::production_fixture();
        let request_digest = must(broker_request_digest(&request), "digest broker request");
        let provisional_ids = must(
            derive_attempt_ids(
                &request.capability.body.capability_id,
                &request.invocation_id,
                &request.proof.body.nonce,
                &request_digest,
            ),
            "derive provisional attempt identifiers",
        );
        let request_binding_hash = "44".repeat(32);
        let (operation_store, operation) = create_broker_admission_operation(
            &operation_path,
            &request,
            &provisional_ids,
            &request_binding_hash,
        );
        let ids = must(
            derive_attempt_ids_for_operation(
                &request.capability.body.capability_id,
                &request.invocation_id,
                &request.proof.body.nonce,
                &request_digest,
                operation.operation_id(),
            ),
            "bind attempt identifiers to kernel operation",
        );
        let adapter = must(
            AuthoritativeBrokerExecutionAdapter::open(
                &authority_path,
                &operation_path,
                AuthoritativeBrokerExecutionConfig {
                    revocation_authority_domain: "combined-sqlite-production".to_string(),
                    supplemental_verifier_id: "broker-capability-verifier-v1".to_string(),
                    maximum_pending_admissions: 1,
                },
                Arc::clone(&registration),
                test_migration_enforcer(),
            ),
            "open execution adapter",
        );
        let family_root_id = "family-root-production-1".to_string();
        let family_evidence = SqliteAggregateFamilyEvidence {
            root_capability_id: family_root_id.clone(),
            root_binding_digest: "ef".repeat(32),
        };
        let revocation_set =
            revocation_set_with_ancestors(&request, std::slice::from_ref(&family_root_id));
        let mut quotas = invocation_quotas(&request);
        quotas.push(must(
            BudgetInvocationQuota::from_persisted_parts(
                must(
                    BudgetQuotaKey::from_persisted_parts(
                        BudgetQuotaProfile::AggregateFamilyInvocation,
                        "cd".repeat(32),
                        None,
                    ),
                    "construct aggregate family quota key",
                ),
                9,
            ),
            "construct aggregate family quota",
        ));
        quotas.sort_unstable_by(|left, right| left.key().cmp(right.key()));
        let artifact_digest = must(
            capability_digest(&request.capability),
            "digest broker capability",
        );
        let authorization = SqliteCompositeAuthorizeInput {
            operation_id: ids.operation_id.clone(),
            request_binding_hash,
            capability_id: request.capability.body.parent_capability_id.clone(),
            grant_index: 0,
            requested_exposure_units: 0,
            max_cost_per_invocation: None,
            max_total_cost_units: None,
            hold_id: ids.hold_id.clone(),
            event_id: ids.authorize_event_id.clone(),
            authority: Some(BudgetEventAuthority {
                authority_id: "budget-authority-production".to_string(),
                lease_id: "lease-production-1".to_string(),
                lease_epoch: 7,
            }),
            invocation_quotas: quotas,
            revocation_set: revocation_set.clone(),
            authorization_artifact_digests: vec![artifact_digest.clone()],
            partition_escrow_evidence: None,
        };
        let trusted = must(
            adapter.register_admission(
                &request,
                &ids.operation_id,
                authorization.clone(),
                Some(family_evidence.clone()),
                Vec::new(),
                Some(0),
            ),
            "register broker admission",
        );
        assert_eq!(trusted.admission_operation_id, ids.operation_id);
        assert!(trusted.source_receipt_ids.is_empty());
        advance_broker_admission_operation(
            &operation_store,
            &ids.operation_id,
            AdmissionOperationState::BrokerAttemptRegistered,
            AdmissionDispatchState::NotStarted,
        );

        let authorize_request = AuthorizeExecutionHoldRequest {
            operation_id: ids.operation_id.clone(),
            invocation_id: request.invocation_id.clone(),
            parent_capability_id: request.capability.body.parent_capability_id.clone(),
            broker_capability_id: request.capability.body.capability_id.clone(),
            hold_id: ids.hold_id.clone(),
            authorize_event_id: ids.authorize_event_id.clone(),
            quotas: trusted.quotas.clone(),
            authority_metadata_digest: trusted.authority_metadata_digest.clone(),
        };
        assert_eq!(
            must(
                adapter.authorize_execution_hold(&authorize_request),
                "query absent authorization",
            ),
            ExecutionHoldState::Unknown,
            "broker RPC must not create kernel authorization"
        );
        assert!(must(
            adapter
                .budget
                .query_composite_authorization(&ids.authorize_event_id),
            "query durable authorization"
        )
        .is_none());

        assert!(matches!(
            must(
                adapter.budget.authorize_aggregate_family_composite_hold(
                    authorization.clone(),
                    family_evidence.clone(),
                ),
                "kernel authorizes composite hold",
            ),
            BudgetAuthorizeHoldDecision::Authorized(_)
        ));
        advance_broker_admission_operation(
            &operation_store,
            &ids.operation_id,
            AdmissionOperationState::BudgetAuthorized,
            AdmissionDispatchState::NotStarted,
        );
        assert_eq!(
            must(
                adapter.reverse_execution_hold(&ReverseExecutionHoldRequest {
                    operation_id: ids.operation_id.clone(),
                    invocation_id: request.invocation_id.clone(),
                    parent_capability_id: request.capability.body.parent_capability_id.clone(),
                    broker_capability_id: request.capability.body.capability_id.clone(),
                    hold_id: ids.hold_id.clone(),
                    reverse_event_id: ids.reverse_event_id.clone(),
                    proof_dispatch_did_not_begin: true,
                }),
                "query kernel-owned hold through reverse RPC",
            ),
            ExecutionHoldState::Held
        );
        assert!(must(
            adapter
                .budget
                .query_composite_hold_mutation(&ids.reverse_event_id),
            "query reverse mutation after broker RPC",
        )
        .is_none());
        advance_broker_admission_operation(
            &operation_store,
            &ids.operation_id,
            AdmissionOperationState::ReadyToDispatch,
            AdmissionDispatchState::NotStarted,
        );
        advance_broker_admission_operation(
            &operation_store,
            &ids.operation_id,
            AdmissionOperationState::CapturePending,
            AdmissionDispatchState::NotStarted,
        );
        let durable = must(
            adapter.registry.load_by_operation(&ids.operation_id),
            "load durable registry entry",
        )
        .unwrap_or_else(|| panic!("durable registry entry is missing"));
        let prepared = must(
            adapter.rehydrate_prepared(durable),
            "rehydrate durable admission",
        )
        .unwrap_or_else(|| panic!("durable authorization is missing"));
        assert_eq!(
            prepared.aggregate_family_evidence,
            Some(family_evidence.clone())
        );
        assert!(matches!(
            must(
                adapter.capture.capture_admission(must(
                    AuthoritativeBrokerExecutionAdapter::capture_request(&prepared),
                    "construct kernel capture request",
                )),
                "kernel captures admission",
            ),
            AdmissionCaptureDecision::Captured { .. }
        ));
        let capture_request = CaptureExecutionHoldRequest {
            operation_id: ids.operation_id.clone(),
            invocation_id: request.invocation_id.clone(),
            parent_capability_id: request.capability.body.parent_capability_id.clone(),
            broker_capability_id: request.capability.body.capability_id.clone(),
            hold_id: ids.hold_id.clone(),
            capture_event_id: ids.capture_event_id.clone(),
            revocation_ids: revocation_set.ids().to_vec(),
            revocation_set_digest: revocation_set.digest().to_string(),
            authorization_artifact_digest: artifact_digest,
            authority_metadata_digest: trusted.authority_metadata_digest.clone(),
        };
        let precommit_error = match adapter.capture_execution_hold(&capture_request) {
            Ok(state) => panic!("precommit capture query unexpectedly returned {state:?}"),
            Err(error) => error,
        };
        assert!(precommit_error.to_string().contains("DispatchCommitted"));
        assert!(adapter.trusted_context_for(&request).is_err());

        advance_broker_admission_operation(
            &operation_store,
            &ids.operation_id,
            AdmissionOperationState::DispatchCommitted,
            AdmissionDispatchState::Committed,
        );
        drop(adapter);

        let restarted = must(
            AuthoritativeBrokerExecutionAdapter::open(
                &authority_path,
                &operation_path,
                AuthoritativeBrokerExecutionConfig {
                    revocation_authority_domain: "combined-sqlite-production".to_string(),
                    supplemental_verifier_id: "broker-capability-verifier-v1".to_string(),
                    maximum_pending_admissions: 1,
                },
                Arc::clone(&registration),
                test_migration_enforcer(),
            ),
            "restart execution adapter",
        );
        assert_eq!(
            must(
                restarted.trusted_context_for(&request),
                "recover trusted broker context",
            ),
            trusted
        );
        let captured = must(
            restarted.capture_execution_hold(&capture_request),
            "query captured execution hold",
        );
        let ExecutionHoldState::Captured(ref commit) = captured else {
            panic!("expected captured hold");
        };
        assert_eq!(commit.leader_epoch, 7);

        let queried = must(
            restarted.query_execution_hold(&QueryExecutionHoldRequest {
                operation_id: ids.operation_id.clone(),
                invocation_id: request.invocation_id.clone(),
                parent_capability_id: request.capability.body.parent_capability_id.clone(),
                broker_capability_id: request.capability.body.capability_id.clone(),
                hold_id: ids.hold_id.clone(),
                authorize_event_id: ids.authorize_event_id.clone(),
                reverse_event_id: ids.reverse_event_id.clone(),
                capture_event_id: ids.capture_event_id.clone(),
            }),
            "query execution hold",
        );
        assert_eq!(queried, captured);

        advance_broker_admission_operation(
            &operation_store,
            &ids.operation_id,
            AdmissionOperationState::Completed,
            AdmissionDispatchState::EffectCompleted,
        );
        drop(restarted);
        let after_terminal_restart = must(
            AuthoritativeBrokerExecutionAdapter::open(
                &authority_path,
                &operation_path,
                AuthoritativeBrokerExecutionConfig {
                    revocation_authority_domain: "combined-sqlite-production".to_string(),
                    supplemental_verifier_id: "broker-capability-verifier-v1".to_string(),
                    maximum_pending_admissions: 1,
                },
                registration,
                test_migration_enforcer(),
            ),
            "restart adapter after terminal kernel state",
        );
        assert!(must(
            after_terminal_restart.registry.operation_ids(),
            "list pending registry after terminal pruning",
        )
        .is_empty());
    }

    #[test]
    fn outcome_unknown_retains_registry_and_capture_query_after_restart() {
        let directory = must(tempfile::tempdir(), "create recovery directory");
        let (_, _, request) = execution_fixture();
        let authority_path = directory.path().join("authority.sqlite3");
        let operation_path = directory.path().join("operations.sqlite3");
        let registration = InProcessAttemptRegistration::production_fixture();
        let request_digest = must(broker_request_digest(&request), "digest broker request");
        let provisional_ids = must(
            derive_attempt_ids(
                &request.capability.body.capability_id,
                &request.invocation_id,
                &request.proof.body.nonce,
                &request_digest,
            ),
            "derive provisional attempt identifiers",
        );
        let request_binding_hash = "66".repeat(32);
        let (operation_store, operation) = create_broker_admission_operation(
            &operation_path,
            &request,
            &provisional_ids,
            &request_binding_hash,
        );
        let ids = must(
            derive_attempt_ids_for_operation(
                &request.capability.body.capability_id,
                &request.invocation_id,
                &request.proof.body.nonce,
                &request_digest,
                operation.operation_id(),
            ),
            "bind recovery attempt identifiers",
        );
        let adapter = must(
            AuthoritativeBrokerExecutionAdapter::open(
                &authority_path,
                &operation_path,
                AuthoritativeBrokerExecutionConfig {
                    revocation_authority_domain: "combined-sqlite-production".to_string(),
                    supplemental_verifier_id: "broker-capability-verifier-v1".to_string(),
                    maximum_pending_admissions: 1,
                },
                Arc::clone(&registration),
                test_migration_enforcer(),
            ),
            "open recovery adapter",
        );
        let revocation_set = revocation_set(&request);
        let artifact_digest = must(
            capability_digest(&request.capability),
            "digest recovery capability",
        );
        let authorization = SqliteCompositeAuthorizeInput {
            operation_id: ids.operation_id.clone(),
            request_binding_hash,
            capability_id: request.capability.body.parent_capability_id.clone(),
            grant_index: 0,
            requested_exposure_units: 0,
            max_cost_per_invocation: None,
            max_total_cost_units: None,
            hold_id: ids.hold_id.clone(),
            event_id: ids.authorize_event_id.clone(),
            authority: Some(BudgetEventAuthority {
                authority_id: "budget-authority-production".to_string(),
                lease_id: "lease-production-unknown".to_string(),
                lease_epoch: 7,
            }),
            invocation_quotas: invocation_quotas(&request),
            revocation_set: revocation_set.clone(),
            authorization_artifact_digests: vec![artifact_digest],
            partition_escrow_evidence: None,
        };
        must(
            adapter.register_admission(
                &request,
                &ids.operation_id,
                authorization.clone(),
                None,
                Vec::new(),
                Some(0),
            ),
            "register recovery admission",
        );
        advance_broker_admission_operation(
            &operation_store,
            &ids.operation_id,
            AdmissionOperationState::BrokerAttemptRegistered,
            AdmissionDispatchState::NotStarted,
        );
        assert!(matches!(
            must(
                adapter.budget.authorize_composite_hold(authorization),
                "authorize recovery hold",
            ),
            BudgetAuthorizeHoldDecision::Authorized(_)
        ));
        for state in [
            AdmissionOperationState::BudgetAuthorized,
            AdmissionOperationState::ReadyToDispatch,
            AdmissionOperationState::CapturePending,
        ] {
            advance_broker_admission_operation(
                &operation_store,
                &ids.operation_id,
                state,
                AdmissionDispatchState::NotStarted,
            );
        }
        let durable = must(
            adapter.registry.load_by_operation(&ids.operation_id),
            "load recovery registry entry",
        )
        .unwrap_or_else(|| panic!("recovery registry entry is missing"));
        let prepared = must(
            adapter.rehydrate_prepared(durable),
            "rehydrate recovery admission",
        )
        .unwrap_or_else(|| panic!("recovery authorization is missing"));
        assert!(matches!(
            must(
                adapter.capture.capture_admission(must(
                    AuthoritativeBrokerExecutionAdapter::capture_request(&prepared),
                    "construct recovery capture request",
                )),
                "capture recovery admission",
            ),
            AdmissionCaptureDecision::Captured { .. }
        ));
        advance_broker_admission_operation(
            &operation_store,
            &ids.operation_id,
            AdmissionOperationState::DispatchCommitted,
            AdmissionDispatchState::Committed,
        );
        advance_broker_admission_operation(
            &operation_store,
            &ids.operation_id,
            AdmissionOperationState::OutcomeUnknownAfterDispatch,
            AdmissionDispatchState::OutcomeUnknown,
        );
        drop(adapter);

        let restarted = must(
            AuthoritativeBrokerExecutionAdapter::open(
                &authority_path,
                &operation_path,
                AuthoritativeBrokerExecutionConfig {
                    revocation_authority_domain: "combined-sqlite-production".to_string(),
                    supplemental_verifier_id: "broker-capability-verifier-v1".to_string(),
                    maximum_pending_admissions: 1,
                },
                registration,
                test_migration_enforcer(),
            ),
            "restart outcome-unknown adapter",
        );
        assert_eq!(
            must(
                restarted.registry.operation_ids(),
                "list outcome-unknown registry",
            ),
            vec![ids.operation_id.clone()]
        );
        assert!(matches!(
            must(
                restarted.query_execution_hold(&QueryExecutionHoldRequest {
                    operation_id: ids.operation_id,
                    invocation_id: request.invocation_id,
                    parent_capability_id: request.capability.body.parent_capability_id,
                    broker_capability_id: request.capability.body.capability_id,
                    hold_id: ids.hold_id,
                    authorize_event_id: ids.authorize_event_id,
                    reverse_event_id: ids.reverse_event_id,
                    capture_event_id: ids.capture_event_id,
                }),
                "query outcome-unknown capture",
            ),
            ExecutionHoldState::Captured(_)
        ));
    }

    #[test]
    fn compensated_release_outbox_survives_both_release_crash_windows() {
        let directory = must(tempfile::tempdir(), "create compensation directory");
        let (_, _, request) = execution_fixture();
        let authority_path = directory.path().join("authority.sqlite3");
        let operation_path = directory.path().join("operations.sqlite3");
        let registration = LoseFirstReleaseAcknowledgement::production_fixture();
        let registration_port: Arc<dyn BrokerAttemptRegistrationPort> = registration.clone();
        let request_digest = must(broker_request_digest(&request), "digest broker request");
        let provisional_ids = must(
            derive_attempt_ids(
                &request.capability.body.capability_id,
                &request.invocation_id,
                &request.proof.body.nonce,
                &request_digest,
            ),
            "derive compensation attempt identifiers",
        );
        let request_binding_hash = "77".repeat(32);
        let (operation_store, operation) = create_broker_admission_operation(
            &operation_path,
            &request,
            &provisional_ids,
            &request_binding_hash,
        );
        let ids = must(
            derive_attempt_ids_for_operation(
                &request.capability.body.capability_id,
                &request.invocation_id,
                &request.proof.body.nonce,
                &request_digest,
                operation.operation_id(),
            ),
            "bind compensation attempt identifiers",
        );
        let adapter = must(
            AuthoritativeBrokerExecutionAdapter::open(
                &authority_path,
                &operation_path,
                AuthoritativeBrokerExecutionConfig {
                    revocation_authority_domain: "combined-sqlite-production".to_string(),
                    supplemental_verifier_id: "broker-capability-verifier-v1".to_string(),
                    maximum_pending_admissions: 1,
                },
                Arc::clone(&registration_port),
                test_migration_enforcer(),
            ),
            "open compensation adapter",
        );
        must(
            adapter.register_admission(
                &request,
                &ids.operation_id,
                SqliteCompositeAuthorizeInput {
                    operation_id: ids.operation_id.clone(),
                    request_binding_hash,
                    capability_id: request.capability.body.parent_capability_id.clone(),
                    grant_index: 0,
                    requested_exposure_units: 0,
                    max_cost_per_invocation: None,
                    max_total_cost_units: None,
                    hold_id: ids.hold_id,
                    event_id: ids.authorize_event_id,
                    authority: Some(BudgetEventAuthority {
                        authority_id: "budget-authority-production".to_string(),
                        lease_id: "lease-production-compensated".to_string(),
                        lease_epoch: 7,
                    }),
                    invocation_quotas: invocation_quotas(&request),
                    revocation_set: revocation_set(&request),
                    authorization_artifact_digests: vec![must(
                        capability_digest(&request.capability),
                        "digest compensation capability",
                    )],
                    partition_escrow_evidence: None,
                },
                None,
                Vec::new(),
                Some(0),
            ),
            "register compensated admission",
        );
        advance_broker_admission_operation(
            &operation_store,
            &ids.operation_id,
            AdmissionOperationState::CompensationPending,
            AdmissionDispatchState::NotStarted,
        );
        advance_broker_admission_operation(
            &operation_store,
            &ids.operation_id,
            AdmissionOperationState::CompensatedBeforeDispatch,
            AdmissionDispatchState::NotStarted,
        );
        drop(adapter);
        let restarted = must(
            AuthoritativeBrokerExecutionAdapter::open(
                &authority_path,
                &operation_path,
                AuthoritativeBrokerExecutionConfig {
                    revocation_authority_domain: "combined-sqlite-production".to_string(),
                    supplemental_verifier_id: "broker-capability-verifier-v1".to_string(),
                    maximum_pending_admissions: 1,
                },
                Arc::clone(&registration_port),
                test_migration_enforcer(),
            ),
            "restart compensated adapter",
        );
        assert_eq!(
            must(
                restarted.registry.operation_ids(),
                "list compensated release outbox",
            ),
            vec![ids.operation_id.clone()]
        );
        let acknowledgement_loss = rejected(
            restarted.drain_compensated_release_outbox(),
            "first drain must lose the broker release acknowledgement",
        );
        assert!(acknowledgement_loss
            .to_string()
            .contains("injected release acknowledgement loss"));
        assert_eq!(
            must(
                restarted.registry.operation_ids(),
                "list release outbox after acknowledgement loss",
            ),
            vec![ids.operation_id.clone()]
        );
        assert_eq!(
            must(
                registration.inner.store.load_attempt(&ids.attempt_id),
                "load broker tombstone after acknowledgement loss",
            )
            .unwrap_or_else(|| panic!("broker release tombstone is missing"))
            .state,
            AttemptState::Failed
        );

        drop(restarted);
        let recovered = must(
            AuthoritativeBrokerExecutionAdapter::open(
                &authority_path,
                &operation_path,
                AuthoritativeBrokerExecutionConfig {
                    revocation_authority_domain: "combined-sqlite-production".to_string(),
                    supplemental_verifier_id: "broker-capability-verifier-v1".to_string(),
                    maximum_pending_admissions: 1,
                },
                registration_port,
                test_migration_enforcer(),
            ),
            "restart after broker tombstone acknowledgement loss",
        );
        assert_eq!(
            must(
                recovered.drain_compensated_release_outbox(),
                "retry exact tombstone and drain compensated release outbox",
            ),
            1
        );
        assert!(must(
            recovered.registry.operation_ids(),
            "list drained compensated registry",
        )
        .is_empty());
    }

    #[test]
    fn startup_rejects_orphaned_pending_admission_after_partial_restore() {
        let directory = must(tempfile::tempdir(), "create partial restore directory");
        let (_, _, request) = execution_fixture();
        let authority_path = directory.path().join("authority.sqlite3");
        let operation_path = directory.path().join("operations.sqlite3");
        let restored_operation_path = directory.path().join("restored-operations.sqlite3");
        let registration = InProcessAttemptRegistration::production_fixture();
        let request_digest = must(broker_request_digest(&request), "digest broker request");
        let provisional_ids = must(
            derive_attempt_ids(
                &request.capability.body.capability_id,
                &request.invocation_id,
                &request.proof.body.nonce,
                &request_digest,
            ),
            "derive provisional attempt identifiers",
        );
        let request_binding_hash = "88".repeat(32);
        let (operation_store, operation) = create_broker_admission_operation(
            &operation_path,
            &request,
            &provisional_ids,
            &request_binding_hash,
        );
        let ids = must(
            derive_attempt_ids_for_operation(
                &request.capability.body.capability_id,
                &request.invocation_id,
                &request.proof.body.nonce,
                &request_digest,
                operation.operation_id(),
            ),
            "bind partial restore attempt identifiers",
        );
        let adapter = must(
            AuthoritativeBrokerExecutionAdapter::open(
                &authority_path,
                &operation_path,
                AuthoritativeBrokerExecutionConfig {
                    revocation_authority_domain: "combined-sqlite-production".to_string(),
                    supplemental_verifier_id: "broker-capability-verifier-v1".to_string(),
                    maximum_pending_admissions: 1,
                },
                Arc::clone(&registration),
                test_migration_enforcer(),
            ),
            "open partial restore adapter",
        );
        let prepared = must(
            adapter.prepare_admission(
                &request,
                &ids.operation_id,
                SqliteCompositeAuthorizeInput {
                    operation_id: ids.operation_id.clone(),
                    request_binding_hash,
                    capability_id: request.capability.body.parent_capability_id.clone(),
                    grant_index: 0,
                    requested_exposure_units: 0,
                    max_cost_per_invocation: None,
                    max_total_cost_units: None,
                    hold_id: ids.hold_id,
                    event_id: ids.authorize_event_id,
                    authority: Some(BudgetEventAuthority {
                        authority_id: "budget-authority-production".to_string(),
                        lease_id: "lease-production-partial-restore".to_string(),
                        lease_epoch: 7,
                    }),
                    invocation_quotas: invocation_quotas(&request),
                    revocation_set: revocation_set(&request),
                    authorization_artifact_digests: vec![must(
                        capability_digest(&request.capability),
                        "digest partial restore capability",
                    )],
                    partition_escrow_evidence: None,
                },
                None,
                Vec::new(),
                Some(0),
            ),
            "prepare partial restore admission",
        );
        must(
            adapter.registry.insert(
                &prepared.durable(),
                adapter.config.maximum_pending_admissions,
            ),
            "persist pending admission",
        );
        drop(adapter);
        drop(operation_store);

        let error = match AuthoritativeBrokerExecutionAdapter::open(
            &authority_path,
            &restored_operation_path,
            AuthoritativeBrokerExecutionConfig {
                revocation_authority_domain: "combined-sqlite-production".to_string(),
                supplemental_verifier_id: "broker-capability-verifier-v1".to_string(),
                maximum_pending_admissions: 1,
            },
            registration,
            test_migration_enforcer(),
        ) {
            Ok(_) => panic!("partial restore unexpectedly opened an orphaned pending admission"),
            Err(error) => error,
        };
        assert!(matches!(error, BrokerIntegrationError::Registry(_)));
        assert!(error
            .to_string()
            .contains("orphaned pending broker admission"));
    }

    #[test]
    fn runtime_construction_has_no_partial_or_mismatched_mode() {
        assert!(matches!(
            BrokerIntegrationRuntimeParts::default().build(),
            Err(BrokerIntegrationError::MissingComponent(
                "supplemental quota verifier"
            ))
        ));

        let directory = must(tempfile::tempdir(), "create runtime directory");
        let canonical_directory = must(
            std::fs::canonicalize(directory.path()),
            "canonicalize runtime directory",
        );
        let (issuer, _, _) = execution_fixture();
        let verifier = Arc::new(must(
            BrokerSupplementalQuotaVerifier::new(
                issuer.public_key(),
                "broker-service-production".to_string(),
                must(
                    SupplementalQuotaDestination::new("broker", "execute"),
                    "construct runtime supplemental destination",
                ),
                true,
                "broker-capability-verifier-v1".to_string(),
            ),
            "construct runtime supplemental verifier",
        ));
        let authority = Arc::new(must(
            AuthoritativeBrokerExecutionAdapter::open(
                canonical_directory.join("runtime-authority.sqlite3"),
                canonical_directory.join("runtime-operations.sqlite3"),
                AuthoritativeBrokerExecutionConfig {
                    revocation_authority_domain: "combined-sqlite-production".to_string(),
                    supplemental_verifier_id: "broker-capability-verifier-v1".to_string(),
                    maximum_pending_admissions: 16,
                },
                InProcessAttemptRegistration::production_fixture(),
                test_migration_enforcer(),
            ),
            "open runtime execution authority",
        ));
        let admin_approver = Keypair::from_seed(&[61; 32]);
        let admin_authorizer = Arc::new(must(
            GovernedAdminAuthorizer::open(
                canonical_directory.join("runtime-admin.sqlite3"),
                GovernedAdminPolicy {
                    trusted_approvers: vec![admin_approver.public_key()],
                    subject: Keypair::from_seed(&[62; 32]).public_key(),
                    threshold: 1,
                    maximum_token_lifetime_seconds: 60,
                },
                Keypair::from_seed(&[63; 32]).public_key(),
                Arc::new(FixedClock(100)),
            ),
            "open governed admin authorizer",
        ));
        let receipt_signer = Keypair::from_seed(&[63; 32]);
        let receipt_sink = Arc::new(must(
            SqliteBrokerReceiptSink::open(
                canonical_directory.join("runtime-receipts.sqlite3"),
                receipt_signer.public_key(),
            ),
            "open broker receipt sink",
        ));
        let runtime = must(
            BrokerIntegrationRuntimeParts::default()
                .with_supplemental_verifier(verifier)
                .with_execution_authority(authority)
                .with_admin_authorizer(admin_authorizer)
                .with_receipt_sink(receipt_sink)
                .build(),
            "build broker integration runtime",
        );
        assert_eq!(
            runtime
                .concrete_execution_authority()
                .supplemental_verifier_id(),
            "broker-capability-verifier-v1"
        );
    }

    #[test]
    fn production_admission_composition_routes_kernel_revocation_through_combined_authority() {
        let directory = must(tempfile::tempdir(), "create production composition directory");
        let canonical_directory = must(
            std::fs::canonicalize(directory.path()),
            "canonicalize production composition directory",
        );
        let (issuer, _, request) = execution_fixture();
        let authority_path = canonical_directory.join("combined-authority.sqlite3");
        let operation_path = canonical_directory.join("kernel-operations.sqlite3");
        let verifier = Arc::new(must(
            BrokerSupplementalQuotaVerifier::new(
                issuer.public_key(),
                "broker-service-production".to_string(),
                must(
                    SupplementalQuotaDestination::new("broker", "execute"),
                    "construct supplemental destination",
                ),
                true,
                "broker-capability-verifier-v1".to_string(),
            ),
            "construct runtime supplemental verifier",
        ));
        let authority = Arc::new(must(
            AuthoritativeBrokerExecutionAdapter::open(
                &authority_path,
                &operation_path,
                AuthoritativeBrokerExecutionConfig {
                    revocation_authority_domain: "combined-sqlite-production".to_string(),
                    supplemental_verifier_id: "broker-capability-verifier-v1".to_string(),
                    maximum_pending_admissions: 16,
                },
                InProcessAttemptRegistration::production_fixture(),
                test_migration_enforcer(),
            ),
            "open production execution authority",
        ));
        let admin_approver = Keypair::from_seed(&[64; 32]);
        let admin_authorizer = Arc::new(must(
            GovernedAdminAuthorizer::open(
                canonical_directory.join("admin.sqlite3"),
                GovernedAdminPolicy {
                    trusted_approvers: vec![admin_approver.public_key()],
                    subject: Keypair::from_seed(&[65; 32]).public_key(),
                    threshold: 1,
                    maximum_token_lifetime_seconds: 60,
                },
                Keypair::from_seed(&[66; 32]).public_key(),
                Arc::new(FixedClock(100)),
            ),
            "open production admin authorizer",
        ));
        let receipt_signer = Keypair::from_seed(&[67; 32]);
        let receipt_sink = Arc::new(must(
            SqliteBrokerReceiptSink::open(
                canonical_directory.join("broker-receipts.sqlite3"),
                receipt_signer.public_key(),
            ),
            "open production broker receipt sink",
        ));
        let runtime = must(
            BrokerIntegrationRuntimeParts::default()
                .with_supplemental_verifier(verifier)
                .with_execution_authority(Arc::clone(&authority))
                .with_admin_authorizer(admin_authorizer)
                .with_receipt_sink(receipt_sink)
                .build(),
            "build production admission composition",
        );

        let capability_id = request.capability.body.parent_capability_id.clone();
        let operation_id = "kernel-revocation-capture-operation".to_string();
        let request_binding_hash = "77".repeat(32);
        let hold_id = "kernel-revocation-capture-hold".to_string();
        let ancestor_ids = [
            "kernel-ancestor-root".to_string(),
            "kernel-ancestor-parent".to_string(),
        ];
        let revocation_set = revocation_set_with_ancestors(&request, &ancestor_ids);
        assert_eq!(
            revocation_set.ids(),
            &[
                request.capability.body.capability_id.clone(),
                request.capability.body.revocation_id.clone(),
                "kernel-ancestor-parent".to_string(),
                "kernel-ancestor-root".to_string(),
                capability_id.clone(),
            ]
        );
        let authorization_artifact_digest = must(
            capability_digest(&request.capability),
            "digest production broker capability",
        );
        let quota = must(
            BudgetInvocationQuota::from_persisted_parts(
                must(
                    BudgetQuotaKey::from_persisted_parts(
                        BudgetQuotaProfile::GrantInvocation,
                        capability_id.clone(),
                        Some(0),
                    ),
                    "construct production grant quota key",
                ),
                2,
            ),
            "construct production grant quota",
        );
        assert!(must(
            authority
                .budget
                .authorize_composite_hold(SqliteCompositeAuthorizeInput {
                    operation_id: operation_id.clone(),
                    request_binding_hash: request_binding_hash.clone(),
                    capability_id: capability_id.clone(),
                    grant_index: 0,
                    requested_exposure_units: 0,
                    max_cost_per_invocation: None,
                    max_total_cost_units: None,
                    hold_id: hold_id.clone(),
                    event_id: "kernel-revocation-authorize".to_string(),
                    authority: None,
                    invocation_quotas: vec![quota],
                    revocation_set: revocation_set.clone(),
                    authorization_artifact_digests: vec![
                        authorization_artifact_digest.clone(),
                    ],
                    partition_escrow_evidence: None,
                }),
            "authorize production capture hold",
        )
        .is_authorized());

        let combined = authority.combined_authority();
        assert_eq!(must(combined.authority_head(), "read initial authority head"), 0);
        let mut kernel = chio_kernel::ChioKernel::new(chio_kernel::KernelConfig {
            keypair: Keypair::from_seed(&[68; 32]),
            ca_public_keys: Vec::new(),
            max_delegation_depth: 4,
            policy_hash: "production-revocation-composition".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: true,
            allow_ephemeral_revocation_store: true,
            checkpoint_batch_size: 64,
            retention_config: None,
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
            deadlines: chio_kernel::HotPathDeadlineConfig::default(),
            dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode::Off,
        });
        kernel
            .set_admission_operation_store_handle(Arc::clone(&authority.admission_operations))
            .unwrap_or_else(|error| panic!("install operation store: {error}"));
        kernel.set_revocation_store(Box::new(must(
            chio_store_sqlite::SqliteRevocationStore::open(&authority_path),
            "open managed revocation reader",
        )));
        assert!(kernel.revoke_capability(&capability_id).is_err());

        must(
            runtime.install_kernel_admission(&mut kernel),
            "install production admission composition",
        );
        kernel
            .revoke_capability(&capability_id)
            .unwrap_or_else(|error| panic!("route kernel revocation: {error}"));
        assert!(must(
            combined.is_revoked(&capability_id),
            "read routed kernel revocation",
        ));
        assert_eq!(must(combined.revocation_head(), "read revocation head"), 1);
        assert_eq!(must(combined.authority_head(), "read revocation authority head"), 1);

        let revocation_commit: (String, Option<String>, i64) = must(
            Connection::open(&authority_path).and_then(|connection| {
                connection.query_row(
                    r#"
                    SELECT kind, capability_id, revocation_commit_index
                    FROM admission_authority_commits
                    WHERE authority_commit_index = 1
                    "#,
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
            }),
            "load indexed kernel revocation",
        );
        assert_eq!(
            revocation_commit,
            ("revocation".to_string(), Some(capability_id.clone()), 1)
        );

        let capture = must(
            combined.capture_admission(must(
                AdmissionCaptureRequest::new(AdmissionCaptureRequestInput {
                    operation_id,
                    budget: BudgetCaptureInvocationRequest {
                        capability_id: capability_id.clone(),
                        grant_index: 0,
                        hold_id: Some(hold_id),
                        event_id: Some("kernel-revocation-capture".to_string()),
                        authority: None,
                        admission_operation: Some(must(
                            BudgetAdmissionOperationBinding::new(
                                "kernel-revocation-capture-operation".to_string(),
                                request_binding_hash,
                            ),
                            "construct production capture binding",
                        )),
                    },
                    revocation_set: revocation_set.clone(),
                    bound_revocation_set_digest: revocation_set.digest().to_string(),
                    authorization_artifact_digests: vec![authorization_artifact_digest],
                    aggregate_root_capability_id: None,
                    aggregate_root_binding_digest: None,
                    last_observed_revocation_index: Some(1),
                }),
                "construct production capture request",
            )),
            "capture after kernel revocation",
        );
        let AdmissionCaptureDecision::Denied(denial) = capture else {
            panic!("capture must observe the kernel revocation");
        };
        assert_eq!(denial.revoked_ids(), &[capability_id]);
        assert_eq!(denial.metadata().revocation_commit_index(), 1);
        assert_eq!(denial.metadata().authority_commit_index(), 2);
        assert_eq!(must(combined.authority_head(), "read capture authority head"), 2);

        let commits: Vec<(i64, String, i64)> = must(
            Connection::open(&authority_path).and_then(|connection| {
                let mut statement = connection.prepare(
                    r#"
                    SELECT authority_commit_index, kind, revocation_commit_index
                    FROM admission_authority_commits
                    ORDER BY authority_commit_index
                    "#,
                )?;
                let rows = statement
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
                    .collect();
                rows
            }),
            "load linear authority commits",
        );
        assert_eq!(
            commits,
            vec![
                (1, "revocation".to_string(), 1),
                (2, "capture-denied".to_string(), 1),
            ]
        );
    }
}
