    type RealAdapterDurableExecutor = DurableActiveResponseExecutor<
        SqliteSecurityStateStore,
        RealAdapterEffects,
        NativeSecurityReceiptSink,
        RealAdapterAlerts,
    >;

    #[derive(Default)]
    struct RealAdapterEffectState {
        replay: BTreeMap<String, (EffectRequest, EffectResult)>,
        executions: usize,
    }

    #[derive(Default)]
    struct RealAdapterEffects {
        state: Mutex<RealAdapterEffectState>,
    }

    impl RealAdapterEffects {
        fn executions(&self) -> usize {
            self.state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .executions
        }
    }

    impl EffectPort for RealAdapterEffects {
        fn ensure_effects_ready(&self) -> PortResult<()> {
            self.state.lock().map(|_| ()).map_err(|_| PortError::unavailable())
        }

        fn execute(&self, request: &EffectRequest) -> PortResult<EffectResult> {
            let mut state = self.state.lock().map_err(|_| PortError::unavailable())?;
            if let Some((stored_request, stored_result)) =
                state.replay.get(request.idempotency_key.as_str())
            {
                if stored_request != request {
                    return Err(PortError::conflict());
                }
                return Ok(stored_result.clone());
            }
            let result = EffectResult {
                effect_id: request.effect_id.clone(),
                resulting_version_hash: match request.operation {
                    EffectOperation::Apply => Digest32::new([0xa1_u8; 32]),
                    EffectOperation::Remove => request.expected_version_hash,
                },
                applied: request.operation == EffectOperation::Apply,
            };
            state.executions = state.executions.saturating_add(1);
            state.replay.insert(
                request.idempotency_key.as_str().to_owned(),
                (request.clone(), result.clone()),
            );
            Ok(result)
        }

        fn load_result(&self, query: &EffectResultQuery) -> PortResult<EffectExecutionStatus> {
            let state = self.state.lock().map_err(|_| PortError::unavailable())?;
            let Some((request, result)) = state.replay.get(query.idempotency_key.as_str()) else {
                return Ok(EffectExecutionStatus::NotExecuted);
            };
            if request.tenant_id != query.tenant_id
                || request.action_id != query.action_id
                || request.plan_hash != query.plan_hash
                || request.effect_id != query.effect_id
                || request.effect_kind != query.effect_kind
                || request.target != query.target
                || request.plan_expires_at_unix_ms != query.plan_expires_at_unix_ms
                || request.operation != query.operation
                || request.expected_version_hash != query.expected_version_hash
                || request.contribution_hash != query.contribution_hash
                || request.scheduler_lease_owner_id != query.scheduler_lease_owner_id
                || request.scheduler_fencing_token != query.scheduler_fencing_token
            {
                return Err(PortError::conflict());
            }
            Ok(EffectExecutionStatus::Completed {
                result: result.clone(),
            })
        }
    }

    struct RealAdapterAlerts;

    impl SecurityAlertPort for RealAdapterAlerts {
        fn ensure_alerts_ready(&self) -> PortResult<()> {
            Ok(())
        }

        fn page(&self, alert: &SecurityAlert) -> PortResult<AlertDeliveryStatus> {
            Ok(AlertDeliveryStatus::Delivered {
                attempts: 1,
                delivered_at_unix_ms: alert.occurred_at_unix_ms,
            })
        }

        fn load_delivery(
            &self,
            query: &AlertDeliveryQuery,
        ) -> PortResult<Option<AlertDeliveryStatus>> {
            Ok(Some(AlertDeliveryStatus::Delivered {
                attempts: 1,
                delivered_at_unix_ms: query.alert.occurred_at_unix_ms,
            }))
        }
    }

    struct RealAdapterRecordingExecutor {
        inner: RealAdapterDurableExecutor,
        admission_operations: Arc<SqliteSecurityAdmissionOperationStore>,
        approvals: Arc<SqliteApprovalStore>,
        calls: AtomicUsize,
        fail_before_effect_once: AtomicBool,
        observed_commit_states: Mutex<Vec<(AdmissionOperationState, ReplayReservationState)>>,
    }

    impl RealAdapterRecordingExecutor {
        fn calls(&self) -> usize {
            self.calls.load(Ordering::Acquire)
        }

        fn observed_commit_states(
            &self,
        ) -> Vec<(AdmissionOperationState, ReplayReservationState)> {
            self.observed_commit_states
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }
    }

    impl ActiveResponseExecutorAuthority for RealAdapterRecordingExecutor {
        fn identity(&self) -> ActiveResponseExecutorAuthorityIdentity {
            self.inner.identity()
        }

        fn ensure_ready(&self) -> Result<(), ActiveResponseExecutorError> {
            self.inner.ensure_ready()
        }

        fn load_committed_active_response_dispatch(
            &self,
            tenant_id: &TenantId,
            dispatch_id: &RecordId,
        ) -> Result<Option<ActiveResponseCommittedDispatch>, ActiveResponseExecutorError> {
            self.inner
                .load_committed_active_response_dispatch(tenant_id, dispatch_id)
        }

        fn fence_uncommitted_automatic_dispatch(
            &self,
            response_plan: &chio_security_types::ResponsePlan,
            binding: &PreparedActiveResponseDispatchBinding,
        ) -> Result<AutomaticActiveResponseDispatchFenceOutcome, ActiveResponseExecutorError> {
            self.inner
                .fence_uncommitted_automatic_dispatch(response_plan, binding)
        }

        fn execute_active_response(
            &self,
            request: &ActiveResponseExecutionRequest,
        ) -> Result<ActiveResponseExecutionEvidence, ActiveResponseExecutorError> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            let ActiveResponseExecutionApproval::Governed {
                admission_operation_id,
                ..
            } = request.approval()
            else {
                return Err(ActiveResponseExecutorError::RejectedBeforeCommit(
                    "real adapter fixture requires governed dispatch".to_string(),
                ));
            };
            let operation = self
                .admission_operations
                .load(admission_operation_id)
                .map_err(|error| {
                    ActiveResponseExecutorError::NotReady(format!(
                        "load governed operation at dispatch: {error}"
                    ))
                })?
                .ok_or_else(|| {
                    ActiveResponseExecutorError::NotReady(
                        "governed operation missing at dispatch".to_string(),
                    )
                })?;
            let approval = self
                .approvals
                .get_approval_reservation(admission_operation_id)
                .map_err(|error| {
                    ActiveResponseExecutorError::NotReady(format!(
                        "load governed approval at dispatch: {error}"
                    ))
                })?
                .ok_or_else(|| {
                    ActiveResponseExecutorError::NotReady(
                        "governed approval missing at dispatch".to_string(),
                    )
                })?;
            self.observed_commit_states
                .lock()
                .map_err(|_| {
                    ActiveResponseExecutorError::NotReady(
                        "record governed dispatch state".to_string(),
                    )
                })?
                .push((operation.state(), approval.state()));
            if self.fail_before_effect_once.swap(false, Ordering::AcqRel) {
                return Err(ActiveResponseExecutorError::NotReady(
                    "injected failure after governed dispatch commitment".to_string(),
                ));
            }
            self.inner.execute_active_response(request)
        }
    }

    struct RealAdapterIssuanceAuthority;

    impl chio_kernel::CapabilityIssuanceAdmissionAuthority for RealAdapterIssuanceAuthority {
        fn ensure_ready(&self) -> PortResult<()> {
            Ok(())
        }

        fn authorize(&self, _: &IssuanceFreezeAdmissionQuery) -> PortResult<()> {
            Ok(())
        }
    }

    struct RealAdapterPreDispatch;

    impl SecurityPreDispatchHook for RealAdapterPreDispatch {
        fn name(&self) -> &str {
            "real-adapter-test-pre-dispatch"
        }

        fn commit(
            &self,
            _: &SecurityPreDispatchContext<'_>,
        ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
            Ok(None)
        }
    }

    #[derive(Clone)]
    struct RealAdapterPaths {
        admission_operations: PathBuf,
        approvals: PathBuf,
        budgets: PathBuf,
        responses: PathBuf,
        receipts: PathBuf,
    }

    impl RealAdapterPaths {
        fn in_directory(directory: &Path) -> Self {
            Self {
                admission_operations: directory.join("real-adapter-operations.sqlite3"),
                approvals: directory.join("real-adapter-approvals.sqlite3"),
                budgets: directory.join("real-adapter-budgets.sqlite3"),
                responses: directory.join("real-adapter-responses.sqlite3"),
                receipts: directory.join("real-adapter-receipts.sqlite3"),
            }
        }
    }

    struct RealAdapterRuntime {
        kernel: Arc<ChioKernel>,
        coordinator: Arc<KernelAttestedFindingResponseCoordinator>,
        admission_operations: Arc<SqliteSecurityAdmissionOperationStore>,
        approvals: Arc<SqliteApprovalStore>,
        effects: Arc<RealAdapterEffects>,
        executor: Arc<RealAdapterRecordingExecutor>,
    }

    struct RealAdapterFixture {
        _directory: tempfile::TempDir,
        paths: RealAdapterPaths,
        operator_authority: Keypair,
        executor_signer: Keypair,
        submission_authority: Keypair,
        threshold_policy_authority: Keypair,
        threshold_requirement: ThresholdApprovalRequirement,
        finding: AuthoritativeCorrelatedFindingEvidence,
        plan: ReservedAttestedFindingResponsePlan,
        artifacts: AttestedFindingAdmissionArtifacts,
        native_request: chio_kernel::ActiveResponseAdmissionRequest,
        governed_request: GovernedApprovalRequest,
        clock: Arc<FixedClock>,
        runtime: RealAdapterRuntime,
    }

    fn real_adapter_now_unix_seconds() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|error| panic!("real adapter clock before Unix epoch: {error}"))
            .as_secs()
    }

    fn real_adapter_finding(
        now_unix_ms: u64,
    ) -> AuthoritativeCorrelatedFindingEvidence {
        let occurred_at_unix_ms = now_unix_ms.saturating_sub(1);
        let body: CorrelatedFindingReceiptBody = serde_json::from_value(json!({
            "header": {
                "schema_version": 1,
                "occurred_at_unix_ms": occurred_at_unix_ms,
                "tenant_id": "tenant-events",
                "transition_id": "real-adapter-finding-transition",
                "prior_receipt_ids": ["real-adapter-source-receipt"]
            },
            "policy": {
                "policy_version": "policy-v1",
                "policy_hash": vec![31_u8; 32]
            },
            "finding_id": "real-adapter-finding",
            "finding_hash": vec![0x32_u8; 32],
            "rule_id": "real-adapter-rule",
            "rule_version_hash": vec![0x33_u8; 32],
            "group_key_hash": vec![0x34_u8; 32],
            "ordered_event_ids": ["real-adapter-event"],
            "ordered_evidence_digests": [vec![0x35_u8; 32]],
            "ordered_source_receipt_ids": ["real-adapter-source-receipt"],
            "first_event_time_unix_ms": occurred_at_unix_ms.saturating_sub(2),
            "last_event_time_unix_ms": occurred_at_unix_ms.saturating_sub(1),
            "lineage_seed": "real-adapter-lineage"
        }))
        .unwrap_or_else(|error| panic!("real adapter finding body: {error}"));
        let closed = ActiveDefenseReceiptBody::CorrelatedFinding(body.clone());
        let evidence_id = closed
            .evidence_id()
            .unwrap_or_else(|error| panic!("real adapter finding evidence id: {error}"));
        AuthoritativeCorrelatedFindingEvidence::from_verified_signed_receipt(evidence_id, body)
            .unwrap_or_else(|error| panic!("real adapter authoritative finding: {error}"))
    }

    fn real_adapter_capability(
        operator_authority: &Keypair,
        executor_subject: &chio_core::PublicKey,
        now_unix_seconds: u64,
    ) -> CapabilityToken {
        let scope = ChioScope {
            grants: vec![ToolGrant {
                server_id: CHIO_ACTIVE_RESPONSE_SERVER_ID.to_string(),
                tool_name: GovernedResponseEffect::ThrottleSession
                    .tool_name()
                    .to_string(),
                operations: vec![Operation::Invoke],
                constraints: Vec::new(),
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..ChioScope::default()
        };
        CapabilityToken::sign(
            CapabilityTokenBody {
                id: "real-adapter-operator-capability".to_string(),
                issuer: operator_authority.public_key(),
                subject: executor_subject.clone(),
                scope,
                issued_at: now_unix_seconds.saturating_sub(1),
                expires_at: now_unix_seconds.saturating_add(300),
                delegation_chain: Vec::new(),
                aggregate_invocation_budget: None,
            },
            operator_authority,
        )
        .unwrap_or_else(|error| panic!("sign real adapter capability: {error}"))
    }

    fn real_adapter_submission_proof(
        response_plan: &chio_security_types::ResponsePlan,
        governed_intent: &GovernedTransactionIntent,
        submitter: &Keypair,
    ) -> ActiveResponseSubmissionProof {
        let plan_body = response_plan.authorization_body();
        let canonical_plan_body = serde_json::to_value(&plan_body)
            .unwrap_or_else(|error| panic!("real adapter plan body: {error}"));
        let plan_body_hash = GovernedResponsePlanIntentBody::compute_plan_body_hash(
            &canonical_plan_body,
        )
        .unwrap_or_else(|error| panic!("real adapter plan body hash: {error}"));
        let governed_intent_hash = governed_intent
            .binding_hash()
            .unwrap_or_else(|error| panic!("real adapter governed intent hash: {error}"));
        let proof_expires_at_unix_ms = response_plan
            .created_at_unix_ms
            .checked_add(45_000)
            .unwrap_or_else(|| panic!("real adapter submission proof expiry overflow"));
        assert!(proof_expires_at_unix_ms < response_plan.expires_at_unix_ms);
        let body = ActiveResponseSubmissionProofBody::new(
            response_plan.action_id.clone(),
            response_plan.tenant_id.clone(),
            plan_body_hash,
            governed_intent_hash,
            submitter.public_key(),
            response_plan.created_at_unix_ms,
            proof_expires_at_unix_ms,
        )
        .unwrap_or_else(|error| panic!("real adapter submission proof body: {error}"));
        ActiveResponseSubmissionProof::sign_with_backend(
            body,
            &Ed25519Backend::new(submitter.clone()),
        )
        .unwrap_or_else(|error| panic!("sign real adapter submission proof: {error}"))
    }

    fn build_real_adapter_runtime(
        paths: &RealAdapterPaths,
        operator_authority: &Keypair,
        executor_signer: &Keypair,
        submission_authority: &Keypair,
        threshold_policy_authority: &Keypair,
        threshold_requirement: &ThresholdApprovalRequirement,
        finding: &AuthoritativeCorrelatedFindingEvidence,
        response_plan: &chio_security_types::ResponsePlan,
        clock: Arc<FixedClock>,
        fail_before_effect_once: bool,
    ) -> RealAdapterRuntime {
        let admission_operations = Arc::new(
            SqliteSecurityAdmissionOperationStore::open(&paths.admission_operations)
                .unwrap_or_else(|error| panic!("open real adapter operation store: {error}")),
        );
        let approvals = Arc::new(
            SqliteApprovalStore::open(&paths.approvals)
                .unwrap_or_else(|error| panic!("open real adapter approval store: {error}")),
        );
        let budgets = Arc::new(
            SqliteBudgetStore::open(&paths.budgets)
                .unwrap_or_else(|error| panic!("open real adapter budget store: {error}")),
        );
        let responses = Arc::new(
            SqliteSecurityStateStore::open(&paths.responses)
                .unwrap_or_else(|error| panic!("open real adapter response store: {error}")),
        );
        let receipt_store = Arc::new(
            SqliteReceiptStore::open(&paths.receipts)
                .unwrap_or_else(|error| panic!("open real adapter receipt store: {error}")),
        );
        let receipt_index: Arc<dyn chio_kernel::IndexedSecurityEvidenceStore> = receipt_store;
        let receipt_signer: Arc<dyn chio_core::SigningBackend> =
            Arc::new(Ed25519Backend::new(executor_signer.clone()));
        let receipts = Arc::new(NativeSecurityReceiptSink::new(
            receipt_index,
            receipt_signer,
        ));
        let effects = Arc::new(RealAdapterEffects::default());
        let alerts = Arc::new(RealAdapterAlerts);
        let executor_identity = ActiveResponseExecutorAuthorityIdentity::new(
            executor_signer.public_key(),
            1,
        )
        .unwrap_or_else(|error| panic!("real adapter executor identity: {error}"));
        let durable_executor = DurableActiveResponseExecutor::new(
            executor_identity.clone(),
            LeaseOwnerId::new("real-adapter-executor")
                .unwrap_or_else(|error| panic!("real adapter lease owner: {error}")),
            responses,
            Arc::clone(&effects),
            receipts,
            alerts,
            Arc::clone(&clock) as Arc<dyn SecurityClock>,
            30_000,
        )
        .unwrap_or_else(|error| panic!("construct real adapter executor: {error}"));
        let executor = Arc::new(RealAdapterRecordingExecutor {
            inner: durable_executor,
            admission_operations: Arc::clone(&admission_operations),
            approvals: Arc::clone(&approvals),
            calls: AtomicUsize::new(0),
            fail_before_effect_once: AtomicBool::new(fail_before_effect_once),
            observed_commit_states: Mutex::new(Vec::new()),
        });

        let policy_hash = hex::encode(response_plan.policy_hash.as_bytes());
        let policy_version = response_plan.policy_version.clone();
        let approval_policy_id = match &response_plan.approval_requirement {
            ResponseApprovalRequirement::Governed { policy_id } => policy_id.clone(),
            ResponseApprovalRequirement::Automatic => {
                panic!("real adapter response plan must be governed")
            }
        };
        let active_response_policy_hash = policy_hash.clone();
        let active_response_requirement = Arc::new(
            move |_: &chio_kernel::ActiveResponsePolicyRequest, received: &str| {
                if received != active_response_policy_hash {
                    return Err(ActiveResponsePolicyResolutionError::StalePolicy {
                        expected: active_response_policy_hash.clone(),
                        received: received.to_string(),
                    });
                }
                Ok(ActiveResponseRequirement::governed(
                    active_response_policy_hash.clone(),
                    policy_version.clone(),
                    approval_policy_id.clone(),
                    60_000,
                ))
            },
        );
        let threshold_requirement = threshold_requirement.clone();
        let threshold_resolver = Arc::new(
            move |received: &str, _: &str, _: &str| {
                if received != threshold_requirement.policy_hash {
                    return Err(format!(
                        "stale threshold policy: expected {}, received {received}",
                        threshold_requirement.policy_hash
                    ));
                }
                Ok(Some(threshold_requirement.clone()))
            },
        );

        let mut kernel = ChioKernel::new(KernelConfig {
            keypair: operator_authority.clone(),
            ca_public_keys: Vec::new(),
            max_delegation_depth: 5,
            policy_hash,
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: true,
            allow_ephemeral_revocation_store: true,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
            memory_budget: MemoryBudgetConfig::defaults(),
            deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        });
        kernel
            .set_active_response_submission_authority(submission_authority.public_key())
            .unwrap_or_else(|error| panic!("install real adapter submission authority: {error}"));

        let budget_authority: Arc<dyn chio_kernel::budget_store::BudgetStore> = budgets;
        let approval_authority: Arc<dyn ApprovalStore> = approvals.clone();
        let operation_authority: Arc<dyn AdmissionOperationStore> =
            admission_operations.clone();
        let executor_authority: Arc<dyn ActiveResponseExecutorAuthority> = executor.clone();
        kernel
            .publish_governed_security_runtime(GovernedSecurityRuntimePublication {
                active_response_requirement_resolver: active_response_requirement,
                threshold_approval_requirement_resolver: threshold_resolver,
                admission_operation_store: operation_authority,
                approval_store: approval_authority,
                budget_store: budget_authority,
                finding_authority: Arc::new(TestFindingAuthority::new(std::slice::from_ref(
                    finding,
                ))),
                executor_authority,
                capability_issuance_admission_authority: Arc::new(
                    RealAdapterIssuanceAuthority,
                ),
                threshold_policy_authorities: vec![
                    threshold_policy_authority.public_key(),
                ],
                guards: Vec::new(),
                pre_dispatch_hook: Arc::new(RealAdapterPreDispatch),
                post_invocation_pipeline: chio_kernel::PostInvocationPipeline::new(),
            })
            .unwrap_or_else(|error| panic!("publish real adapter governed runtime: {error}"));
        let kernel = Arc::new(kernel);
        let coordinator = Arc::new(KernelAttestedFindingResponseCoordinator::new_unbound(
            executor_identity,
            Arc::clone(&clock) as Arc<dyn SecurityClock>,
        ));
        coordinator
            .bind_kernel(Arc::clone(&kernel))
            .unwrap_or_else(|error| panic!("bind real adapter kernel: {error}"));
        RealAdapterRuntime {
            kernel,
            coordinator,
            admission_operations,
            approvals,
            effects,
            executor,
        }
    }

    fn real_adapter_fixture() -> RealAdapterFixture {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| panic!("create real adapter directory: {error}"));
        let paths = RealAdapterPaths::in_directory(directory.path());
        let now_unix_seconds = real_adapter_now_unix_seconds();
        let now_unix_ms = now_unix_seconds
            .checked_mul(1_000)
            .unwrap_or_else(|| panic!("real adapter current time exceeds milliseconds"));
        let operator_authority = Keypair::from_seed(&[0x81_u8; 32]);
        let executor_signer = Keypair::from_seed(&[0x82_u8; 32]);
        let submitter = Keypair::from_seed(&[0x83_u8; 32]);
        let submission_authority = Keypair::from_seed(&[0x84_u8; 32]);
        let threshold_policy_authority = Keypair::from_seed(&[0x85_u8; 32]);
        let approver = Keypair::from_seed(&[0x86_u8; 32]);
        let capability = real_adapter_capability(
            &operator_authority,
            &executor_signer.public_key(),
            now_unix_seconds,
        );
        let capability_hash = authorization_capability_hash(&capability)
            .unwrap_or_else(|error| panic!("real adapter capability hash: {error}"));
        let capability_digest = super::digest_from_canonical_hex(&capability_hash)
            .unwrap_or_else(|error| panic!("real adapter capability digest: {error}"));

        let finding = real_adapter_finding(now_unix_ms);
        let publication = build_attested_finding_batch_publication(std::slice::from_ref(&finding))
            .unwrap_or_else(|error| panic!("real adapter batch publication: {error}"));
        let binding = publication
            .body
            .bindings
            .as_slice()
            .first()
            .cloned()
            .unwrap_or_else(|| panic!("real adapter binding missing"));
        let canonical_contribution = CanonicalBody::new(
            canonical_json_bytes(&json!({ "maximum_invocations": 1 }))
                .unwrap_or_else(|error| panic!("real adapter contribution: {error}")),
        )
        .unwrap_or_else(|error| panic!("real adapter canonical contribution: {error}"));
        let contribution_hash =
            Digest32::new(*chio_core::sha256(canonical_contribution.as_bytes()).as_bytes());
        let approval_policy_id = record("real-adapter-approval-policy");
        let response_plan = chio_quarantine::build_response_plan(
            chio_security_types::ResponsePlanInput {
                action_id: binding.action_id.clone(),
                trigger_finding_id: binding.finding_id.clone(),
                trigger_finding_hash: binding.finding_hash,
                trigger_finding_receipt_id: binding.evidence_id.clone(),
                tenant_id: binding.tenant_id.clone(),
                policy_version: finding.body().policy.policy_version.clone(),
                policy_hash: finding.body().policy.policy_hash,
                affected_ids: vec![record("real-adapter-affected-session")],
                effects: vec![ResponseEffectSpec {
                    kind: ResponseEffectKind::ThrottleSession,
                    target: ResponseTarget::Session {
                        session_id: SessionId::new("real-adapter-session")
                            .unwrap_or_else(|error| panic!("real adapter session: {error}")),
                    },
                    canonical_contribution,
                    contribution_hash,
                    observed_base_version_hash: Digest32::new([0x44_u8; 32]),
                }],
                ttl_ms: 60_000,
                created_at_unix_ms: now_unix_ms,
                operator_capability: OperatorCapabilityBinding {
                    capability_id: record(&capability.id),
                    capability_digest,
                    expires_at_unix_ms: capability
                        .expires_at
                        .checked_mul(1_000)
                        .unwrap_or_else(|| panic!("real adapter capability expiry overflow")),
                    executor_subject: record(&capability.subject.to_hex()),
                },
                approval_requirement: ResponseApprovalRequirement::Governed {
                    policy_id: approval_policy_id.clone(),
                },
                submitter: record(&submitter.public_key().to_hex()),
                reason_hash: Digest32::new([0x45_u8; 32]),
            },
        )
        .unwrap_or_else(|error| panic!("build real adapter response plan: {error}"));

        let plan_body = response_plan.authorization_body();
        let canonical_plan_body = serde_json::to_value(&plan_body)
            .unwrap_or_else(|error| panic!("real adapter canonical plan body: {error}"));
        let plan_body_hash = GovernedResponsePlanIntentBody::compute_plan_body_hash(
            &canonical_plan_body,
        )
        .unwrap_or_else(|error| panic!("real adapter governed plan hash: {error}"));
        assert_eq!(
            super::digest_from_canonical_hex(&plan_body_hash)
                .unwrap_or_else(|error| panic!("real adapter plan digest: {error}")),
            response_plan.plan_hash
        );
        let governed_intent = GovernedTransactionIntent::active_response_plan(
            GovernedResponsePlanIntentBody::new(
                CHIO_RESPONSE_PLAN_SCHEMA,
                response_plan.action_id.as_str(),
                capability.id.clone(),
                capability_hash.clone(),
                capability.expires_at,
                capability.subject.clone(),
                canonical_plan_body,
                plan_body_hash.clone(),
                json!({
                    "affectedSetHash": hex::encode(response_plan.affected_set_hash.as_bytes()),
                }),
                vec![GovernedResponseEffect::ThrottleSession],
                response_plan.expires_at_unix_ms / 1_000,
                json!({ "responsePlanHash": plan_body_hash }),
            )
            .unwrap_or_else(|error| panic!("real adapter governed intent body: {error}")),
        );
        let submission_proof =
            real_adapter_submission_proof(&response_plan, &governed_intent, &submitter);
        let authorization = ActiveResponseAuthorizationRequest::new(
            capability.clone(),
            plan_body,
            governed_intent.clone(),
            submission_proof.clone(),
        )
        .unwrap_or_else(|error| panic!("real adapter authorization request: {error}"));

        let policy_hash = hex::encode(response_plan.policy_hash.as_bytes());
        let threshold_requirement = ThresholdApprovalRequirement::new(
            policy_hash.clone(),
            1,
            vec![ThresholdApproverIdentity {
                identifier: "real-adapter-approver".to_string(),
                public_key: approver.public_key(),
            }],
            "real-adapter-directory-v1".to_string(),
            120,
        )
        .unwrap_or_else(|error| panic!("real adapter threshold requirement: {error}"));
        let governed_intent_hash = governed_intent
            .binding_hash()
            .unwrap_or_else(|error| panic!("real adapter intent binding: {error}"));
        let proposal = ThresholdApprovalProposal::sign(
            ThresholdApprovalProposalBody {
                schema: chio_core::capability::governance::THRESHOLD_APPROVAL_PROPOSAL_SCHEMA
                    .to_string(),
                proposal_id: "real-adapter-proposal".to_string(),
                request_id: response_plan.action_id.as_str().to_string(),
                governed_intent_hash: governed_intent_hash.clone(),
                subject: capability.subject.clone(),
                authorizing_capability_digest: capability_hash,
                policy_hash,
                threshold: threshold_requirement.required(),
                eligible_set_digest: threshold_requirement.eligible_set_digest().to_string(),
                proposal_created_at: now_unix_seconds,
                proposal_deadline: ThresholdApprovalProposalBody::proposal_deadline(
                    now_unix_seconds,
                    threshold_requirement.proposal_timeout_seconds(),
                    capability.expires_at,
                    Some(response_plan.expires_at_unix_ms / 1_000),
                )
                .unwrap_or_else(|error| panic!("real adapter proposal deadline: {error}")),
                policy_authority: threshold_policy_authority.public_key(),
            },
            &threshold_policy_authority,
        )
        .unwrap_or_else(|error| panic!("sign real adapter proposal: {error}"));
        let approval_token = GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: "real-adapter-approval-token".to_string(),
                approver: approver.public_key(),
                subject: capability.subject.clone(),
                governed_intent_hash,
                threshold_proposal_hash: Some(
                    proposal
                        .proposal_hash()
                        .unwrap_or_else(|error| panic!("real adapter proposal hash: {error}")),
                ),
                request_id: response_plan.action_id.as_str().to_string(),
                issued_at: now_unix_seconds,
                expires_at: proposal.body().proposal_deadline,
                decision: GovernedApprovalDecision::Approved,
            },
            &approver,
        )
        .unwrap_or_else(|error| panic!("sign real adapter approval: {error}"));
        let approval_tokens = vec![approval_token];
        let threshold_proposal = Some(proposal);
        let artifact_ref = AdmissionArtifactRef::new("real-adapter-admission-artifacts")
            .unwrap_or_else(|error| panic!("real adapter artifact ref: {error}"));
        let payload_digest = chio_kernel::active_response_admission_artifact_payload_digest(
            &response_plan.authorization_body(),
            &capability,
            &governed_intent,
            &submission_proof,
            &threshold_proposal,
            &approval_tokens,
        )
        .unwrap_or_else(|error| panic!("real adapter artifact payload digest: {error}"));
        let proof_digest = chio_kernel::active_response_submission_proof_digest(&submission_proof)
            .unwrap_or_else(|error| panic!("real adapter proof digest: {error}"));
        let attestation_body = ActiveResponseArtifactAuthorityAttestationBody {
            schema: chio_kernel::ACTIVE_RESPONSE_ARTIFACT_AUTHORITY_ATTESTATION_SCHEMA
                .to_string(),
            artifact_ref: artifact_ref.clone(),
            action_id: response_plan.action_id.clone(),
            tenant_id: response_plan.tenant_id.clone(),
            artifact_payload_digest: payload_digest,
            submission_proof_digest: proof_digest,
            plan_body_hash: super::digest_from_canonical_hex(
                &submission_proof.body.plan_body_hash,
            )
            .unwrap_or_else(|error| panic!("real adapter proof plan hash: {error}")),
            governed_intent_hash: super::digest_from_canonical_hex(
                &submission_proof.body.governed_intent_hash,
            )
            .unwrap_or_else(|error| panic!("real adapter proof intent hash: {error}")),
            submitter: submission_proof.body.submitter.clone(),
            authority: submission_authority.public_key(),
            issued_at_unix_ms: submission_proof.body.issued_at_unix_ms,
            expires_at_unix_ms: submission_proof.body.expires_at_unix_ms,
        };
        let authority_attestation =
            ActiveResponseArtifactAuthorityAttestation::sign_with_backend(
                attestation_body,
                &Ed25519Backend::new(submission_authority.clone()),
            )
            .unwrap_or_else(|error| panic!("sign real adapter attestation: {error}"));
        let native_request = chio_kernel::ActiveResponseAdmissionRequest::new(
            response_plan.clone(),
            authorization,
            artifact_ref.clone(),
            authority_attestation.clone(),
            threshold_proposal.clone(),
            approval_tokens.clone(),
        )
        .unwrap_or_else(|error| panic!("real adapter native request: {error}"));
        let artifacts = AttestedFindingAdmissionArtifacts::new(
            artifact_ref.clone(),
            capability,
            governed_intent,
            submission_proof,
            authority_attestation,
            threshold_proposal,
            approval_tokens,
        );
        let artifact_digest = artifacts
            .canonical_digest(&response_plan)
            .unwrap_or_else(|error| panic!("real adapter artifact digest: {error}"));
        let plan = ReservedAttestedFindingResponsePlan {
            finding: finding.clone(),
            batch_id: publication.body.batch_id.clone(),
            ordinal: 0,
            binding,
            response_plan,
            admission_artifact_ref: artifact_ref,
            admission_artifact_digest: Some(artifact_digest),
        };
        let governed_request = governed_approval_request_from_native(&native_request)
            .unwrap_or_else(|error| panic!("real adapter portable projection: {error}"));
        let execution_now_unix_ms = plan
            .response_plan()
            .created_at_unix_ms
            .checked_add(30_000)
            .unwrap_or_else(|| panic!("real adapter execution time overflow"));
        assert!(execution_now_unix_ms < plan.response_plan().expires_at_unix_ms);
        let clock = Arc::new(FixedClock(execution_now_unix_ms));
        let runtime = build_real_adapter_runtime(
            &paths,
            &operator_authority,
            &executor_signer,
            &submission_authority,
            &threshold_policy_authority,
            &threshold_requirement,
            &finding,
            plan.response_plan(),
            Arc::clone(&clock),
            true,
        );
        RealAdapterFixture {
            _directory: directory,
            paths,
            operator_authority,
            executor_signer,
            submission_authority,
            threshold_policy_authority,
            threshold_requirement,
            finding,
            plan,
            artifacts,
            native_request,
            governed_request,
            clock,
            runtime,
        }
    }

    fn real_adapter_prepared_operation_id(
        prepared: &PreparedAttestedFindingResponse,
    ) -> String {
        let PreparedAttestedFindingResponse::Kernel(prepared) = prepared else {
            panic!("real adapter preparation must retain a kernel admission");
        };
        let PreparedActiveResponseAdmission::Governed(reservation) = &prepared.prepared else {
            panic!("real adapter preparation must be governed");
        };
        reservation.operation_id().to_string()
    }

    fn real_adapter_table_count(path: &Path, table: &str) -> u64 {
        let connection = Connection::open(path)
            .unwrap_or_else(|error| panic!("open real adapter database: {error}"));
        let count: i64 = connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0))
            .unwrap_or_else(|error| panic!("count real adapter {table}: {error}"));
        checked_sqlite_count(count, table)
    }

    fn real_adapter_mutation_snapshot(paths: &RealAdapterPaths) -> [u64; 5] {
        [
            real_adapter_table_count(&paths.admission_operations, "admission_operations"),
            real_adapter_table_count(
                &paths.approvals,
                "chio_hitl_operation_reservations",
            ),
            real_adapter_table_count(
                &paths.approvals,
                "chio_hitl_operation_reservation_tokens",
            ),
            real_adapter_table_count(&paths.budgets, "budget_authorization_holds"),
            real_adapter_table_count(&paths.budgets, "budget_hold_quota_members"),
        ]
    }

    fn real_adapter_budget_and_replay_snapshot(paths: &RealAdapterPaths) -> [u64; 9] {
        [
            real_adapter_table_count(
                &paths.approvals,
                "chio_hitl_operation_reservations",
            ),
            real_adapter_table_count(
                &paths.approvals,
                "chio_hitl_operation_reservation_tokens",
            ),
            real_adapter_table_count(&paths.approvals, "chio_hitl_consumed_tokens"),
            real_adapter_table_count(&paths.budgets, "budget_authorization_holds"),
            real_adapter_table_count(
                &paths.budgets,
                "budget_hold_authorization_artifacts",
            ),
            real_adapter_table_count(&paths.budgets, "budget_mutation_events"),
            real_adapter_table_count(&paths.budgets, "budget_invocation_quotas"),
            real_adapter_table_count(
                &paths.budgets,
                "budget_event_authorization_artifacts",
            ),
            real_adapter_table_count(&paths.budgets, "budget_hold_quota_members"),
        ]
    }

    #[test]
    fn authority_artifact_draft_validator_rederives_all_static_bindings() {
        let fixture = real_adapter_fixture();
        let AttestedFindingAdmissionArtifactPayload::Kernel(payload) = &fixture.artifacts.payload
        else {
            panic!("real adapter fixture must carry kernel artifacts");
        };
        let response_plan = fixture.plan.response_plan();
        let draft = crate::security::ActiveResponseAdmissionArtifactsDraftWire {
            action_id: response_plan.action_id.clone(),
            plan_hash: response_plan.plan_hash,
            admission_artifact_ref: payload.artifact_ref.clone(),
            operator_capability: payload.operator_capability.clone(),
            governed_intent: payload.governed_intent.clone(),
            submission_proof: payload.submission_proof.clone(),
            authority_attestation_body: payload.authority_attestation.body.clone(),
            threshold_proposal: payload.threshold_proposal.clone(),
            approval_tokens: crate::security::ActiveResponseApprovalTokens::new(
                payload.approval_tokens.clone(),
            )
            .unwrap_or_else(|error| panic!("bound approval tokens: {error}")),
        };
        crate::security::validate_active_response_artifacts_draft(
            response_plan,
            &payload.artifact_ref,
            &fixture.submission_authority.public_key(),
            &draft,
        )
        .unwrap_or_else(|error| panic!("validate exact authority draft: {error}"));

        let mut changed = draft;
        changed.authority_attestation_body.artifact_payload_digest = Digest32::new([0x71; 32]);
        assert!(crate::security::validate_active_response_artifacts_draft(
            response_plan,
            &payload.artifact_ref,
            &fixture.submission_authority.public_key(),
            &changed,
        )
        .is_err());
    }

    #[test]
    fn real_kernel_approval_adapter_prepares_reconstructs_commits_and_cold_resumes_once() {
        let fixture = real_adapter_fixture();
        let prepared = fixture
            .runtime
            .coordinator
            .prepare_admission(&fixture.plan, fixture.artifacts.clone())
            .unwrap_or_else(|error| panic!("real adapter prepare: {error}"));
        let operation_id = real_adapter_prepared_operation_id(&prepared);
        let binding = prepared
            .durable_dispatch_binding(fixture.plan.response_plan())
            .unwrap_or_else(|error| panic!("real adapter durable binding: {error}"));
        let PreparedAttestedFindingResponse::Kernel(kernel_prepared) = &prepared else {
            panic!("real adapter preparation must retain the native request");
        };
        let portable_reservation = kernel_prepared
            .governed_approval
            .as_ref()
            .unwrap_or_else(|| panic!("real adapter portable reservation missing"));
        assert_eq!(
            kernel_prepared.request.response_plan(),
            fixture.native_request.response_plan()
        );
        assert_eq!(
            governed_approval_request_from_native(&kernel_prepared.request)
                .unwrap_or_else(|error| panic!("project retained real adapter request: {error}")),
            fixture.governed_request
        );
        assert_eq!(portable_reservation.request, fixture.governed_request);
        assert_eq!(portable_reservation.prepared_dispatch_binding, binding);
        assert_eq!(
            portable_reservation.expires_at_unix_ms,
            fixture.governed_request.proposal_expires_at_unix_ms
        );
        let reserved_operation = fixture
            .runtime
            .admission_operations
            .load(&operation_id)
            .unwrap_or_else(|error| panic!("load reserved real adapter operation: {error}"))
            .unwrap_or_else(|| panic!("reserved real adapter operation missing"));
        assert_eq!(
            reserved_operation.state(),
            AdmissionOperationState::ApprovalReserved
        );
        let reserved_approval = fixture
            .runtime
            .approvals
            .get_approval_reservation(&operation_id)
            .unwrap_or_else(|error| panic!("load reserved real adapter approval: {error}"))
            .unwrap_or_else(|| panic!("reserved real adapter approval missing"));
        assert_eq!(reserved_approval.state(), ReplayReservationState::Reserved);
        assert_eq!(real_adapter_mutation_snapshot(&fixture.paths), [1, 1, 1, 0, 0]);
        assert_eq!(fixture.runtime.effects.executions(), 0);
        assert_eq!(fixture.runtime.executor.calls(), 0);

        let recreated = Arc::new(KernelAttestedFindingResponseCoordinator::new_unbound(
            fixture.runtime.executor.identity(),
            Arc::clone(&fixture.clock) as Arc<dyn SecurityClock>,
        ));
        recreated
            .bind_kernel(Arc::clone(&fixture.runtime.kernel))
            .unwrap_or_else(|error| panic!("bind recreated real adapter: {error}"));
        let reconstructed = match recreated
            .reconstruct_pre_dispatch(
                &fixture.plan,
                fixture.artifacts.clone(),
                &binding,
            )
            .unwrap_or_else(|error| panic!("reconstruct real adapter preparation: {error}"))
        {
            AttestedFindingPreDispatchReconstruction::Prepared(prepared) => *prepared,
            AttestedFindingPreDispatchReconstruction::NotPrepared => {
                panic!("real adapter reservation disappeared during reconstruction")
            }
        };
        assert_eq!(
            reconstructed
                .durable_dispatch_binding(fixture.plan.response_plan())
                .unwrap_or_else(|error| panic!("reconstructed real adapter binding: {error}")),
            binding
        );
        assert_eq!(
            real_adapter_prepared_operation_id(&reconstructed),
            operation_id
        );
        assert_eq!(
            fixture
                .runtime
                .admission_operations
                .load(&operation_id)
                .unwrap_or_else(|error| {
                    panic!("load reconstructed real adapter operation: {error}")
                })
                .unwrap_or_else(|| panic!("reconstructed real adapter operation missing"))
                .state(),
            AdmissionOperationState::ApprovalReserved
        );
        assert_eq!(
            fixture
                .runtime
                .approvals
                .get_approval_reservation(&operation_id)
                .unwrap_or_else(|error| {
                    panic!("load reconstructed real adapter approval: {error}")
                })
                .unwrap_or_else(|| panic!("reconstructed real adapter approval missing"))
                .state(),
            ReplayReservationState::Reserved
        );
        assert_eq!(real_adapter_mutation_snapshot(&fixture.paths), [1, 1, 1, 0, 0]);
        assert_eq!(fixture.runtime.effects.executions(), 0);
        assert_eq!(fixture.runtime.executor.calls(), 0);

        let execution_error = rejected(
            recreated.execute_prepared(&fixture.plan, reconstructed),
            "injected pre-effect failure must interrupt real adapter execution",
        );
        assert_eq!(execution_error.kind(), PortErrorKind::Unavailable);
        assert_eq!(fixture.runtime.effects.executions(), 0);
        assert_eq!(fixture.runtime.executor.calls(), 1);
        assert_eq!(
            fixture.runtime.executor.observed_commit_states(),
            vec![(
                AdmissionOperationState::DispatchCommitted,
                ReplayReservationState::Committed,
            )]
        );
        let committed_operation = fixture
            .runtime
            .admission_operations
            .load(&operation_id)
            .unwrap_or_else(|error| panic!("load committed real adapter operation: {error}"))
            .unwrap_or_else(|| panic!("committed real adapter operation missing"));
        assert_eq!(
            committed_operation.state(),
            AdmissionOperationState::DispatchCommitted
        );
        let committed_approval = fixture
            .runtime
            .approvals
            .get_approval_reservation(&operation_id)
            .unwrap_or_else(|error| panic!("load committed real adapter approval: {error}"))
            .unwrap_or_else(|| panic!("committed real adapter approval missing"));
        assert_eq!(committed_approval.state(), ReplayReservationState::Committed);
        assert_eq!(real_adapter_mutation_snapshot(&fixture.paths), [1, 1, 1, 0, 0]);
        let original_effects = Arc::clone(&fixture.runtime.effects);
        drop(recreated);
        drop(fixture.runtime);

        let cold = build_real_adapter_runtime(
            &fixture.paths,
            &fixture.operator_authority,
            &fixture.executor_signer,
            &fixture.submission_authority,
            &fixture.threshold_policy_authority,
            &fixture.threshold_requirement,
            &fixture.finding,
            fixture.plan.response_plan(),
            Arc::clone(&fixture.clock),
            false,
        );
        let resumed = cold
            .coordinator
            .resume_dispatch_committed(fixture.plan.response_plan(), &binding)
            .unwrap_or_else(|error| panic!("cold resume real adapter dispatch: {error}"));
        let AttestedFindingDispatchCommittedResume::Completed(resumed) = resumed else {
            panic!("cold real adapter resume did not recover completion");
        };
        assert_eq!(resumed.dispatch_id(), &binding.dispatch_id);
        assert_eq!(
            resumed.outcome(),
            AttestedFindingResponseCompletionOutcome::Activated
        );
        assert_eq!(original_effects.executions(), 0);
        assert_eq!(cold.effects.executions(), 1);
        assert_eq!(cold.executor.calls(), 1);
        assert_eq!(
            cold.executor.observed_commit_states(),
            vec![(
                AdmissionOperationState::DispatchCommitted,
                ReplayReservationState::Committed,
            )]
        );
        assert_eq!(
            original_effects
                .executions()
                .saturating_add(cold.effects.executions()),
            1
        );
        assert_eq!(
            cold.admission_operations
                .load(&operation_id)
                .unwrap_or_else(|error| panic!("cold load real adapter operation: {error}"))
                .unwrap_or_else(|| panic!("cold real adapter operation missing"))
                .state(),
            AdmissionOperationState::Completed
        );
        assert_eq!(
            cold.approvals
                .get_approval_reservation(&operation_id)
                .unwrap_or_else(|error| panic!("cold load real adapter approval: {error}"))
                .unwrap_or_else(|| panic!("cold real adapter approval missing"))
                .state(),
            ReplayReservationState::Committed
        );
        assert_eq!(real_adapter_mutation_snapshot(&fixture.paths), [1, 1, 1, 0, 0]);
        let cold_effect_executions = cold.effects.executions();
        drop(cold);

        let replay = build_real_adapter_runtime(
            &fixture.paths,
            &fixture.operator_authority,
            &fixture.executor_signer,
            &fixture.submission_authority,
            &fixture.threshold_policy_authority,
            &fixture.threshold_requirement,
            &fixture.finding,
            fixture.plan.response_plan(),
            Arc::clone(&fixture.clock),
            false,
        );
        let replay_calls_before_resume = replay.executor.calls();
        assert_eq!(replay_calls_before_resume, 0);
        assert_eq!(replay.effects.executions(), 0);
        let replayed = replay
            .coordinator
            .resume_dispatch_committed(fixture.plan.response_plan(), &binding)
            .unwrap_or_else(|error| panic!("replay completed real adapter dispatch: {error}"));
        let AttestedFindingDispatchCommittedResume::Completed(replayed) = replayed else {
            panic!("completed real adapter replay lost terminal evidence");
        };
        assert_eq!(replayed.dispatch_id(), &binding.dispatch_id);
        assert_eq!(
            replayed.outcome(),
            AttestedFindingResponseCompletionOutcome::Activated
        );
        assert_eq!(replay.effects.executions(), 0);
        assert_eq!(
            replay.executor.calls(),
            replay_calls_before_resume.saturating_add(1)
        );
        assert_eq!(
            replay.executor.observed_commit_states(),
            vec![(
                AdmissionOperationState::Completed,
                ReplayReservationState::Committed,
            )]
        );
        assert_eq!(
            replay
                .admission_operations
                .load(&operation_id)
                .unwrap_or_else(|error| panic!("replay load real adapter operation: {error}"))
                .unwrap_or_else(|| panic!("replay real adapter operation missing"))
                .state(),
            AdmissionOperationState::Completed
        );
        assert_eq!(
            replay
                .approvals
                .get_approval_reservation(&operation_id)
                .unwrap_or_else(|error| panic!("replay load real adapter approval: {error}"))
                .unwrap_or_else(|| panic!("replay real adapter approval missing"))
                .state(),
            ReplayReservationState::Committed
        );
        assert_eq!(
            original_effects
                .executions()
                .saturating_add(cold_effect_executions)
                .saturating_add(replay.effects.executions()),
            1
        );
    }

    fn mutate_real_adapter_proposal_digest(request: &mut GovernedApprovalRequest) {
        request.proposal_digest = Digest32::new([0xb1_u8; 32]);
    }

    fn mutate_real_adapter_proposal_deadline(request: &mut GovernedApprovalRequest) {
        request.proposal_expires_at_unix_ms =
            request.proposal_expires_at_unix_ms.saturating_sub(1);
    }

    fn mutate_real_adapter_capability_digest(request: &mut GovernedApprovalRequest) {
        request.operator_capability_digest = Digest32::new([0xb2_u8; 32]);
    }

    fn mutate_real_adapter_governed_intent(request: &mut GovernedApprovalRequest) {
        request.governed_intent_hash = Digest32::new([0xb3_u8; 32]);
    }

    fn mutate_real_adapter_artifact_ref(request: &mut GovernedApprovalRequest) {
        request.admission_artifact.body.artifact_ref =
            AdmissionArtifactRef::new("substituted-real-adapter-artifact")
                .unwrap_or_else(|error| panic!("substituted real adapter artifact ref: {error}"));
    }

    fn mutate_real_adapter_artifact_digest(request: &mut GovernedApprovalRequest) {
        request.admission_artifact.body.artifact_digest = Digest32::new([0xb4_u8; 32]);
    }

    #[test]
    fn real_kernel_approval_adapter_rejects_projection_mutations_before_store_changes() {
        type ApprovalMutation = fn(&mut GovernedApprovalRequest);

        let fixture = real_adapter_fixture();
        let baseline = real_adapter_mutation_snapshot(&fixture.paths);
        let zero_budget_and_replay = real_adapter_budget_and_replay_snapshot(&fixture.paths);
        assert_eq!(zero_budget_and_replay, [0; 9]);
        let cases: [(&str, ApprovalMutation); 6] = [
            ("proposal_digest", mutate_real_adapter_proposal_digest),
            ("proposal_deadline", mutate_real_adapter_proposal_deadline),
            ("capability_digest", mutate_real_adapter_capability_digest),
            ("governed_intent", mutate_real_adapter_governed_intent),
            ("artifact_ref", mutate_real_adapter_artifact_ref),
            ("artifact_digest", mutate_real_adapter_artifact_digest),
        ];
        for (name, mutate) in cases {
            let mut substituted = fixture.governed_request.clone();
            mutate(&mut substituted);
            let verifier = KernelActiveResponseApprovalVerifier::for_prepare(
                fixture.runtime.kernel.as_ref(),
                &substituted,
                &fixture.native_request,
            );
            let error = rejected(
                verifier.verify_and_reserve(&substituted),
                "substituted real adapter projection must fail closed",
            );
            assert_eq!(
                error.kind(),
                PortErrorKind::IntegrityFailure,
                "unexpected error for {name} substitution"
            );
            assert_eq!(
                real_adapter_mutation_snapshot(&fixture.paths),
                baseline,
                "{name} substitution mutated a durable authority"
            );
            assert_eq!(
                real_adapter_budget_and_replay_snapshot(&fixture.paths),
                zero_budget_and_replay,
                "{name} substitution mutated a budget or replay authority"
            );
        }
        assert_eq!(baseline, [0, 0, 0, 0, 0]);
        assert_eq!(fixture.runtime.effects.executions(), 0);
        assert_eq!(fixture.runtime.executor.calls(), 0);
        assert!(fixture
            .runtime
            .admission_operations
            .list_unresolved(Some(AdmissionOperationKind::GovernedActiveResponse), 8)
            .unwrap_or_else(|error| panic!("list real adapter mutation operations: {error}"))
            .is_empty());

        let prepared = fixture
            .runtime
            .coordinator
            .prepare_admission(&fixture.plan, fixture.artifacts.clone())
            .unwrap_or_else(|error| panic!("prepare scoped mutation fixture: {error}"));
        let operation_id = real_adapter_prepared_operation_id(&prepared);
        let PreparedAttestedFindingResponse::Kernel(kernel_prepared) = &prepared else {
            panic!("scoped mutation fixture must retain a kernel preparation");
        };
        let retained = kernel_prepared
            .governed_approval
            .as_ref()
            .cloned()
            .unwrap_or_else(|| panic!("scoped mutation fixture reservation missing"));
        let prepared_native = kernel_prepared.prepared.clone();
        let reserved_baseline = real_adapter_mutation_snapshot(&fixture.paths);
        let reserved_budget_and_replay =
            real_adapter_budget_and_replay_snapshot(&fixture.paths);
        assert_eq!(reserved_baseline, [1, 1, 1, 0, 0]);
        assert_eq!(reserved_budget_and_replay, [1, 1, 0, 0, 0, 0, 0, 0, 0]);

        for (name, mutate) in cases {
            let mut substituted = fixture.governed_request.clone();
            mutate(&mut substituted);
            let mut substituted_reservation = retained.clone();
            substituted_reservation.request = substituted.clone();
            substituted_reservation.expires_at_unix_ms =
                substituted.proposal_expires_at_unix_ms;

            let reconstruct = KernelActiveResponseApprovalVerifier::for_reconstruction(
                fixture.runtime.kernel.as_ref(),
                &substituted,
                &fixture.native_request,
            );
            let reconstruct_error = rejected(
                reconstruct.reconstruct(&substituted, &substituted_reservation),
                "substituted reconstruction projection must fail closed",
            );
            assert_eq!(
                reconstruct_error.kind(),
                PortErrorKind::IntegrityFailure,
                "unexpected reconstruction error for {name} substitution"
            );

            let mutation = GovernedApprovalReservationMutation {
                reservation: substituted_reservation,
            };
            let commit = KernelActiveResponseApprovalVerifier::for_commit(
                fixture.runtime.kernel.as_ref(),
                &substituted,
                &fixture.native_request,
                prepared_native.clone(),
            );
            let commit_error = rejected(
                commit.commit(&mutation),
                "substituted commit projection must fail closed",
            );
            assert_eq!(
                commit_error.kind(),
                PortErrorKind::IntegrityFailure,
                "unexpected commit error for {name} substitution"
            );

            let cancel = KernelActiveResponseApprovalVerifier::for_cancel(
                fixture.runtime.kernel.as_ref(),
                &substituted,
                &fixture.native_request,
                prepared_native.clone(),
            );
            let cancel_error = rejected(
                cancel.cancel(&mutation),
                "substituted cancel projection must fail closed",
            );
            assert_eq!(
                cancel_error.kind(),
                PortErrorKind::IntegrityFailure,
                "unexpected cancel error for {name} substitution"
            );
            assert_eq!(
                real_adapter_mutation_snapshot(&fixture.paths),
                reserved_baseline,
                "scoped {name} substitution mutated a durable authority"
            );
            assert_eq!(
                real_adapter_budget_and_replay_snapshot(&fixture.paths),
                reserved_budget_and_replay,
                "scoped {name} substitution mutated a budget or replay authority"
            );
        }
        assert_eq!(
            fixture
                .runtime
                .admission_operations
                .load(&operation_id)
                .unwrap_or_else(|error| panic!("load scoped mutation operation: {error}"))
                .unwrap_or_else(|| panic!("scoped mutation operation missing"))
                .state(),
            AdmissionOperationState::ApprovalReserved
        );
        assert_eq!(
            fixture
                .runtime
                .approvals
                .get_approval_reservation(&operation_id)
                .unwrap_or_else(|error| panic!("load scoped mutation approval: {error}"))
                .unwrap_or_else(|| panic!("scoped mutation approval missing"))
                .state(),
            ReplayReservationState::Reserved
        );
        assert_eq!(fixture.runtime.effects.executions(), 0);
        assert_eq!(fixture.runtime.executor.calls(), 0);
    }
