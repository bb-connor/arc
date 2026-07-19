use crate::approval::{
    ApprovalFilter, ApprovalReservation, ApprovalSetReservationInput, ApprovalStoreError,
    ApprovalStoreProfile, ResolvedApproval,
};

struct DurableThresholdApprovalStore {
    inner: InMemoryApprovalStore,
    profile: ApprovalStoreProfile,
    lose_reserve_ack: std::sync::atomic::AtomicBool,
    lose_commit_ack: std::sync::atomic::AtomicBool,
    fail_commit_before_write: std::sync::atomic::AtomicBool,
    reserve_calls: std::sync::atomic::AtomicUsize,
    block_first_reserve: std::sync::Mutex<Option<std::sync::Arc<std::sync::Barrier>>>,
    reservation_readback_fault: std::sync::atomic::AtomicU8,
}

impl DurableThresholdApprovalStore {
    fn new() -> Self {
        Self {
            inner: InMemoryApprovalStore::new(),
            profile: ApprovalStoreProfile::SingleNodeDurable,
            lose_reserve_ack: std::sync::atomic::AtomicBool::new(false),
            lose_commit_ack: std::sync::atomic::AtomicBool::new(false),
            fail_commit_before_write: std::sync::atomic::AtomicBool::new(false),
            reserve_calls: std::sync::atomic::AtomicUsize::new(0),
            block_first_reserve: std::sync::Mutex::new(None),
            reservation_readback_fault: std::sync::atomic::AtomicU8::new(0),
        }
    }

    fn shared() -> Self {
        Self {
            inner: InMemoryApprovalStore::new(),
            profile: ApprovalStoreProfile::SharedLinearizable,
            lose_reserve_ack: std::sync::atomic::AtomicBool::new(false),
            lose_commit_ack: std::sync::atomic::AtomicBool::new(false),
            fail_commit_before_write: std::sync::atomic::AtomicBool::new(false),
            reserve_calls: std::sync::atomic::AtomicUsize::new(0),
            block_first_reserve: std::sync::Mutex::new(None),
            reservation_readback_fault: std::sync::atomic::AtomicU8::new(0),
        }
    }

    fn with_ack_loss() -> Self {
        Self {
            inner: InMemoryApprovalStore::new(),
            profile: ApprovalStoreProfile::SingleNodeDurable,
            lose_reserve_ack: std::sync::atomic::AtomicBool::new(true),
            lose_commit_ack: std::sync::atomic::AtomicBool::new(true),
            fail_commit_before_write: std::sync::atomic::AtomicBool::new(false),
            reserve_calls: std::sync::atomic::AtomicUsize::new(0),
            block_first_reserve: std::sync::Mutex::new(None),
            reservation_readback_fault: std::sync::atomic::AtomicU8::new(0),
        }
    }

    fn with_blocked_first_reserve(barrier: std::sync::Arc<std::sync::Barrier>) -> Self {
        Self {
            block_first_reserve: std::sync::Mutex::new(Some(barrier)),
            ..Self::new()
        }
    }

    fn with_commit_failure_before_write() -> Self {
        Self {
            fail_commit_before_write: std::sync::atomic::AtomicBool::new(true),
            ..Self::new()
        }
    }

    fn reserve_calls(&self) -> usize {
        self.reserve_calls
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn hide_approval_reservation_readback(&self) {
        self.reservation_readback_fault
            .store(1, std::sync::atomic::Ordering::SeqCst);
    }

    fn mismatch_approval_reservation_readback(&self) {
        self.reservation_readback_fault
            .store(2, std::sync::atomic::Ordering::SeqCst);
    }
}

impl ApprovalStore for DurableThresholdApprovalStore {
    fn authority_profile(&self) -> ApprovalStoreProfile {
        self.profile
    }

    fn store_pending(&self, request: &ApprovalRequest) -> Result<(), ApprovalStoreError> {
        self.inner.store_pending(request)
    }

    fn get_pending(&self, id: &str) -> Result<Option<ApprovalRequest>, ApprovalStoreError> {
        self.inner.get_pending(id)
    }

    fn list_pending(
        &self,
        filter: &ApprovalFilter,
    ) -> Result<Vec<ApprovalRequest>, ApprovalStoreError> {
        self.inner.list_pending(filter)
    }

    fn resolve(&self, id: &str, decision: &ApprovalDecision) -> Result<(), ApprovalStoreError> {
        self.inner.resolve(id, decision)
    }

    fn count_approved(&self, subject_id: &str, policy_id: &str) -> Result<u64, ApprovalStoreError> {
        self.inner.count_approved(subject_id, policy_id)
    }

    fn record_consumed(
        &self,
        token_id: &str,
        parameter_hash: &str,
        now: u64,
    ) -> Result<(), ApprovalStoreError> {
        self.inner.record_consumed(token_id, parameter_hash, now)
    }

    fn is_consumed(
        &self,
        token_id: &str,
        parameter_hash: &str,
    ) -> Result<bool, ApprovalStoreError> {
        self.inner.is_consumed(token_id, parameter_hash)
    }

    fn get_resolution(&self, id: &str) -> Result<Option<ResolvedApproval>, ApprovalStoreError> {
        self.inner.get_resolution(id)
    }

    fn reserve_approval_set(
        &self,
        operation_id: &str,
        approval_set: &ApprovalSetReservationInput,
    ) -> Result<ApprovalReservation, ApprovalStoreError> {
        self.reserve_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let barrier = self
            .block_first_reserve
            .lock()
            .map_err(|_| ApprovalStoreError::Backend("reserve barrier poisoned".to_string()))?
            .take();
        if let Some(barrier) = barrier {
            barrier.wait();
            barrier.wait();
        }
        let reservation = self
            .inner
            .reserve_approval_set(operation_id, approval_set)?;
        if self
            .lose_reserve_ack
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(ApprovalStoreError::Backend(
                "injected approval reservation acknowledgement loss".to_string(),
            ));
        }
        Ok(reservation)
    }

    fn commit_approval_reservation(
        &self,
        operation_id: &str,
    ) -> Result<ApprovalReservation, ApprovalStoreError> {
        if self
            .fail_commit_before_write
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(ApprovalStoreError::Backend(
                "injected approval commit failure before write".to_string(),
            ));
        }
        let reservation = self.inner.commit_approval_reservation(operation_id)?;
        if self
            .lose_commit_ack
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(ApprovalStoreError::Backend(
                "injected approval commit acknowledgement loss".to_string(),
            ));
        }
        Ok(reservation)
    }

    fn cancel_approval_reservation(
        &self,
        operation_id: &str,
    ) -> Result<ApprovalReservation, ApprovalStoreError> {
        self.inner.cancel_approval_reservation(operation_id)
    }

    fn get_approval_reservation(
        &self,
        operation_id: &str,
    ) -> Result<Option<ApprovalReservation>, ApprovalStoreError> {
        let reservation = self.inner.get_approval_reservation(operation_id)?;
        match self
            .reservation_readback_fault
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            0 => Ok(reservation),
            1 => Ok(None),
            2 => reservation
                .map(|reservation| {
                    let mut mismatched_hash =
                        reservation.approval_set().approval_set_hash().to_string();
                    let replacement = if mismatched_hash.starts_with("ab") {
                        "cd"
                    } else {
                        "ab"
                    };
                    mismatched_hash.replace_range(..2, replacement);
                    let mismatched_set = ApprovalSetReservationInput::new(
                        mismatched_hash,
                        reservation.approval_set().members().to_vec(),
                        reservation.approval_set().proposal_deadline(),
                    )?;
                    ApprovalReservation::from_persisted_parts(
                        reservation.operation_id().to_string(),
                        mismatched_set,
                        reservation.state(),
                    )
                })
                .transpose(),
            _ => Err(ApprovalStoreError::Backend(
                "invalid approval reservation readback fault".to_string(),
            )),
        }
    }
}

fn threshold_test_fixture() -> (
    ChioKernel,
    CapabilityToken,
    ToolGrant,
    chio_core::capability::governance::GovernedTransactionIntent,
    ToolCallRequest,
    u64,
) {
    let mut config = make_config();
    config.policy_hash = "33".repeat(32);
    let kernel = make_kernel(config);
    let subject = Keypair::generate();
    let grant = make_governed_monetary_grant("payments", "transfer", 100, 1_000, "USD", 50);
    let capability = kernel
        .issue_capability(
            &subject.public_key(),
            make_scope(vec![grant.clone()]),
            3_600,
        )
        .expect("capability");
    let intent = make_governed_intent(
        "threshold-intent",
        "payments",
        "transfer",
        "approved transfer",
        100,
        "USD",
    );
    let now = current_unix_timestamp();
    let request = ToolCallRequest {
        request_id: "threshold-request".to_string(),
        capability: capability.clone(),
        tool_name: "transfer".to_string(),
        server_id: "payments".to_string(),
        agent_id: subject.public_key().to_hex(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: Some(intent.clone()),
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: None,
        supplemental_authorization: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };
    (kernel, capability, grant, intent, request, now)
}

fn legacy_threshold_test_token(
    kernel: &ChioKernel,
    capability: &CapabilityToken,
    intent: &chio_core::capability::governance::GovernedTransactionIntent,
    request_id: &str,
    token_id: &str,
    now: u64,
) -> GovernedApprovalToken {
    GovernedApprovalToken::sign(
        chio_core::capability::governance::GovernedApprovalTokenBody {
            id: token_id.to_string(),
            approver: kernel.config.keypair.public_key(),
            subject: capability.subject.clone(),
            governed_intent_hash: intent.binding_hash().expect("intent hash"),
            threshold_proposal_hash: None,
            request_id: request_id.to_string(),
            issued_at: now.saturating_sub(1),
            expires_at: now + 300,
            decision: GovernedApprovalDecision::Approved,
        },
        &kernel.config.keypair,
    )
    .expect("legacy approval")
}

#[test]
fn approval_token_input_rejects_singular_list_ambiguity() {
    let (kernel, capability, _grant, intent, mut request, now) = threshold_test_fixture();
    let token = legacy_threshold_test_token(
        &kernel,
        &capability,
        &intent,
        &request.request_id,
        "legacy-a",
        now,
    );
    request.approval_token = Some(token.clone());
    request.approval_tokens = vec![token];
    let error = request
        .normalized_approval_tokens()
        .expect_err("ambiguous token forms must deny");
    assert!(error.to_string().contains("must not both"));
}

#[test]
fn threshold_policy_authority_roots_are_bounded_and_deduplicated() {
    let mut kernel = make_kernel(make_config());
    let authority = Keypair::generate().public_key();
    kernel
        .set_threshold_approval_policy_authorities(vec![authority.clone(), authority.clone()])
        .expect("deduplicated trust roots");
    assert_eq!(kernel.threshold_approval_policy_authorities(), &[authority]);

    let oversized = (0..=chio_core::capability::threshold_approval::MAX_THRESHOLD_APPROVAL_TOKENS)
        .map(|_| Keypair::generate().public_key())
        .collect();
    assert!(kernel
        .set_threshold_approval_policy_authorities(oversized)
        .is_err());
}

#[test]
fn threshold_replay_requires_a_durable_approval_store() {
    let mut kernel = make_kernel(make_config());
    let error = kernel
        .set_approval_store_handle(std::sync::Arc::new(InMemoryApprovalStore::new()))
        .expect_err("ephemeral replay storage must not enable threshold execution");
    assert!(error.to_string().contains("durable approval store"));

    let store = std::sync::Arc::new(DurableThresholdApprovalStore::new());
    kernel
        .set_approval_store_handle(store)
        .expect("single-node durable approval store");
}

#[test]
fn threshold_activation_requires_all_durable_authorities() {
    let mut config = make_config();
    config.policy_hash = "33".repeat(32);
    let mut kernel = make_kernel(config);
    let approver = Keypair::generate().public_key();
    let requirement = crate::threshold_approval::ThresholdApprovalRequirement::new(
        1,
        std::collections::BTreeMap::from([("approver".to_string(), approver)]),
        900,
        kernel.config.policy_hash.clone(),
        1,
    )
    .expect("requirement");
    kernel
        .set_threshold_approval_requirement_resolver(std::sync::Arc::new(
            move |_: &crate::threshold_approval::ThresholdApprovalRequest, _: &str| {
                Ok(requirement.clone())
            },
        ))
        .expect("resolver");
    kernel
        .set_threshold_approval_policy_authority(Keypair::generate().public_key())
        .expect("policy authority");
    assert!(!kernel
        .capability_negotiation_for_remote(None, current_unix_timestamp())
        .expect("local negotiation")
        .supports(chio_core::capability::features::THRESHOLD_GOVERNED_APPROVALS));

    let missing_operation = kernel
        .enable_threshold_governed_approvals()
        .expect_err("operation store is mandatory");
    assert!(missing_operation
        .to_string()
        .contains("admission operation store"));

    kernel
        .set_admission_operation_store_handle(std::sync::Arc::new(ProfiledTestStore::new(
            AdmissionOperationStoreProfile::SingleNodeDurable,
        )))
        .expect("durable operation store");
    let missing_approval = kernel
        .enable_threshold_governed_approvals()
        .expect_err("approval store is mandatory");
    assert!(missing_approval.to_string().contains("approval store"));

    kernel
        .set_approval_store_handle(std::sync::Arc::new(DurableThresholdApprovalStore::new()))
        .expect("durable approval store");
    let missing_budget = kernel
        .enable_threshold_governed_approvals()
        .expect_err("durable budget store is mandatory");
    assert!(missing_budget.to_string().contains("budget store"));
    kernel
        .set_budget_store_handle(std::sync::Arc::new(DurableThresholdBudgetStore::new()))
        .expect("budget store");
    kernel
        .enable_threshold_governed_approvals()
        .expect("all durable authorities installed");
    assert!(kernel
        .capability_negotiation_for_remote(None, current_unix_timestamp())
        .expect("local negotiation")
        .supports(chio_core::capability::features::THRESHOLD_GOVERNED_APPROVALS));
}

#[test]
fn single_node_threshold_stores_cannot_be_added_after_multiworker_configuration() {
    let mut kernel = make_kernel(make_config());
    kernel
        .set_dispatch_worker_count(2)
        .expect("empty topology may select worker count");
    assert!(kernel
        .set_admission_operation_store_handle(std::sync::Arc::new(ProfiledTestStore::new(
            AdmissionOperationStoreProfile::SingleNodeDurable,
        )))
        .is_err());
    assert!(kernel
        .set_approval_store_handle(std::sync::Arc::new(DurableThresholdApprovalStore::new()))
        .is_err());
}

#[test]
fn multiworker_activation_requires_every_participant_to_be_shared_linearizable() {
    let (mut kernel, capability, _grant, intent, mut request, now) = threshold_test_fixture();
    install_valid_threshold_artifacts(&mut kernel, &capability, &intent, &mut request, now);
    kernel
        .set_dispatch_worker_count(2)
        .expect("multiworker topology");
    kernel
        .set_admission_operation_store_handle(std::sync::Arc::new(ProfiledTestStore::new(
            AdmissionOperationStoreProfile::SharedLinearizable,
        )))
        .expect("shared operation store");
    kernel
        .set_approval_store_handle(std::sync::Arc::new(DurableThresholdApprovalStore::shared()))
        .expect("shared approval store");
    kernel
        .set_budget_store_handle(std::sync::Arc::new(DurableThresholdBudgetStore::new()))
        .expect("single-node budget store installation");
    let budget_error = kernel
        .enable_threshold_governed_approvals()
        .expect_err("single-node budget store must block multiworker activation");
    assert!(budget_error.to_string().contains("budget store"));

    kernel
        .set_budget_store_handle(std::sync::Arc::new(DurableThresholdBudgetStore::shared()))
        .expect("shared budget store");
    kernel
        .set_execution_nonce_store(
            ExecutionNonceConfig::default(),
            Box::new(DurableThresholdNonceStore::new()),
        )
        .expect("single-node nonce store installation");
    let nonce_error = kernel
        .enable_threshold_governed_approvals()
        .expect_err("single-node nonce store must block multiworker activation");
    assert!(nonce_error.to_string().contains("nonce store"));

    kernel
        .set_execution_nonce_store(
            ExecutionNonceConfig::default(),
            Box::new(DurableThresholdNonceStore::shared()),
        )
        .expect("shared nonce store");
    kernel
        .enable_threshold_governed_approvals()
        .expect("fully shared multiworker activation");
}

#[test]
fn active_threshold_authorities_require_explicit_deactivation_before_replacement() {
    let mut config = make_config();
    config.policy_hash = "33".repeat(32);
    let mut kernel = make_kernel(config);
    let requirement = crate::threshold_approval::ThresholdApprovalRequirement::new(
        1,
        std::collections::BTreeMap::from([(
            "approver".to_string(),
            Keypair::generate().public_key(),
        )]),
        900,
        kernel.config.policy_hash.clone(),
        1,
    )
    .expect("requirement");
    kernel
        .set_threshold_approval_requirement_resolver(std::sync::Arc::new(
            move |_: &crate::threshold_approval::ThresholdApprovalRequest, _: &str| {
                Ok(requirement.clone())
            },
        ))
        .expect("resolver");
    kernel
        .set_threshold_approval_policy_authority(Keypair::generate().public_key())
        .expect("policy authority");
    kernel
        .set_admission_operation_store_handle(std::sync::Arc::new(ProfiledTestStore::new(
            AdmissionOperationStoreProfile::SingleNodeDurable,
        )))
        .expect("operation store");
    kernel
        .set_approval_store_handle(std::sync::Arc::new(DurableThresholdApprovalStore::new()))
        .expect("approval store");
    kernel
        .set_budget_store_handle(std::sync::Arc::new(DurableThresholdBudgetStore::new()))
        .expect("budget store");
    kernel
        .enable_threshold_governed_approvals()
        .expect("activation");

    assert!(kernel
        .set_threshold_approval_requirement_resolver(std::sync::Arc::new(
            |_: &crate::threshold_approval::ThresholdApprovalRequest, _: &str| {
                Err(crate::threshold_approval::ThresholdApprovalResolutionError::Missing)
            },
        ))
        .is_err());
    assert!(kernel
        .set_threshold_approval_policy_authorities(vec![Keypair::generate().public_key()])
        .is_err());
    assert!(kernel
        .set_admission_operation_store_handle(std::sync::Arc::new(ProfiledTestStore::new(
            AdmissionOperationStoreProfile::SingleNodeDurable,
        )))
        .is_err());
    assert!(kernel
        .set_approval_store_handle(std::sync::Arc::new(DurableThresholdApprovalStore::new()))
        .is_err());
    assert!(kernel
        .set_budget_store_handle(std::sync::Arc::new(DurableThresholdBudgetStore::new()))
        .is_err());
    assert!(kernel
        .set_execution_nonce_store(
            ExecutionNonceConfig::default(),
            Box::new(DurableThresholdNonceStore::new()),
        )
        .is_err());

    kernel.deactivate_threshold_governed_approvals();
    kernel
        .set_threshold_approval_policy_authorities(vec![Keypair::generate().public_key()])
        .expect("replacement after deactivation");
    kernel
        .set_budget_store_handle(std::sync::Arc::new(DurableThresholdBudgetStore::new()))
        .expect("budget replacement after deactivation");
    kernel
        .set_execution_nonce_store(
            ExecutionNonceConfig::default(),
            Box::new(DurableThresholdNonceStore::new()),
        )
        .expect("nonce replacement after deactivation");
}

#[test]
fn one_element_list_preserves_legacy_semantics_without_threshold_policy() {
    let (kernel, capability, grant, intent, mut request, now) = threshold_test_fixture();
    request.approval_tokens = vec![legacy_threshold_test_token(
        &kernel,
        &capability,
        &intent,
        &request.request_id,
        "legacy-list",
        now,
    )];
    assert!(kernel
        .validate_governed_transaction(&request, &capability, &grant, None, now)
        .is_ok());
}

#[test]
fn multiple_legacy_list_tokens_cannot_bypass_threshold_proposal() {
    let (kernel, capability, grant, intent, mut request, now) = threshold_test_fixture();
    request.approval_tokens = vec![
        legacy_threshold_test_token(
            &kernel,
            &capability,
            &intent,
            &request.request_id,
            "legacy-a",
            now,
        ),
        legacy_threshold_test_token(
            &kernel,
            &capability,
            &intent,
            &request.request_id,
            "legacy-b",
            now,
        ),
    ];
    let error = kernel
        .validate_governed_transaction(&request, &capability, &grant, None, now)
        .expect_err("multiple legacy tokens must deny");
    assert!(error.to_string().contains("were not negotiated"));
}

#[test]
fn configured_threshold_policy_cannot_downgrade_after_resolver_loss() {
    let (mut kernel, capability, grant, _intent, request, now) = threshold_test_fixture();
    let approver = Keypair::generate().public_key();
    let requirement = crate::threshold_approval::ThresholdApprovalRequirement::new(
        1,
        std::collections::BTreeMap::from([("approver".to_string(), approver)]),
        900,
        kernel.config.policy_hash.clone(),
        1,
    )
    .expect("requirement");
    kernel
        .set_threshold_approval_requirement_resolver(std::sync::Arc::new(
            move |_: &crate::threshold_approval::ThresholdApprovalRequest, _: &str| {
                Ok(requirement.clone())
            },
        ))
        .expect("resolver");
    kernel.clear_threshold_approval_requirement_resolver();
    let error = kernel
        .validate_governed_transaction(&request, &capability, &grant, None, now)
        .expect_err("missing configured resolver must deny");
    assert!(error.to_string().contains("resolver is unavailable"));
}

#[test]
fn stale_threshold_policy_denies_before_legacy_fallback() {
    let (mut kernel, capability, grant, _intent, request, now) = threshold_test_fixture();
    kernel
        .set_threshold_approval_requirement_resolver(std::sync::Arc::new(
            move |_: &crate::threshold_approval::ThresholdApprovalRequest, received: &str| {
                Err(
                    crate::threshold_approval::ThresholdApprovalResolutionError::StalePolicy {
                        expected: "44".repeat(32),
                        received: received.to_string(),
                    },
                )
            },
        ))
        .expect("resolver");
    let error = kernel
        .validate_governed_transaction(&request, &capability, &grant, None, now)
        .expect_err("stale threshold policy must deny");
    assert!(error.to_string().contains("stale"));
}

#[test]
fn policy_approver_directory_does_not_create_an_approval_trigger() {
    let (mut kernel, capability, mut grant, _intent, request, now) = threshold_test_fixture();
    grant
        .constraints
        .retain(|constraint| !matches!(constraint, Constraint::RequireApprovalAbove { .. }));
    let approver = Keypair::generate().public_key();
    let requirement = crate::threshold_approval::ThresholdApprovalRequirement::new(
        1,
        std::collections::BTreeMap::from([("approver".to_string(), approver)]),
        900,
        kernel.config.policy_hash.clone(),
        1,
    )
    .expect("requirement");
    kernel
        .set_threshold_approval_requirement_resolver(std::sync::Arc::new(
            move |_: &crate::threshold_approval::ThresholdApprovalRequest, _: &str| {
                Ok(requirement.clone())
            },
        ))
        .expect("resolver");
    assert!(kernel
        .validate_governed_transaction(&request, &capability, &grant, None, now)
        .is_ok());
}
