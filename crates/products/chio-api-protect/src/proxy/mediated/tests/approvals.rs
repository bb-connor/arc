//! Actual approval routes over retained SQLite state and native replay custody.
use super::*;
use chio_kernel::admission_operation::governed_approval_claim::GovernedApprovalAuthorityBindingV1;
use chio_kernel::admission_operation::{AdmissionIdentifier, StoreMutationFence};
use chio_kernel::caller_delivery::{CallerExecutorIdentityV1, SignedCallerDispatchAuthorizationV1};
use chio_security_types::clock::{Clock, ClockError, ClockReading, MonotonicInstant, UnixMillis};
use chio_store_sqlite::caller_execution_ledger::SqliteCallerExecutionLedger;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct ApprovalClock {
    base: u64,
    elapsed: AtomicU64,
}
impl Clock for ApprovalClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        let elapsed = self.elapsed.load(Ordering::SeqCst);
        Ok(ClockReading::new(
            UnixMillis::new(self.base.checked_add(elapsed).ok_or(ClockError::Overflow)?),
            MonotonicInstant::from_nanos(
                elapsed.checked_mul(1_000_000).ok_or(ClockError::Overflow)?,
            ),
        ))
    }
}

struct ApprovalHarness {
    directory: tempfile::TempDir,
    clock_source: Arc<ApprovalClock>,
    clock: clock::ProxyClock,
    signer: Keypair,
    subject: Keypair,
    approver: Keypair,
    executor_key: Keypair,
    config: crate::ProtectApprovalConfig,
}

impl ApprovalHarness {
    fn new() -> TestResult<Self> {
        let clock_source = Arc::new(ApprovalClock {
            base: chio_test_support::clock::clock()
                .unix_millis()?
                .get()
                .checked_add(1000)
                .ok_or(ClockError::Overflow)?,
            elapsed: AtomicU64::new(0),
        });
        let clock = clock::ProxyClock::new(clock_source.clone());
        let directory = tempfile::tempdir()?;
        let locks = directory.path().join("locks");
        std::fs::create_dir(&locks)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
            std::fs::set_permissions(&locks, std::fs::Permissions::from_mode(0o700))?;
        }
        let database = directory.path().join("admission.db");
        chio_store_sqlite::SqliteAuthorityStore::provision(&database, &locks)?;
        let authority = chio_store_sqlite::SqliteAuthorityStore::open_serving_with_clock(
            &database,
            &locks,
            Arc::new(clock.clone()),
        )?;
        let store = authority.admission_operation_store();
        let fence: StoreMutationFence = authority.mutation_fence();
        let replay = directory.path().join("approvals-replay.db");
        drop(
            chio_store_sqlite::SqliteGovernedApprovalReplayStore::open_with_clock(
                &replay,
                128,
                Arc::new(clock.clone()),
            )?,
        );
        let source = chio_store_sqlite::SqliteGovernedApprovalReplaySource::open_with_clock(
            &replay,
            Arc::new(clock.clone()),
        )?;
        let id = AdmissionIdentifier::try_new("approval_authority", "api-approval-authority")?;
        let source_id = AdmissionIdentifier::try_new("approval_source", "api-approval-source")?;
        let now = clock.millis()?;
        let expected =
            store.expect_governed_approval_replay_source(&source_id, &id, &source, &fence, now)?;
        let imported = store.import_governed_approval_replay_source(
            &id,
            expected.expectation_id(),
            &source,
            &fence,
            now,
        )?;
        let binding =
            GovernedApprovalAuthorityBindingV1::new(id, imported.expectation_id().clone());
        store.activate_governed_approval_replay_source(&binding, &source, &fence, now)?;
        let executor_key = Keypair::generate();
        let approver = Keypair::generate();
        let config = crate::ProtectApprovalConfig {
            tenant_id: "tenant-a".into(),
            approvers: vec![approver.public_key()],
            replay_source_path: replay.to_string_lossy().into_owned(),
            binding,
            caller_executor: CallerExecutorIdentityV1 {
                executor_id: AdmissionIdentifier::try_new("executor_id", "api-approval-executor")?,
                public_key: executor_key.public_key(),
                key_epoch: 1,
            },
        };
        Ok(Self {
            directory,
            clock_source,
            clock,
            signer: Keypair::generate(),
            subject: Keypair::generate(),
            approver,
            executor_key,
            config,
        })
    }

    async fn open(&self, config: crate::ProtectApprovalConfig) -> TestResult<Arc<ProxyState>> {
        self.open_with_policy(config, "ap23-policy-a").await
    }

    async fn open_with_policy(
        &self,
        config: crate::ProtectApprovalConfig,
        policy: &str,
    ) -> TestResult<Arc<ProxyState>> {
        let authority = chio_store_sqlite::SqliteAuthorityStore::open_serving_with_clock(
            self.directory.path().join("admission.db"),
            self.directory.path().join("locks"),
            Arc::new(self.clock.clone()),
        )?;
        let durable = DurableAdmissionStores {
            store: Arc::new(authority.admission_operation_store()),
            outcome_store: Arc::new(authority.tool_outcome_store()),
            fence: authority.mutation_fence(),
            budget_store: Arc::new(authority.budget_store()),
        };
        let budget = durable.budget_store.clone();
        let revocation: Arc<dyn chio_kernel::RevocationStore> =
            Arc::new(chio_store_sqlite::SqliteRevocationStore::open(
                self.directory.path().join("revocations.db"),
            )?);
        let policy_hash = chio_core_types::sha256_hex(policy.as_bytes());
        let mut kernel = build_mediation_kernel(
            &self.signer,
            budget.clone(),
            super::super::MediationPolicy {
                issuers: &[],
                hash: Some(&policy_hash),
            },
            Vec::new(),
            None,
            Some(durable),
            Arc::new(self.clock.clone()),
        )?;
        kernel.set_revocation_store_handle(revocation.clone());
        super::super::super::approval_authority::configure(&mut kernel, &config)?;
        kernel.reconcile_durable_admission_startup()?;
        let mut state = mediated_test_state_core(
            self.signer.clone(),
            budget,
            Vec::new(),
            Some(MEDIATED_CONTROL_TOKEN.into()),
            None,
            true,
            None,
            Some(revocation),
        );
        let mutable = Arc::get_mut(&mut state).ok_or("unexpected shared fixture state")?;
        mutable.clock = self.clock.clone();
        mutable.mediation_kernel = Some(Mutex::new(kernel));
        mutable.approval_admin = ApprovalAdmin::new(Arc::new(SqliteApprovalStore::open(
            self.directory.path().join("approvals.db"),
        )?));
        mutable.approval_config = Some(config);
        Ok(state)
    }

    async fn capability(&self, state: &ProxyState) -> TestResult<CapabilityToken> {
        Ok(state
            .mediation_kernel
            .as_ref()
            .ok_or("kernel")?
            .lock()
            .await
            .issue_capability(
                &self.subject.public_key(),
                ChioScope {
                    grants: vec![ToolGrant {
                        server_id: "approval-server".into(),
                        tool_name: "effect".into(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![
                            chio_core_types::capability::scope::Constraint::RequireApprovalAbove {
                                threshold_units: 0,
                            },
                        ],
                        max_invocations: Some(10),
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    }],
                    ..Default::default()
                },
                600,
            )?)
    }

    async fn submit(
        &self,
        state: Arc<ProxyState>,
        capability: &CapabilityToken,
    ) -> TestResult<ApprovalRequest> {
        let (status, body) = post_json_with_bearer(state.clone(), "/approvals/submit", &serde_json::json!({
            "capability": capability, "requested_by": self.subject.public_key().to_hex(),
            "tool_server": "approval-server", "tool_name": "effect", "parameters": {"value": "A"}, "ttl_seconds": 300,
        }), Some(MEDIATED_CONTROL_TOKEN)).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let id = body["approval_id"].as_str().ok_or("approval id")?;
        state
            .approval_admin
            .store()
            .get_pending(id)?
            .ok_or_else(|| "pending approval".into())
    }

    async fn approve(
        &self,
        state: Arc<ProxyState>,
        pending: &ApprovalRequest,
    ) -> TestResult<GovernedApprovalToken> {
        let now = state.clock.seconds()?;
        let token = GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: format!("vote-{}", pending.approval_id),
                approver: self.approver.public_key(),
                subject: self.subject.public_key(),
                governed_intent_hash: pending.parameter_hash.clone(),
                request_id: pending.approval_id.clone(),
                threshold_proposal_hash: None,
                issued_at: now,
                expires_at: pending.expires_at,
                decision: GovernedApprovalDecision::Approved,
            },
            &self.approver,
        )?;
        let (status, body) = post_json_with_bearer(state, &format!("/approvals/{}/respond", pending.approval_id),
            &serde_json::json!({"outcome": "approved", "approver": self.approver.public_key(), "token": token}), Some(MEDIATED_CONTROL_TOKEN)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        Ok(token)
    }
}

fn evaluate_body(capability: &CapabilityToken, pending: &ApprovalRequest) -> serde_json::Value {
    serde_json::json!({"capability": capability, "tool_server": "approval-server", "tool_name": "effect",
        "parameters": {"value": "A"}, "approval_id": pending.approval_id})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ap23_signed_approval_survives_restart_and_dispatches_exact_call_once() -> TestResult {
    let harness = ApprovalHarness::new()?;
    let state = harness.open(harness.config.clone()).await?;
    let capability = harness.capability(&state).await?;
    let pending = harness.submit(state.clone(), &capability).await?;
    let token = harness.approve(state.clone(), &pending).await?;
    drop(state);
    let state = harness.open(harness.config.clone()).await?;
    let body = evaluate_body(&capability, &pending);
    let mut wrong_arguments = body.clone();
    wrong_arguments["parameters"] = serde_json::json!({"value": "B"});
    let (status, denied) = post_evaluate(state.clone(), &wrong_arguments).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
    assert!(
        denied["message"]
            .as_str()
            .is_some_and(|text| text.contains("approval arguments")),
        "{denied}"
    );
    let ((status_a, first), (status_b, second)) = tokio::join!(
        post_evaluate(state.clone(), &body),
        post_evaluate(state.clone(), &body)
    );
    let reserved = if status_a == StatusCode::OK {
        assert_eq!(status_b, StatusCode::CONFLICT, "{second}");
        first
    } else {
        assert_eq!(status_a, StatusCode::CONFLICT, "{first}");
        assert_eq!(status_b, StatusCode::OK, "{second}");
        second
    };
    assert_eq!(reserved["status"], "reserved", "{reserved}");
    assert_eq!(
        reserved["receipt"]["metadata"]["governed_transaction"]["approval"]["approver_key"],
        harness.approver.public_key().to_hex(),
        "{reserved}"
    );
    let receipt: ChioReceipt = serde_json::from_value(reserved["receipt"].clone())?;
    assert!(receipt.verify_signature()?);
    let (status, started) = post_json_with_bearer(
        state.clone(),
        "/v1/caller/start",
        &serde_json::json!({
            "protocol": "chio.caller-delivery.v1", "execution_nonce": reserved["execution_nonce"],
            "arguments": {"value": "A"}, "credentials": {"approval_token": token},
        }),
        Some(MEDIATED_CONTROL_TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{started}");
    let authorization: SignedCallerDispatchAuthorizationV1 =
        serde_json::from_value(started["authorization"].clone())?;
    let effects = AtomicUsize::new(0);
    let ledger = SqliteCallerExecutionLedger::provision_with_clock(
        &harness.directory.path().join("executor.db"),
        harness.config.caller_executor.clone(),
        4,
        Arc::new(harness.clock.clone()),
    )?;
    for _ in 0..2 {
        ledger.execute_once(
            &authorization,
            &harness.signer.public_key(),
            &authorization.authorization.invocation,
            &harness.executor_key,
            || {
                effects.fetch_add(1, Ordering::SeqCst);
                Ok(CallerExecutionReport {
                    output: serde_json::json!({"approved": "A"}),
                    realized_cost: None,
                })
            },
        )?;
    }
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    drop(state);
    let reopened = harness.open(harness.config.clone()).await?;
    let (status, replay) = post_evaluate(reopened, &body).await;
    assert_eq!(status, StatusCode::OK, "{replay}");
    assert_eq!(replay["status"], "deny", "{replay}");
    assert_eq!(replay["execution_authorized"], false, "{replay}");
    assert_receipt_denial(
        &replay,
        "request replay is retained in state AwaitingCallerReport",
    );
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ap23_approval_rejects_changed_roster_tenant_and_request_bindings() -> TestResult {
    let harness = ApprovalHarness::new()?;
    let state = harness.open(harness.config.clone()).await?;
    let capability = harness.capability(&state).await?;
    let alternate = harness.capability(&state).await?;
    let pending = harness.submit(state.clone(), &capability).await?;
    harness.approve(state.clone(), &pending).await?;
    let body = evaluate_body(&capability, &pending);
    for (field, value) in [
        ("capability", serde_json::to_value(alternate)?),
        ("tool_name", serde_json::json!("other")),
        ("tool_server", serde_json::json!("other")),
        ("request_id", serde_json::json!("other")),
    ] {
        let mut changed = body.clone();
        changed[field] = value;
        let (status, denied) = post_evaluate(state.clone(), &changed).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{field}: {denied}");
        assert!(
            denied["message"]
                .as_str()
                .is_some_and(|message| message.contains("approval does not bind")),
            "{denied}"
        );
    }
    let mut changed_capability = capability.body();
    changed_capability.expires_at -= 1;
    let changed_capability = CapabilityToken::sign(changed_capability, &harness.signer)?;
    let mut changed = body.clone();
    changed["capability"] = serde_json::to_value(changed_capability)?;
    let (status, denied) = post_evaluate(state.clone(), &changed).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
    assert_eq!(
        denied["message"], "approval arguments, tenant, policy or capability changed",
        "{denied}"
    );
    drop(state);
    let mut config = harness.config.clone();
    config.tenant_id = "tenant-b".into();
    let state = harness.open(config).await?;
    let (status, denied) = post_evaluate(state.clone(), &body).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
    assert!(
        denied["message"]
            .as_str()
            .is_some_and(|message| message.contains("approval arguments, tenant")),
        "{denied}"
    );
    drop(state);
    let mut config = harness.config.clone();
    config.approvers = vec![Keypair::generate().public_key()];
    let state = harness.open(config).await?;
    let (status, denied) = post_evaluate(state, &body).await;
    assert_eq!(status, StatusCode::OK, "{denied}");
    assert_eq!(denied["status"], "deny", "{denied}");
    assert_receipt_denial(&denied, "approval signer is not in configured roster");
    let state = harness
        .open_with_policy(harness.config.clone(), "ap23-policy-b")
        .await?;
    let (status, denied) = post_evaluate(state, &body).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
    assert_eq!(
        denied["message"], "approval does not bind this request, capability, route or policy",
        "{denied}"
    );
    Ok(())
}

fn assert_receipt_denial(body: &serde_json::Value, reason: &str) {
    assert_eq!(body["receipt"]["decision"]["verdict"], "deny", "{body}");
    assert!(
        body["receipt"]["decision"]["reason"]
            .as_str()
            .is_some_and(|value| value.contains(reason)),
        "{body}"
    );
    assert!(body.get("authorization").is_none(), "{body}");
}

#[tokio::test]
async fn ap23_signed_approval_expires_without_reserving_or_dispatching() -> TestResult {
    let harness = ApprovalHarness::new()?;
    let state = harness.open(harness.config.clone()).await?;
    let capability = harness.capability(&state).await?;
    let pending = harness.submit(state.clone(), &capability).await?;
    harness.approve(state.clone(), &pending).await?;
    harness
        .clock_source
        .elapsed
        .store(300_000, Ordering::SeqCst);
    let (status, denied) =
        post_evaluate(state.clone(), &evaluate_body(&capability, &pending)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
    assert_eq!(
        denied["message"], "approval request expired or token exceeds its deadline",
        "{denied}"
    );
    assert!(state
        .budget_store
        .as_ref()
        .ok_or("budget")?
        .get_usage(&capability.id, 0)?
        .is_none());
    Ok(())
}

#[tokio::test]
async fn ap23_capability_revocation_rejects_approved_call_before_reservation() -> TestResult {
    let harness = ApprovalHarness::new()?;
    let state = harness.open(harness.config.clone()).await?;
    let capability = harness.capability(&state).await?;
    let pending = harness.submit(state.clone(), &capability).await?;
    harness.approve(state.clone(), &pending).await?;
    state
        .revocation_store
        .as_ref()
        .ok_or("revocation store")?
        .revoke(&capability.id)?;
    let (status, denied) =
        post_evaluate(state.clone(), &evaluate_body(&capability, &pending)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
    assert_eq!(denied["error"], "chio_capability_revoked", "{denied}");
    assert!(state
        .budget_store
        .as_ref()
        .ok_or("budget")?
        .get_usage(&capability.id, 0)?
        .is_none());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ap23_fresh_start_rechecks_signer_retirement_and_capability_revocation() -> TestResult {
    for retire_signer in [true, false] {
        let harness = ApprovalHarness::new()?;
        let state = harness.open(harness.config.clone()).await?;
        let capability = harness.capability(&state).await?;
        let pending = harness.submit(state.clone(), &capability).await?;
        let token = harness.approve(state.clone(), &pending).await?;
        let (status, reserved) =
            post_evaluate(state.clone(), &evaluate_body(&capability, &pending)).await;
        assert_eq!(status, StatusCode::OK, "{reserved}");
        assert_eq!(reserved["status"], "reserved", "{reserved}");
        if retire_signer {
            state
                .mediation_kernel
                .as_ref()
                .ok_or("kernel")?
                .lock()
                .await
                .set_governed_approval_policy(
                    "tenant-a".into(),
                    vec![Keypair::generate().public_key()],
                )?;
        } else {
            state
                .revocation_store
                .as_ref()
                .ok_or("revocation store")?
                .revoke(&capability.id)?;
        }
        let (status, denied) = post_json_with_bearer(state, "/v1/caller/start", &serde_json::json!({
            "protocol": "chio.caller-delivery.v1", "execution_nonce": reserved["execution_nonce"],
            "arguments": {"value": "A"}, "credentials": {"approval_token": token},
        }), Some(MEDIATED_CONTROL_TOKEN)).await;
        if retire_signer {
            assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
            assert_receipt_denial(&denied, "approval signer is not in configured roster");
        } else {
            assert_eq!(status, StatusCode::CONFLICT, "{denied}");
            assert_eq!(denied["error"], "chio_caller_delivery_rejected", "{denied}");
        }
        assert!(denied.get("authorization").is_none(), "{denied}");
    }
    Ok(())
}

#[tokio::test]
async fn ap23_submit_rejects_invalid_subject_and_unsigned_or_unlisted_decisions() -> TestResult {
    let harness = ApprovalHarness::new()?;
    let state = harness.open(harness.config.clone()).await?;
    let capability = harness.capability(&state).await?;
    for requested_by in [
        "not-a-public-key".to_owned(),
        harness.approver.public_key().to_hex(),
    ] {
        let (status, rejected) = post_json_with_bearer(state.clone(), "/approvals/submit", &serde_json::json!({
            "capability": capability, "requested_by": requested_by,
            "tool_server": "approval-server", "tool_name": "effect", "parameters": {"value": "A"},
        }), Some(MEDIATED_CONTROL_TOKEN)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{rejected}");
        assert_eq!(
            rejected["message"],
            "requested_by must be the capability subject public key"
        );
    }
    let pending = harness.submit(state.clone(), &capability).await?;
    let (status, rejected) = post_json_with_bearer(
        state.clone(),
        &format!("/approvals/{}/operator-respond", pending.approval_id),
        &serde_json::json!({"decision": "approve"}),
        Some(MEDIATED_CONTROL_TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{rejected}");
    assert_eq!(rejected["error"], "bad_request", "{rejected}");
    let token = GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: "unlisted-decision".into(),
            approver: harness.signer.public_key(),
            subject: harness.subject.public_key(),
            governed_intent_hash: pending.parameter_hash.clone(),
            request_id: pending.approval_id.clone(),
            threshold_proposal_hash: None,
            issued_at: state.clock.seconds()?,
            expires_at: pending.expires_at,
            decision: GovernedApprovalDecision::Approved,
        },
        &harness.signer,
    )?;
    let (status, rejected) = post_json_with_bearer(state.clone(), &format!("/approvals/{}/respond", pending.approval_id), &serde_json::json!({"outcome": "approved", "approver": harness.signer.public_key(), "token": token}), Some(MEDIATED_CONTROL_TOKEN)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{rejected}");
    assert_eq!(
        rejected["message"],
        "approval signer is not in configured roster"
    );
    assert!(state
        .approval_admin
        .store()
        .get_pending(&pending.approval_id)?
        .is_some());
    Ok(())
}

#[tokio::test]
async fn ap23_approval_submission_rejects_original_duplicate_arguments() -> TestResult {
    let harness = ApprovalHarness::new()?;
    let state = harness.open(harness.config.clone()).await?;
    let capability = harness.capability(&state).await?;
    let body = format!(
        r#"{{"capability":{},"requested_by":"{}","tool_server":"approval-server","tool_name":"effect","parameters":{{"value":"A","value":"B"}}}}"#,
        serde_json::to_string(&capability)?,
        harness.subject.public_key().to_hex()
    );
    let request = with_loopback_peer(
        Request::builder()
            .method("POST")
            .uri("/approvals/submit")
            .header("content-type", "application/json")
            .header(AUTHORIZATION, format!("Bearer {MEDIATED_CONTROL_TOKEN}"))
            .body(Body::from(body))?,
    );
    let response = build_app(state.clone()).oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 1024 * 1024).await?)?;
    assert_eq!(body["error"], "bad_request");
    assert_eq!(
        body["message"],
        "urn:chio:error:attest:signed-json-invalid-input"
    );
    assert!(state
        .approval_admin
        .store()
        .list_pending(&chio_kernel::ApprovalFilter::default())?
        .is_empty());
    Ok(())
}
