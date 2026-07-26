fn assert_monetary_post_dispatch_error_releases_exposure(
    server: Box<dyn ToolServerConnection>,
    server_entries: std::sync::Arc<AtomicU64>,
    request_id: &str,
    nested: bool,
) {
    let mut kernel = make_kernel(make_monetary_config());
    install_bounded_budget_authorities(&mut kernel, request_id);
    kernel.register_tool_server(server);
    let subject_kp = Keypair::generate();
    let mut grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    grant.max_invocations = Some(1);
    let cap = kernel
        .issue_capability(&subject_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let request = make_request(request_id, &cap, "compute", "cost-srv");

    let response = if nested {
        let session_id = kernel
            .open_session(subject_kp.public_key().to_hex(), vec![cap.clone()])
            .unwrap();
        kernel.activate_session(&session_id).unwrap();
        let context =
            make_operation_context(&session_id, request_id, &subject_kp.public_key().to_hex());
        kernel
            .begin_session_request(&context, OperationKind::ToolCall, true)
            .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime
            .block_on(async {
                let mut client = NoopNestedFlowClient;
                kernel
                    .evaluate_tool_call_with_nested_flow_client_async(
                        &context,
                        &request,
                        &mut client,
                        None,
                    )
                    .await
            })
            .unwrap()
    } else {
        kernel.evaluate_tool_call_blocking(&request).unwrap()
    };

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(server_entries.load(Ordering::SeqCst), 1);
    let usage = kernel.budget_store.get_usage(&cap.id, 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_eq!(usage.total_cost_exposed, 0);
    assert!(!kernel
        .budget_store
        .try_increment(&cap.id, 0, Some(1))
        .unwrap());

    let terminal = &response.receipt.metadata.as_ref().unwrap()["budget_authority"]["terminal"];
    assert_eq!(terminal["disposition"], "released");
    assert_eq!(terminal["exposure_units"], 100);
    assert_eq!(terminal["committed_cost_units_after"], 0);
    assert!(terminal["event_id"]
        .as_str()
        .is_some_and(|event_id| event_id.ends_with(":release")));
}

#[test]
fn monetary_cancelled_connector_error_releases_exposure_top_level() {
    let entries = std::sync::Arc::new(AtomicU64::new(0));
    assert_monetary_post_dispatch_error_releases_exposure(
        Box::new(CancellationAfterSideEffectServer::new(
            "cost-srv",
            vec!["compute"],
            std::sync::Arc::clone(&entries),
        )),
        entries,
        "req-monetary-cancelled-top-level",
        false,
    );
}

#[test]
fn monetary_incomplete_connector_error_releases_exposure_top_level() {
    let entries = std::sync::Arc::new(AtomicU64::new(0));
    assert_monetary_post_dispatch_error_releases_exposure(
        Box::new(IncompleteAfterSideEffectServer::new(
            "cost-srv",
            vec!["compute"],
            std::sync::Arc::clone(&entries),
        )),
        entries,
        "req-monetary-incomplete-top-level",
        false,
    );
}

#[test]
fn monetary_generic_connector_error_releases_exposure_top_level() {
    let entries = std::sync::Arc::new(AtomicU64::new(0));
    assert_monetary_post_dispatch_error_releases_exposure(
        Box::new(FailingAfterSideEffectServer::new(
            "cost-srv",
            vec!["compute"],
            std::sync::Arc::clone(&entries),
        )),
        entries,
        "req-monetary-generic-top-level",
        false,
    );
}

#[test]
fn monetary_cancelled_connector_error_releases_exposure_nested() {
    let entries = std::sync::Arc::new(AtomicU64::new(0));
    assert_monetary_post_dispatch_error_releases_exposure(
        Box::new(CancellationAfterSideEffectServer::new(
            "cost-srv",
            vec!["compute"],
            std::sync::Arc::clone(&entries),
        )),
        entries,
        "req-monetary-cancelled-nested",
        true,
    );
}

#[test]
fn monetary_incomplete_connector_error_releases_exposure_nested() {
    let entries = std::sync::Arc::new(AtomicU64::new(0));
    assert_monetary_post_dispatch_error_releases_exposure(
        Box::new(IncompleteAfterSideEffectServer::new(
            "cost-srv",
            vec!["compute"],
            std::sync::Arc::clone(&entries),
        )),
        entries,
        "req-monetary-incomplete-nested",
        true,
    );
}

#[test]
fn monetary_generic_connector_error_releases_exposure_nested() {
    let entries = std::sync::Arc::new(AtomicU64::new(0));
    assert_monetary_post_dispatch_error_releases_exposure(
        Box::new(FailingAfterSideEffectServer::new(
            "cost-srv",
            vec!["compute"],
            std::sync::Arc::clone(&entries),
        )),
        entries,
        "req-monetary-generic-nested",
        true,
    );
}

#[derive(Clone, Copy)]
enum CleanupFailureSource {
    Payment,
    BudgetStore,
}

#[derive(Clone, Copy)]
enum CleanupFailureTerminal {
    Cancelled,
    Incomplete,
    Denied,
}

fn assert_post_dispatch_cleanup_failure_projection(
    server: Box<dyn ToolServerConnection>,
    server_entries: std::sync::Arc<AtomicU64>,
    request_id: &str,
    nested: bool,
    source: CleanupFailureSource,
    terminal: CleanupFailureTerminal,
) {
    let mut kernel = make_kernel(make_monetary_config());
    match source {
        CleanupFailureSource::Payment => {
            install_bounded_budget_authorities(&mut kernel, request_id);
            kernel
                .set_payment_adapter(Box::new(FailingReleasePaymentAdapter))
                .expect("payment adapter");
        }
        CleanupFailureSource::BudgetStore => {
            install_bounded_admission_operation_store(&mut kernel, request_id);
            kernel
                .set_budget_store_handle(std::sync::Arc::new(FailingReleaseBudgetStore::new()))
                .expect("budget store");
        }
    }
    kernel.register_tool_server(server);

    let subject_kp = Keypair::generate();
    let mut grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    grant.max_invocations = Some(1);
    let cap = kernel
        .issue_capability(&subject_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let request = make_request(request_id, &cap, "compute", "cost-srv");

    let response = if nested {
        let session_id = kernel
            .open_session(subject_kp.public_key().to_hex(), vec![cap.clone()])
            .unwrap();
        kernel.activate_session(&session_id).unwrap();
        let context =
            make_operation_context(&session_id, request_id, &subject_kp.public_key().to_hex());
        kernel
            .begin_session_request(&context, OperationKind::ToolCall, true)
            .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime
            .block_on(async {
                let mut client = NoopNestedFlowClient;
                kernel
                    .evaluate_tool_call_with_nested_flow_client_async(
                        &context,
                        &request,
                        &mut client,
                        None,
                    )
                    .await
            })
            .expect("cleanup failure must preserve the connector terminal response")
    } else {
        kernel
            .evaluate_tool_call_blocking(&request)
            .expect("cleanup failure must preserve the connector terminal response")
    };

    assert_eq!(server_entries.load(Ordering::SeqCst), 1);
    match terminal {
        CleanupFailureTerminal::Cancelled => assert!(response.receipt.is_cancelled()),
        CleanupFailureTerminal::Incomplete => assert!(response.receipt.is_incomplete()),
        CleanupFailureTerminal::Denied => assert!(response.receipt.is_denied()),
    }

    let usage = kernel.budget_store.get_usage(&cap.id, 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_eq!(usage.total_cost_exposed, 100);

    let metadata = response.receipt.metadata.as_ref().unwrap();
    assert!(metadata["budget_authority"]["terminal"].is_null());
    let financial_budget_authority = response
        .receipt
        .financial_budget_authority_metadata()
        .expect("cleanup fault receipt must retain typed budget authorization metadata");
    assert!(financial_budget_authority.terminal.is_none());
    assert_eq!(
        metadata["chio_runtime"]["post_dispatch_cleanup_failed"],
        true
    );
    let faults = metadata["chio_runtime"]["post_dispatch_cleanup_faults"]
        .as_array()
        .unwrap();
    assert_eq!(faults.len(), 1);
    let fault = &faults[0];
    let expected_step = match source {
        CleanupFailureSource::Payment => "payment_release",
        CleanupFailureSource::BudgetStore => "budget_hold_release",
    };
    assert_eq!(fault["step"], expected_step);
    let reason = fault["reason"].as_str().unwrap();
    assert!(reason.contains("[REDACTED-API-KEY]"));
    assert!(!reason.contains("sk_live_"));
    assert!(fault["attempted_release_event_id"]
        .as_str()
        .is_some_and(|event_id| event_id.ends_with(":release")));
    let hold_ids = fault["hold_ids"].as_array().unwrap();
    assert!(hold_ids.iter().any(|id| id == &cap.id));
    let budget_hold_id = metadata["budget_authority"]["hold_id"].as_str().unwrap();
    assert!(hold_ids.iter().any(|id| id == budget_hold_id));
    if matches!(source, CleanupFailureSource::Payment) {
        let payment_authorization_id =
            FailingReleasePaymentAdapter::operation_authorization_id(request_id, 100, "USD");
        assert!(hold_ids.iter().any(|id| id == &payment_authorization_id));
    }
}

#[test]
fn public_metadata_rejects_forged_budget_authority_before_dispatch() {
    let entries = std::sync::Arc::new(AtomicU64::new(0));
    let mut kernel = make_kernel(make_monetary_config());
    kernel.register_tool_server(Box::new(FailingAfterSideEffectServer::new(
        "cost-srv",
        vec!["compute"],
        std::sync::Arc::clone(&entries),
    )));

    let subject_kp = Keypair::generate();
    let cap = kernel
        .issue_capability(
            &subject_kp.public_key(),
            make_scope(vec![make_monetary_grant(
                "cost-srv", "compute", 100, 1000, "USD",
            )]),
            3600,
        )
        .unwrap();
    let request = make_request(
        "req-cleanup-fault-forged-budget-authority",
        &cap,
        "compute",
        "cost-srv",
    );

    let error = kernel
        .evaluate_tool_call_blocking_with_metadata(
            &request,
            Some(forged_budget_authority_metadata()),
        )
        .expect_err("caller budget authority metadata must fail before dispatch");
    assert!(matches!(
        error,
        KernelError::InvalidReceiptMetadata(reason) if reason.contains("budget_authority")
    ));
    assert_eq!(
        entries.load(Ordering::SeqCst),
        0,
        "reserved metadata must be rejected before the tool server runs"
    );
    assert_eq!(kernel.receipt_log().len(), 0);
}

struct PartitionEscrowCleanupTestStore {
    inner: InMemoryBudgetStore,
    binding: crate::budget_store::PartitionEscrowStoreBinding,
    partition_escrow_evidence: crate::budget_store::PartitionEscrowCommitEvidence,
}

impl PartitionEscrowCleanupTestStore {
    fn partition_authority(&self) -> crate::budget_store::BudgetEventAuthority {
        crate::budget_store::BudgetEventAuthority {
            authority_id: self.binding.store_identity_digest().to_string(),
            lease_id: format!(
                "partition-escrow:fence:{}",
                self.binding.fencing_token()
            ),
            lease_epoch: self.binding.fencing_token(),
        }
    }

    fn stamp_partition_metadata(&self, metadata: &mut crate::budget_store::BudgetCommitMetadata) {
        metadata.guarantee_level = crate::budget_store::BudgetGuaranteeLevel::PartitionEscrowed;
        metadata.partition_escrow_evidence = Some(self.partition_escrow_evidence.clone());
        metadata.authority = Some(self.partition_authority());
    }

    fn stamp_partition_mutation(
        &self,
        mut decision: crate::budget_store::BudgetHoldMutationDecision,
    ) -> crate::budget_store::BudgetHoldMutationDecision {
        self.stamp_partition_metadata(&mut decision.metadata);
        decision
    }

    fn admission_capture_decision(
        request: &crate::admission_capture_authority::AdmissionCaptureRequest,
        budget: crate::budget_store::BudgetHoldMutationDecision,
    ) -> Result<
        crate::admission_capture_authority::AdmissionCaptureDecision,
        crate::admission_capture_authority::AdmissionCaptureError,
    > {
        let authority_commit_index = budget.metadata.budget_commit_index.ok_or_else(|| {
            crate::admission_capture_authority::AdmissionCaptureError::InvalidRequest(
                "partition test capture omitted its budget commit index".to_string(),
            )
        })?;
        let metadata = crate::admission_capture_authority::AdmissionCaptureMetadata::new(
            crate::admission_capture_authority::AdmissionCaptureMetadataInput {
                operation_id: request.operation_id().to_string(),
                checked_revocation_set_digest: request
                    .bound_revocation_set_digest()
                    .to_string(),
                aggregate_root_capability_id: request
                    .aggregate_root_capability_id()
                    .map(str::to_string),
                aggregate_root_binding_digest: request
                    .aggregate_root_binding_digest()
                    .map(str::to_string),
                budget_commit: budget.metadata.clone(),
                revocation_commit_index: request.last_observed_revocation_index().unwrap_or(0),
                authority_commit_index,
                leader_epoch: None,
            },
        )?;
        Ok(
            crate::admission_capture_authority::AdmissionCaptureDecision::Captured {
                budget: Box::new(budget),
                metadata,
            },
        )
    }
}

impl crate::budget_store::BudgetStore for PartitionEscrowCleanupTestStore {
    fn authority_profile(&self) -> crate::budget_store::BudgetStoreProfile {
        crate::budget_store::BudgetStoreProfile::SharedLinearizable
    }

    fn budget_authority_profile(&self) -> crate::budget_store::BudgetAuthorityProfile {
        crate::budget_store::BudgetAuthorityProfile::AuthoritativeHoldEvent
    }

    fn budget_metering_profile(&self) -> crate::budget_store::BudgetMeteringProfile {
        crate::budget_store::BudgetMeteringProfile::MaxCostPreauthorizeThenReconcileActual
    }

    fn try_increment(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, crate::budget_store::BudgetStoreError> {
        crate::budget_store::BudgetStore::try_increment(
            &self.inner,
            capability_id,
            grant_index,
            max_invocations,
        )
    }

    fn try_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    ) -> Result<bool, crate::budget_store::BudgetStoreError> {
        crate::budget_store::BudgetStore::try_charge_cost(
            &self.inner,
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
        )
    }

    fn reverse_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), crate::budget_store::BudgetStoreError> {
        crate::budget_store::BudgetStore::reverse_charge_cost(
            &self.inner,
            capability_id,
            grant_index,
            cost_units,
        )
    }

    fn reduce_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), crate::budget_store::BudgetStoreError> {
        crate::budget_store::BudgetStore::reduce_charge_cost(
            &self.inner,
            capability_id,
            grant_index,
            cost_units,
        )
    }

    fn settle_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
    ) -> Result<(), crate::budget_store::BudgetStoreError> {
        crate::budget_store::BudgetStore::settle_charge_cost(
            &self.inner,
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
        )
    }

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<crate::budget_store::BudgetUsageRecord>, crate::budget_store::BudgetStoreError>
    {
        crate::budget_store::BudgetStore::list_usages(&self.inner, limit, capability_id)
    }

    fn get_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<crate::budget_store::BudgetUsageRecord>, crate::budget_store::BudgetStoreError>
    {
        crate::budget_store::BudgetStore::get_usage(&self.inner, capability_id, grant_index)
    }

    fn get_mutation_event_by_id(
        &self,
        event_id: &str,
    ) -> Result<
        Option<crate::budget_store::BudgetMutationRecord>,
        crate::budget_store::BudgetStoreError,
    > {
        crate::budget_store::BudgetStore::get_mutation_event_by_id(&self.inner, event_id).map(
            |record| {
                record.map(|mut record| {
                    record.authority = Some(self.partition_authority());
                    record
                })
            },
        )
    }

    fn authorize_budget_hold(
        &self,
        mut request: crate::budget_store::BudgetAuthorizeHoldRequest,
    ) -> Result<
        crate::budget_store::BudgetAuthorizeHoldDecision,
        crate::budget_store::BudgetStoreError,
    > {
        let request_evidence = request
            .invocation_admission_evidence()
            .and_then(|evidence| evidence.partition_escrow_evidence())
            .map(crate::budget_store::PartitionEscrowCommitEvidence::from_admission_evidence)
            .transpose()?;
        if request_evidence.as_ref() != Some(&self.partition_escrow_evidence) {
            return Err(crate::budget_store::BudgetStoreError::Invariant(
                "partition cleanup test authorization changed its escrow evidence".to_string(),
            ));
        }
        request.authority = Some(self.partition_authority());
        let mut decision =
            crate::budget_store::BudgetStore::authorize_budget_hold(&self.inner, request)?;
        let metadata = match &mut decision {
            crate::budget_store::BudgetAuthorizeHoldDecision::Authorized(authorized) => {
                &mut authorized.metadata
            }
            crate::budget_store::BudgetAuthorizeHoldDecision::Denied(denied) => {
                &mut denied.metadata
            }
        };
        self.stamp_partition_metadata(metadata);
        Ok(decision)
    }

    fn replay_budget_authorization(
        &self,
        mut request: crate::budget_store::BudgetAuthorizeHoldRequest,
    ) -> Result<
        crate::budget_store::BudgetAuthorizeHoldDecision,
        crate::budget_store::BudgetStoreError,
    > {
        request.authority = Some(self.partition_authority());
        let mut decision =
            crate::budget_store::BudgetStore::replay_budget_authorization(&self.inner, request)?;
        let metadata = match &mut decision {
            crate::budget_store::BudgetAuthorizeHoldDecision::Authorized(authorized) => {
                &mut authorized.metadata
            }
            crate::budget_store::BudgetAuthorizeHoldDecision::Denied(denied) => {
                &mut denied.metadata
            }
        };
        self.stamp_partition_metadata(metadata);
        Ok(decision)
    }

    fn reverse_budget_hold(
        &self,
        request: crate::budget_store::BudgetReverseHoldRequest,
    ) -> Result<
        crate::budget_store::BudgetReverseHoldDecision,
        crate::budget_store::BudgetStoreError,
    > {
        let decision =
            crate::budget_store::BudgetStore::reverse_budget_hold(&self.inner, request)?;
        Ok(self.stamp_partition_mutation(decision))
    }

    fn release_budget_hold(
        &self,
        request: crate::budget_store::BudgetReleaseHoldRequest,
    ) -> Result<
        crate::budget_store::BudgetReleaseHoldDecision,
        crate::budget_store::BudgetStoreError,
    > {
        let decision =
            crate::budget_store::BudgetStore::release_budget_hold(&self.inner, request)?;
        Ok(self.stamp_partition_mutation(decision))
    }

    fn reconcile_budget_hold(
        &self,
        request: crate::budget_store::BudgetReconcileHoldRequest,
    ) -> Result<
        crate::budget_store::BudgetReconcileHoldDecision,
        crate::budget_store::BudgetStoreError,
    > {
        let decision =
            crate::budget_store::BudgetStore::reconcile_budget_hold(&self.inner, request)?;
        Ok(self.stamp_partition_mutation(decision))
    }

    fn capture_budget_hold(
        &self,
        request: crate::budget_store::BudgetCaptureHoldRequest,
    ) -> Result<
        crate::budget_store::BudgetCaptureHoldDecision,
        crate::budget_store::BudgetStoreError,
    > {
        let decision =
            crate::budget_store::BudgetStore::capture_budget_hold(&self.inner, request)?;
        Ok(self.stamp_partition_mutation(decision))
    }

    fn capture_invocation_reservations(
        &self,
        request: crate::budget_store::BudgetCaptureInvocationRequest,
    ) -> Result<
        crate::budget_store::BudgetHoldMutationDecision,
        crate::budget_store::BudgetStoreError,
    > {
        let decision = crate::budget_store::BudgetStore::capture_invocation_reservations(
            &self.inner,
            request,
        )?;
        Ok(self.stamp_partition_mutation(decision))
    }

    fn query_invocation_capture(
        &self,
        request: &crate::budget_store::BudgetCaptureInvocationRequest,
    ) -> Result<
        Option<crate::budget_store::BudgetHoldMutationDecision>,
        crate::budget_store::BudgetStoreError,
    > {
        crate::budget_store::BudgetStore::query_invocation_capture(&self.inner, request).map(
            |decision| decision.map(|decision| self.stamp_partition_mutation(decision)),
        )
    }

    fn get_budget_hold(
        &self,
        hold_id: &str,
    ) -> Result<
        Option<crate::budget_store::BudgetHoldSnapshot>,
        crate::budget_store::BudgetStoreError,
    > {
        crate::budget_store::BudgetStore::get_budget_hold(&self.inner, hold_id).map(|hold| {
            hold.map(|mut hold| {
                self.stamp_partition_metadata(&mut hold.authorization_metadata);
                hold
            })
        })
    }

    fn mark_hold_reserved(
        &self,
        hold_id: &str,
        reserved_until_unix_secs: i64,
        currency: &str,
        payment_reference: Option<&str>,
        envelope: &crate::budget_store::ReservedHoldEnvelope,
    ) -> Result<(), crate::budget_store::BudgetStoreError> {
        crate::budget_store::BudgetStore::mark_hold_reserved(
            &self.inner,
            hold_id,
            reserved_until_unix_secs,
            currency,
            payment_reference,
            envelope,
        )
    }

    fn mark_invocation_hold_reserved(
        &self,
        hold_id: &str,
        capability_id: &str,
        grant_index: usize,
        reserved_until_unix_secs: i64,
        envelope: &crate::budget_store::ReservedHoldEnvelope,
    ) -> Result<(), crate::budget_store::BudgetStoreError> {
        crate::budget_store::BudgetStore::mark_invocation_hold_reserved(
            &self.inner,
            hold_id,
            capability_id,
            grant_index,
            reserved_until_unix_secs,
            envelope,
        )
    }

    fn mark_admission_operation_hold_reserved(
        &self,
        hold_id: &str,
        admission_operation: &crate::budget_store::BudgetAdmissionOperationBinding,
        reserved_until_unix_secs: i64,
        currency: Option<&str>,
        payment_reference: Option<&str>,
        envelope: &crate::budget_store::ReservedHoldEnvelope,
    ) -> Result<(), crate::budget_store::BudgetStoreError> {
        crate::budget_store::BudgetStore::mark_admission_operation_hold_reserved(
            &self.inner,
            hold_id,
            admission_operation,
            reserved_until_unix_secs,
            currency,
            payment_reference,
            envelope,
        )
    }

    fn reserve_invocation_hold(
        &self,
        hold_id: &str,
        capability_id: &str,
        grant_index: usize,
        reserved_until_unix_secs: i64,
        envelope: &crate::budget_store::ReservedHoldEnvelope,
    ) -> Result<(), crate::budget_store::BudgetStoreError> {
        crate::budget_store::BudgetStore::reserve_invocation_hold(
            &self.inner,
            hold_id,
            capability_id,
            grant_index,
            reserved_until_unix_secs,
            envelope,
        )
    }

    fn reap_expired_reserved_holds(
        &self,
        now_unix_secs: i64,
    ) -> Result<usize, crate::budget_store::BudgetStoreError> {
        crate::budget_store::BudgetStore::reap_expired_reserved_holds(
            &self.inner,
            now_unix_secs,
        )
    }

    fn list_open_delegated_reserved_hold_ids(
        &self,
    ) -> Result<Option<Vec<String>>, crate::budget_store::BudgetStoreError> {
        crate::budget_store::BudgetStore::list_open_delegated_reserved_hold_ids(&self.inner)
    }

    fn request_id_has_reserved_hold(
        &self,
        request_id: &str,
    ) -> Result<Option<bool>, crate::budget_store::BudgetStoreError> {
        crate::budget_store::BudgetStore::request_id_has_reserved_hold(&self.inner, request_id)
    }

    fn budget_guarantee_level(&self) -> crate::budget_store::BudgetGuaranteeLevel {
        crate::budget_store::BudgetGuaranteeLevel::PartitionEscrowed
    }

    fn partition_escrow_store_binding(
        &self,
    ) -> Result<
        Option<crate::budget_store::PartitionEscrowStoreBinding>,
        crate::budget_store::BudgetStoreError,
    > {
        Ok(Some(self.binding.clone()))
    }
}

impl crate::admission_capture_authority::AdmissionCaptureAuthority
    for PartitionEscrowCleanupTestStore
{
    fn query_admission_capture(
        &self,
        request: &crate::admission_capture_authority::AdmissionCaptureRequest,
    ) -> Result<
        Option<crate::admission_capture_authority::AdmissionCaptureDecision>,
        crate::admission_capture_authority::AdmissionCaptureError,
    > {
        crate::budget_store::BudgetStore::query_invocation_capture(self, request.budget())
            .map_err(crate::admission_capture_authority::AdmissionCaptureError::from)?
            .map(|budget| Self::admission_capture_decision(request, budget))
            .transpose()
    }

    fn capture_admission(
        &self,
        request: crate::admission_capture_authority::AdmissionCaptureRequest,
    ) -> Result<
        crate::admission_capture_authority::AdmissionCaptureDecision,
        crate::admission_capture_authority::AdmissionCaptureError,
    > {
        let budget = crate::budget_store::BudgetStore::capture_invocation_reservations(
            self,
            request.budget().clone(),
        )?;
        Self::admission_capture_decision(&request, budget)
    }
}

fn assert_partition_cleanup_failure_message_is_non_leaking(message: &str) {
    for exhausted_dimension_detail in [
        "exhausted-owner-secret",
        "chio.grant-invocation.v1",
        "17",
        "937",
        "413729",
        "grant_index",
        "max_invocations",
        "invocation_count",
        "reserved_invocations_after",
        "captured_invocations_after",
        "committed_cost_units_after",
        "max_total_cost_units",
        "grant",
        "aggregate",
        "broker",
        "invocation",
        "monetary",
        "cost",
    ] {
        assert!(
            !message.contains(exhausted_dimension_detail),
            "cleanup evidence failure leaked `{exhausted_dimension_detail}`: {message}"
        );
    }
}

fn assert_partition_cleanup_evidence_failure_is_non_leaking(result: Result<(), KernelError>) {
    let message = match result {
        Err(KernelError::GuardDenied(message)) => message,
        other => panic!("partition escrow cleanup evidence must fail closed, got {other:?}"),
    };
    assert_partition_cleanup_failure_message_is_non_leaking(&message);
}

#[test]
fn partition_escrow_cleanup_denial_rejects_malformed_missing_or_mismatched_evidence_without_dimension_leak(
) -> Result<(), Box<dyn std::error::Error>> {
    use chio_core_types::partition_escrow::{
        verify_partition_escrow_quota_commitment, PartitionEscrowAllocation,
        PartitionEscrowAllocationPlan, PartitionEscrowAllocationPlanBinding,
        PartitionEscrowAllocationSetBody, PartitionEscrowQuota, PartitionEscrowQuotaCommitmentBody,
        PartitionEscrowQuotaSourceBinding, SignedPartitionEscrowAllocationSet,
        SignedPartitionEscrowQuotaCommitment,
    };

    #[derive(serde::Serialize)]
    #[serde(tag = "kind", rename_all = "camelCase")]
    enum CleanupSourceTrust<'a> {
        GrantCapability {
            capability_id: &'a str,
            grant_index: u32,
            revocation_set_digest: &'a str,
        },
    }

    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct CleanupSourceTrustBinding<'a> {
        schema: &'static str,
        profile: &'a str,
        quota_key_digest: String,
        quota_descriptor_digest: String,
        underlying_source_artifact_digest: &'a str,
        source_signer: &'a PublicKey,
        source_not_before: u64,
        source_expires_at: u64,
        profile_trust: CleanupSourceTrust<'a>,
    }

    let signer = Keypair::from_seed(&[91; 32]);
    let subject = Keypair::from_seed(&[92; 32]);
    let capability_id = "partition-cleanup-capability";
    let now = current_unix_timestamp();
    let issued_at = now.saturating_sub(10);
    let expires_at = now.saturating_add(300);
    let allocation_expires_at = expires_at.saturating_sub(1);
    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: capability_id.to_string(),
            issuer: signer.public_key(),
            subject: subject.public_key(),
            scope: ChioScope::default(),
            issued_at,
            expires_at,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &signer,
    )?;
    let invocation_admission =
        crate::budget_store::VerifiedInvocationAdmission::grant_only(capability_id, 0, Some(5))?;
    let quota = PartitionEscrowQuota::new("chio.grant-invocation.v1", capability_id, Some(0), 5)?;
    let authority_id = "71".repeat(32);
    let allocations = vec![
        PartitionEscrowAllocation::new("partition-a", &authority_id, 2)?,
        PartitionEscrowAllocation::new("partition-b", "authority-b", 3)?,
    ];
    let plan = PartitionEscrowAllocationPlan::new(
        PartitionEscrowAllocationPlanBinding::new(
            "production",
            "partition-cleanup-root",
            1,
            quota.clone(),
            capability.expires_at,
            issued_at,
            allocation_expires_at,
        )?,
        allocations.clone(),
    )?;
    let source_artifact_digest =
        crate::threshold_approval::authorization_capability_hash(&capability)?;
    let revocation_set_digest = invocation_admission.revocation_set().digest().to_string();
    let source_signer = signer.public_key();
    let source_trust_binding = CleanupSourceTrustBinding {
        schema: "chio.partition-escrow-source-trust-binding.v1",
        profile: quota.profile(),
        quota_key_digest: quota.key_digest()?,
        quota_descriptor_digest: quota.descriptor_digest()?,
        underlying_source_artifact_digest: &source_artifact_digest,
        source_signer: &source_signer,
        source_not_before: capability.issued_at,
        source_expires_at: capability.expires_at,
        profile_trust: CleanupSourceTrust::GrantCapability {
            capability_id,
            grant_index: 0,
            revocation_set_digest: &revocation_set_digest,
        },
    };
    let source_trust_canonical = chio_core::canonical_json_bytes(&source_trust_binding)?;
    let mut source_trust_preimage = b"chio.partition-escrow-source-trust-binding.v1\0".to_vec();
    source_trust_preimage.extend_from_slice(&source_trust_canonical);
    let source_trust_digest = chio_core::sha256_hex(&source_trust_preimage);
    let quota_commitment = SignedPartitionEscrowQuotaCommitment::sign(
        PartitionEscrowQuotaCommitmentBody::new(
            &plan,
            PartitionEscrowQuotaSourceBinding::new(
                source_artifact_digest,
                source_trust_digest,
                capability.issued_at,
                capability.expires_at,
            )?,
        )?,
        &signer,
    )?;
    let certificate = verify_partition_escrow_quota_commitment(&quota_commitment, now)?;
    let allocation_set = SignedPartitionEscrowAllocationSet::sign(
        PartitionEscrowAllocationSetBody::new(
            &certificate,
            issued_at,
            allocation_expires_at,
            allocations,
        )?,
        &signer,
    )?;
    let source = crate::partition_escrow::verify_grant_partition_escrow_source(
        &quota_commitment,
        &capability,
        &invocation_admission,
        0,
        now,
    )?;
    let counter_namespace_digest =
        crate::partition_escrow::partition_escrow_counter_namespace_digest(
            "partition-a",
            &authority_id,
        )?;
    let registry = crate::partition_escrow::PartitionEscrowRegistry::new(
        crate::partition_escrow::PartitionEscrowRegistryInput {
            authority_domain: "production".to_string(),
            partition_id: "partition-a".to_string(),
            authority_id: authority_id.clone(),
            resolver_id: "static-partition-escrow-registry".to_string(),
            resolver_implementation_id: "chio-kernel-static-partition-escrow".to_string(),
            resolver_implementation_version: 1,
            store_identity_digest: authority_id.clone(),
            counter_namespace_digest: counter_namespace_digest.clone(),
            fencing_token: 1,
            entries: vec![crate::partition_escrow::PartitionEscrowRegistryEntryInput {
                quota_commitment,
                allocation_set,
            }],
        },
    )?;
    let admission = registry.resolve(&[source], now)?;
    let commit_evidence =
        crate::budget_store::PartitionEscrowCommitEvidence::from_admission_evidence(
            admission.evidence(),
        )?;
    let verified_partition_admission = invocation_admission
        .clone()
        .install_partition_escrow(&admission)?;
    let binding = crate::budget_store::PartitionEscrowStoreBinding::new(
        authority_id.clone(),
        counter_namespace_digest,
        1,
    )?;
    let store = std::sync::Arc::new(PartitionEscrowCleanupTestStore {
        inner: InMemoryBudgetStore::new(),
        binding,
        partition_escrow_evidence: commit_evidence.clone(),
    });
    let mut kernel = make_kernel(make_config());
    kernel.set_budget_store_handle(store.clone())?;
    kernel.set_admission_capture_authority(store.clone())?;
    kernel.install_partition_escrow_registry(std::sync::Arc::new(registry))?;

    let event_id = "partition-cleanup-authorize";
    let hold_id = "partition-cleanup-hold";
    let authority = store.partition_authority();
    let exhausted_quota = crate::budget_store::BudgetInvocationQuota::from_persisted_parts(
        crate::budget_store::BudgetQuotaKey::grant("exhausted-owner-secret", 17)?,
        413_729,
    )?;
    let denied = crate::budget_store::DeniedBudgetHold {
        hold_id: Some(hold_id.to_string()),
        attempted_exposure_units: 937,
        committed_cost_units_after: 937,
        invocation_count_after: 413_729,
        invocation_counts_after: vec![crate::budget_store::BudgetInvocationQuotaUsage {
            quota: exhausted_quota,
            reserved_invocations_after: 413_729,
            captured_invocations_after: 0,
        }],
        invocation_state: crate::budget_store::BudgetInvocationReservationState::Denied,
        monetary_state: crate::budget_store::BudgetMonetaryHoldState::None,
        revocation_set: None,
        metadata: crate::budget_store::BudgetCommitMetadata {
            authority: Some(authority.clone()),
            guarantee_level: crate::budget_store::BudgetGuaranteeLevel::PartitionEscrowed,
            budget_profile: crate::budget_store::BudgetAuthorityProfile::AuthoritativeHoldEvent,
            metering_profile:
                crate::budget_store::BudgetMeteringProfile::MaxCostPreauthorizeThenReconcileActual,
            budget_commit_index: Some(1),
            event_id: Some(event_id.to_string()),
            partition_escrow_evidence: Some(commit_evidence.clone()),
        },
    };
    let validation = |denied: &crate::budget_store::DeniedBudgetHold| {
        kernel.validate_budget_cleanup_denial(
            super::admission_cleanup::BudgetCleanupDenialValidation {
                store: store.as_ref(),
                denied,
                expected_hold_id: Some(hold_id),
                expected_exposure: 937,
                expected_event_id: event_id,
                expected_authority: Some(&authority),
                expected_revocation_set: None,
            },
        )
    };
    validation(&denied)?;

    // Malformed bytes cannot be represented by the typed metadata field. The
    // strict constructor is therefore the cleanup metadata admission boundary.
    let Err(malformed_error) =
        crate::budget_store::PartitionEscrowCommitEvidence::from_canonical_json(
            "{\"schema\":\"chio.partition-escrow-admission-evidence.v1\"}".to_string(),
            "00".repeat(32),
        )
    else {
        panic!("malformed partition escrow evidence must fail closed");
    };
    assert_partition_cleanup_failure_message_is_non_leaking(&malformed_error.to_string());
    let Err(digest_mismatch_error) =
        crate::budget_store::PartitionEscrowCommitEvidence::from_canonical_json(
            commit_evidence.canonical_json().to_string(),
            "ff".repeat(32),
        )
    else {
        panic!("partition escrow evidence with a mismatched digest must fail closed");
    };
    assert_partition_cleanup_failure_message_is_non_leaking(&digest_mismatch_error.to_string());

    let mut missing_evidence = denied.clone();
    missing_evidence.metadata.partition_escrow_evidence = None;
    assert_partition_cleanup_evidence_failure_is_non_leaking(validation(&missing_evidence));

    let mut mismatched_value: serde_json::Value =
        serde_json::from_str(commit_evidence.canonical_json())?;
    mismatched_value["durableStore"]["counterNamespaceDigest"] =
        serde_json::Value::String("72".repeat(32));
    let mismatched_canonical = chio_core::canonical_json_bytes(&mismatched_value)?;
    let mismatched_evidence =
        crate::partition_escrow::PartitionEscrowAdmissionEvidence::from_canonical_json_bytes(
            &mismatched_canonical,
        )?;
    let mismatched_commit_evidence =
        crate::budget_store::PartitionEscrowCommitEvidence::from_admission_evidence(
            &mismatched_evidence,
        )?;
    let mut mismatched_denial = denied;
    mismatched_denial.metadata.partition_escrow_evidence =
        Some(mismatched_commit_evidence.clone());
    assert_partition_cleanup_evidence_failure_is_non_leaking(validation(&mismatched_denial));

    let source_operation = crate::budget_store::BudgetAdmissionOperationBinding::new(
        "partition-source-cleanup-operation".to_string(),
        "83".repeat(32),
    )?;
    let mut authorization = crate::budget_store::BudgetAuthorizeHoldRequest::legacy(
        capability_id.to_string(),
        0,
        None,
        0,
        None,
        None,
        Some("partition-source-cleanup-hold".to_string()),
        Some("partition-source-cleanup-authorize".to_string()),
        Some(authority.clone()),
    );
    authorization.admission_operation = Some(source_operation.clone());
    authorization.install_verified_invocation_admission(verified_partition_admission)?;
    let authorization_artifact_digests =
        super::ordinary_admission::admission_authorization_artifact_digests(
            authorization
                .invocation_admission_evidence()
                .ok_or("partition source cleanup admission evidence is unavailable")?,
        )?;
    let decision = crate::budget_store::BudgetStore::authorize_budget_hold(
        store.as_ref(),
        authorization.clone(),
    )?;
    kernel.validate_budget_authorization_decision_for_store(
        store.as_ref(),
        &authorization,
        &decision,
        &authorization_artifact_digests,
        "partition source cleanup authorization",
    )?;
    let crate::budget_store::BudgetAuthorizeHoldDecision::Authorized(mut authorized) = decision
    else {
        panic!("partition source cleanup authorization must succeed");
    };
    authorized.metadata.partition_escrow_evidence = Some(mismatched_commit_evidence.clone());
    let forged_decision =
        crate::budget_store::BudgetAuthorizeHoldDecision::Authorized(authorized.clone());
    assert!(matches!(
        kernel.validate_budget_authorization_decision_for_store(
            store.as_ref(),
            &authorization,
            &forged_decision,
            &authorization_artifact_digests,
            "partition source cleanup authorization",
        ),
        Err(KernelError::GuardDenied(message))
            if message.contains("partition escrow commit does not match")
    ));
    authorized.metadata.partition_escrow_evidence =
        super::ordinary_admission::authorization_partition_escrow_commit_evidence(
            &authorization,
            "partition source cleanup authorization",
        )?;

    let capture_denial = crate::admission_capture_authority::AdmissionCaptureDenial::revoked(
        vec![capability_id.to_string()],
        crate::admission_capture_authority::AdmissionCaptureMetadata::new(
            crate::admission_capture_authority::AdmissionCaptureMetadataInput {
                operation_id: source_operation.operation_id().to_string(),
                checked_revocation_set_digest: "84".repeat(32),
                aggregate_root_capability_id: None,
                aggregate_root_binding_digest: None,
                budget_commit: crate::budget_store::BudgetCommitMetadata {
                    authority: Some(authority.clone()),
                    guarantee_level:
                        crate::budget_store::BudgetGuaranteeLevel::PartitionEscrowed,
                    budget_profile:
                        crate::budget_store::BudgetAuthorityProfile::AuthoritativeHoldEvent,
                    metering_profile: crate::budget_store::BudgetMeteringProfile::
                        MaxCostPreauthorizeThenReconcileActual,
                    budget_commit_index: None,
                    event_id: Some("partition-source-cleanup-capture".to_string()),
                    partition_escrow_evidence: Some(mismatched_commit_evidence),
                },
                revocation_commit_index: 1,
                authority_commit_index: 1,
                leader_epoch: None,
            },
        )?,
    )?;
    assert!(matches!(
        super::ordinary_admission::validate_capture_denial_partition_escrow_evidence(
            &authorized,
            &capture_denial,
            "partition source cleanup capture denial",
        ),
        Err(KernelError::BudgetCaptureRecoveryRequired(message))
            if message.contains("partition escrow evidence did not match authorization")
    ));

    let reverse_event_id = "partition-source-cleanup-reverse";
    let reversed = crate::budget_store::BudgetStore::reverse_budget_hold(
        store.as_ref(),
        crate::budget_store::BudgetReverseHoldRequest {
            capability_id: capability_id.to_string(),
            grant_index: 0,
            reversed_exposure_units: 0,
            hold_id: Some("partition-source-cleanup-hold".to_string()),
            event_id: Some(reverse_event_id.to_string()),
            authority: Some(authority.clone()),
            admission_operation: Some(source_operation.clone()),
        },
    )?;
    kernel.validate_budget_terminal_decision_for_store(
        store.as_ref(),
        &reversed,
        super::ordinary_admission::BudgetTerminalDecisionExpectation {
            authorization_metadata: &authorized.metadata,
            expected_event_id: reverse_event_id,
            expected_authority: Some(&authority),
            expected_capability_id: Some(capability_id),
            expected_grant_index: 0,
            expected_hold_id: "partition-source-cleanup-hold",
            expected_admission_operation: Some(&source_operation),
            expected_mutation_kind: crate::budget_store::BudgetMutationKind::ReverseInvocations,
            expected_exposure_units: 0,
            expected_realized_spend_units: 0,
            expected_invocation_state:
                crate::budget_store::BudgetInvocationReservationState::Reversed,
            expected_monetary_state: crate::budget_store::BudgetMonetaryHoldState::None,
            stage: "partition source cleanup reverse",
        },
    )?;

    Ok(())
}

include!("budget_part2_tail.inc");
