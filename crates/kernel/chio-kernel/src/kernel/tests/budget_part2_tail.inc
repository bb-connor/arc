#[test]
fn partition_escrow_reconcile_receipt_passes_authoritative_consumers(
) -> Result<(), Box<dyn std::error::Error>> {
    use chio_core_types::partition_escrow::{
        verify_partition_escrow_quota_commitment, PartitionEscrowAllocation,
        PartitionEscrowAllocationPlan, PartitionEscrowAllocationPlanBinding,
        PartitionEscrowAllocationSetBody, PartitionEscrowQuota, PartitionEscrowQuotaCommitmentBody,
        PartitionEscrowQuotaSourceBinding, SignedPartitionEscrowAllocationSet,
        SignedPartitionEscrowQuotaCommitment,
    };
    use chio_core_types::receipt::authoritative_spend::{
        is_authoritative_spend_receipt, receipt_meets_guarantee_floor,
    };

    #[derive(serde::Serialize)]
    #[serde(tag = "kind", rename_all = "camelCase")]
    enum ReconcileSourceTrust<'a> {
        GrantCapability {
            capability_id: &'a str,
            grant_index: u32,
            revocation_set_digest: &'a str,
        },
    }

    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct ReconcileSourceTrustBinding<'a> {
        schema: &'static str,
        profile: &'a str,
        quota_key_digest: String,
        quota_descriptor_digest: String,
        underlying_source_artifact_digest: &'a str,
        source_signer: &'a PublicKey,
        source_not_before: u64,
        source_expires_at: u64,
        profile_trust: ReconcileSourceTrust<'a>,
    }

    let mut config = make_monetary_config();
    config.dispatch_intent_journal = crate::DispatchIntentJournalMode::SideEffecting;
    let authority_signer = config.keypair.clone();
    let mut kernel = make_kernel(config);
    let agent = Keypair::from_seed(&[94; 32]);
    let mut grant = make_monetary_grant("cost-srv", "compute", 100, 150, "USD");
    grant.max_invocations = Some(10);
    let capability = kernel.issue_capability(
        &agent.public_key(),
        make_scope(vec![grant]),
        3_600,
    )?;
    let now = current_unix_timestamp();
    let invocation_admission = crate::budget_store::VerifiedInvocationAdmission::grant_only(
        &capability.id,
        0,
        Some(10),
    )?;
    let quota = PartitionEscrowQuota::new(
        "chio.grant-invocation.v1",
        &capability.id,
        Some(0),
        10,
    )?;
    let authority_id = "95".repeat(32);
    let allocations = vec![PartitionEscrowAllocation::new(
        "partition-a",
        &authority_id,
        10,
    )?];
    let allocation_expires_at = capability.expires_at.saturating_sub(1);
    let plan = PartitionEscrowAllocationPlan::new(
        PartitionEscrowAllocationPlanBinding::new(
            "production",
            "partition-reconcile-root",
            1,
            quota.clone(),
            capability.expires_at,
            capability.issued_at,
            allocation_expires_at,
        )?,
        allocations.clone(),
    )?;
    let source_artifact_digest =
        crate::threshold_approval::authorization_capability_hash(&capability)?;
    let revocation_set_digest = invocation_admission.revocation_set().digest().to_string();
    let source_signer = authority_signer.public_key();
    let source_trust_binding = ReconcileSourceTrustBinding {
        schema: "chio.partition-escrow-source-trust-binding.v1",
        profile: quota.profile(),
        quota_key_digest: quota.key_digest()?,
        quota_descriptor_digest: quota.descriptor_digest()?,
        underlying_source_artifact_digest: &source_artifact_digest,
        source_signer: &source_signer,
        source_not_before: capability.issued_at,
        source_expires_at: capability.expires_at,
        profile_trust: ReconcileSourceTrust::GrantCapability {
            capability_id: &capability.id,
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
        &authority_signer,
    )?;
    let certificate = verify_partition_escrow_quota_commitment(&quota_commitment, now)?;
    let allocation_set = SignedPartitionEscrowAllocationSet::sign(
        PartitionEscrowAllocationSetBody::new(
            &certificate,
            capability.issued_at,
            allocation_expires_at,
            allocations,
        )?,
        &authority_signer,
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
    let partition_admission = registry.resolve(&[source], now)?;
    let commit_evidence =
        crate::budget_store::PartitionEscrowCommitEvidence::from_admission_evidence(
            partition_admission.evidence(),
        )?;
    let binding = crate::budget_store::PartitionEscrowStoreBinding::new(
        authority_id,
        counter_namespace_digest,
        1,
    )?;
    let store = std::sync::Arc::new(PartitionEscrowCleanupTestStore {
        inner: InMemoryBudgetStore::new(),
        binding,
        partition_escrow_evidence: commit_evidence.clone(),
    });
    kernel.deactivate_aggregate_invocation_admission();
    kernel.deactivate_supplemental_broker_admission();
    kernel.set_budget_store_handle(store.clone())?;
    kernel.set_admission_capture_authority(store)?;
    kernel.set_admission_operation_store_handle(durable_test_admission_operation_store(
        "partition-reconcile-operations",
    ))?;
    let receipt_path = unique_receipt_db_path("partition-reconcile-receipts");
    let receipt_store = SqliteReceiptStore::open(&receipt_path)?;
    kernel.set_receipt_store(Box::new(receipt_store))?;
    kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));
    let nonce_config = ExecutionNonceConfig {
        nonce_ttl_secs: 60,
        nonce_store_capacity: 1_024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        nonce_config.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&nonce_config)),
    )?;
    kernel.install_partition_escrow_registry(std::sync::Arc::new(registry))?;
    kernel.enable_aggregate_invocation_admission()?;

    let request = ToolCallRequest {
        request_id: "req-partition-reconcile".to_string(),
        capability: capability.clone(),
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent.public_key().to_hex(),
        arguments: serde_json::json!({ "invoice": "partition-1" }),
        supplemental_authorization: None,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };
    let caller_attribution = serde_json::json!({
        "attribution": {
            "subject_key": "caller-controlled-subject",
            "issuer_key": "caller-controlled-issuer",
            "delegation_depth": 4_294_967_295_u32,
            "grant_index": 4_294_967_295_u32,
            "caller_extension": "must-not-survive",
        }
    });
    let reserved = kernel.authorize_tool_call_reserving_blocking_with_metadata(
        &request,
        Some(caller_attribution),
    )?;
    assert_eq!(
        reserved.verdict,
        Verdict::Allow,
        "partition reservation denied: {:?}",
        reserved.reason
    );
    let nonce = reserved
        .execution_nonce
        .as_deref()
        .cloned()
        .ok_or("partition reservation omitted its reconcile nonce")?;
    let reconciled = kernel.reconcile_reserved_authorization_by_nonce(
        &nonce,
        &request.arguments,
        &ToolInvocationCost {
            units: 30,
            currency: "USD".to_string(),
            breakdown: None,
        },
    )?;

    assert_eq!(
        receipt_meets_guarantee_floor(&reconciled.receipt, "partition_escrowed"),
        Ok(()),
    );
    assert_eq!(
        is_authoritative_spend_receipt(
            &reconciled.receipt,
            &[kernel.public_key()],
            &nonce,
        ),
        Ok(()),
    );
    let receipt_metadata = reconciled
        .receipt
        .metadata
        .as_ref()
        .ok_or("partition reconcile receipt omitted metadata")?;
    let attribution = receipt_metadata
        .get("attribution")
        .cloned()
        .ok_or("partition reconcile receipt omitted attribution")?;
    assert!(attribution.get("caller_extension").is_none());
    let attribution: crate::ReceiptAttributionMetadata = serde_json::from_value(attribution)?;
    assert_eq!(attribution.subject_key, capability.subject.to_hex());
    assert_eq!(attribution.issuer_key, capability.issuer.to_hex());
    assert_eq!(attribution.delegation_depth, 0);
    assert_eq!(attribution.grant_index, Some(0));
    let authorization_artifact_digests = receipt_metadata
        .pointer("/protocol_admission/authorize/authorization_artifact_digests")
        .and_then(serde_json::Value::as_array)
        .ok_or("partition reconcile receipt omitted authorization artifact digests")?;
    assert_eq!(
        authorization_artifact_digests
            .iter()
            .filter(|digest| digest.as_str() == Some(commit_evidence.evidence_digest()))
            .count(),
        1,
    );

    drop(kernel);
    let _ = std::fs::remove_file(receipt_path);
    Ok(())
}

#[test]
fn post_dispatch_cleanup_fault_preserves_cancelled_top_level() {
    let entries = std::sync::Arc::new(AtomicU64::new(0));
    assert_post_dispatch_cleanup_failure_projection(
        Box::new(CancellationAfterSideEffectServer::new(
            "cost-srv",
            vec!["compute"],
            std::sync::Arc::clone(&entries),
        )),
        entries,
        "req-cleanup-fault-cancelled-top",
        false,
        CleanupFailureSource::Payment,
        CleanupFailureTerminal::Cancelled,
    );
}

#[test]
fn post_dispatch_cleanup_fault_preserves_incomplete_top_level() {
    let entries = std::sync::Arc::new(AtomicU64::new(0));
    assert_post_dispatch_cleanup_failure_projection(
        Box::new(IncompleteAfterSideEffectServer::new(
            "cost-srv",
            vec!["compute"],
            std::sync::Arc::clone(&entries),
        )),
        entries,
        "req-cleanup-fault-incomplete-top",
        false,
        CleanupFailureSource::BudgetStore,
        CleanupFailureTerminal::Incomplete,
    );
}

#[test]
fn post_dispatch_cleanup_fault_preserves_denied_top_level() {
    let entries = std::sync::Arc::new(AtomicU64::new(0));
    assert_post_dispatch_cleanup_failure_projection(
        Box::new(FailingAfterSideEffectServer::new(
            "cost-srv",
            vec!["compute"],
            std::sync::Arc::clone(&entries),
        )),
        entries,
        "req-cleanup-fault-denied-top",
        false,
        CleanupFailureSource::Payment,
        CleanupFailureTerminal::Denied,
    );
}

#[test]
fn post_dispatch_cleanup_fault_preserves_cancelled_nested() {
    let entries = std::sync::Arc::new(AtomicU64::new(0));
    assert_post_dispatch_cleanup_failure_projection(
        Box::new(CancellationAfterSideEffectServer::new(
            "cost-srv",
            vec!["compute"],
            std::sync::Arc::clone(&entries),
        )),
        entries,
        "req-cleanup-fault-cancelled-nested",
        true,
        CleanupFailureSource::BudgetStore,
        CleanupFailureTerminal::Cancelled,
    );
}

#[test]
fn post_dispatch_cleanup_fault_preserves_incomplete_nested() {
    let entries = std::sync::Arc::new(AtomicU64::new(0));
    assert_post_dispatch_cleanup_failure_projection(
        Box::new(IncompleteAfterSideEffectServer::new(
            "cost-srv",
            vec!["compute"],
            std::sync::Arc::clone(&entries),
        )),
        entries,
        "req-cleanup-fault-incomplete-nested",
        true,
        CleanupFailureSource::Payment,
        CleanupFailureTerminal::Incomplete,
    );
}

#[test]
fn post_dispatch_cleanup_fault_preserves_denied_nested() {
    let entries = std::sync::Arc::new(AtomicU64::new(0));
    assert_post_dispatch_cleanup_failure_projection(
        Box::new(FailingAfterSideEffectServer::new(
            "cost-srv",
            vec!["compute"],
            std::sync::Arc::clone(&entries),
        )),
        entries,
        "req-cleanup-fault-denied-nested",
        true,
        CleanupFailureSource::BudgetStore,
        CleanupFailureTerminal::Denied,
    );
}

#[test]
fn monetary_full_pipeline_three_invocations_third_denied() {
    // max_total_cost=250, max_cost_per_invocation=100.
    // Invocation 1: charges 100, total = 100. Allowed.
    // Invocation 2: charges 100, total = 200. Allowed.
    // Invocation 3: would charge 100, total would be 300 > 250. Denied.
    let mut kernel = make_kernel(make_monetary_config());
    install_bounded_budget_authorities(&mut kernel, "monetary-full-pipeline");
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));

    let grant = make_monetary_grant("cost-srv", "compute", 100, 250, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let make_req = |id: &str| ToolCallRequest {
        request_id: id.to_string(),
        capability: cap.clone(),
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: None,
        supplemental_authorization: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };

    let r1 = kernel
        .evaluate_tool_call_blocking(&make_req("req-1"))
        .unwrap();
    assert_eq!(r1.verdict, Verdict::Allow, "first invocation should pass");

    let r2 = kernel
        .evaluate_tool_call_blocking(&make_req("req-2"))
        .unwrap();
    assert_eq!(r2.verdict, Verdict::Allow, "second invocation should pass");

    let r3 = kernel
        .evaluate_tool_call_blocking(&make_req("req-3"))
        .unwrap();
    assert_eq!(
        r3.verdict,
        Verdict::Deny,
        "third invocation should be denied"
    );

    // Budget authorization denials are intentionally opaque and omit financial
    // dimensions that could reveal a capability's limits or current usage.
    let metadata = r3.receipt.metadata.as_ref().expect("should have metadata");
    assert!(metadata.get("financial").is_none());
}

#[test]
fn multi_grant_budget_remaining_uses_matched_grant_total() {
    let mut kernel = make_kernel(make_monetary_config());
    install_bounded_budget_authorities(&mut kernel, "multi-grant-budget-remaining");
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));

    let grant_a = make_monetary_grant("cost-srv", "compute-a", 100, 500, "USD");
    let grant_b = make_monetary_grant("cost-srv", "compute-b", 40, 200, "USD");
    let cap = kernel
        .issue_capability(
            &agent_kp.public_key(),
            make_scope(vec![grant_a, grant_b]),
            3600,
        )
        .unwrap();

    let invoke = |request_id: &str, tool_name: &str| ToolCallRequest {
        request_id: request_id.to_string(),
        capability: cap.clone(),
        tool_name: tool_name.to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: None,
        supplemental_authorization: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };

    let _ = kernel
        .evaluate_tool_call_blocking(&invoke("req-a", "compute-a"))
        .unwrap();
    let response_b = kernel
        .evaluate_tool_call_blocking(&invoke("req-b", "compute-b"))
        .unwrap();

    let metadata = response_b
        .receipt
        .metadata
        .as_ref()
        .expect("should have metadata");
    let financial = metadata
        .get("financial")
        .expect("should have financial metadata");
    assert_eq!(financial["grant_index"].as_u64(), Some(1));
    assert_eq!(financial["cost_charged"].as_u64(), Some(40));
    assert_eq!(financial["budget_total"].as_u64(), Some(200));
    assert_eq!(financial["budget_remaining"].as_u64(), Some(160));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn async_evaluate_tool_call_supports_shared_kernel_concurrency() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};

    struct ConcurrentServer {
        barrier: Arc<Barrier>,
        current: Arc<AtomicUsize>,
        max_concurrent: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl ToolServerConnection for ConcurrentServer {
        fn server_id(&self) -> &str {
            "srv"
        }

        fn tool_names(&self) -> Vec<String> {
            vec!["echo".to_string()]
        }

        async fn invoke(
            &self,
            tool_name: &str,
            arguments: serde_json::Value,
            _bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<serde_json::Value, KernelError> {
            assert_eq!(tool_name, "echo");

            let concurrent = self.current.fetch_add(1, Ordering::SeqCst) + 1;
            let _ =
                self.max_concurrent
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |observed| {
                        (concurrent > observed).then_some(concurrent)
                    });

            self.barrier.wait();
            std::thread::sleep(Duration::from_millis(25));
            self.current.fetch_sub(1, Ordering::SeqCst);

            Ok(arguments)
        }
    }

    let barrier = Arc::new(Barrier::new(2));
    let max_concurrent = Arc::new(AtomicUsize::new(0));

    let mut configured_kernel = make_kernel(make_config());
    configured_kernel.register_tool_server(Box::new(ConcurrentServer {
        barrier: barrier.clone(),
        current: Arc::new(AtomicUsize::new(0)),
        max_concurrent: max_concurrent.clone(),
    }));

    let agent_kp = Keypair::generate();
    let capability = configured_kernel
        .issue_capability(
            &agent_kp.public_key(),
            make_scope(vec![ToolGrant {
                server_id: "srv".to_string(),
                tool_name: "echo".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![],
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }]),
            3600,
        )
        .unwrap();

    let kernel = Arc::new(configured_kernel);
    let make_request = |request_id: &str| ToolCallRequest {
        request_id: request_id.to_string(),
        capability: capability.clone(),
        tool_name: "echo".to_string(),
        server_id: "srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({ "request_id": request_id }),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: None,
        supplemental_authorization: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };

    let thread_a = {
        let kernel = kernel.clone();
        let request = make_request("req-a");
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move { kernel.evaluate_tool_call(&request).await })
        })
    };
    let thread_b = {
        let kernel = kernel.clone();
        let request = make_request("req-b");
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move { kernel.evaluate_tool_call(&request).await })
        })
    };

    let (response_a, response_b) = tokio::time::timeout(Duration::from_secs(2), async move {
        let response_a = thread_a.join().expect("thread a should not panic");
        let response_b = thread_b.join().expect("thread b should not panic");
        (response_a, response_b)
    })
    .await
    .expect("shared kernel evaluation should not deadlock");

    let response_a = response_a.unwrap();
    let response_b = response_b.unwrap();
    assert_eq!(response_a.verdict, Verdict::Allow);
    assert_eq!(response_b.verdict, Verdict::Allow);
    assert!(
        max_concurrent.load(Ordering::SeqCst) >= 2,
        "expected concurrent server invocations on a shared kernel"
    );
}

#[test]
fn tool_invocation_cost_serde_roundtrip() {
    let cost = ToolInvocationCost {
        units: 500,
        currency: "USD".to_string(),
        breakdown: None,
    };
    let json = serde_json::to_string(&cost).unwrap();
    let restored: ToolInvocationCost = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.units, 500);
    assert_eq!(restored.currency, "USD");
    assert!(restored.breakdown.is_none());

    // With breakdown
    let cost_with = ToolInvocationCost {
        units: 200,
        currency: "EUR".to_string(),
        breakdown: Some(serde_json::json!({"compute": 150, "network": 50})),
    };
    let json_with = serde_json::to_string(&cost_with).unwrap();
    let restored_with: ToolInvocationCost = serde_json::from_str(&json_with).unwrap();
    assert_eq!(restored_with.units, 200);
    assert!(restored_with.breakdown.is_some());
}

#[test]
fn cross_currency_reported_cost_attaches_oracle_evidence_and_converted_units() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_secs();
    let mut kernel = make_kernel(make_monetary_config());
    install_bounded_budget_authorities(&mut kernel, "cross-currency-oracle");
    kernel.set_price_oracle(Box::new(StaticPriceOracle::new([(
        ("ETH".to_string(), "USD".to_string()),
        Ok(ExchangeRate {
            base: "ETH".to_string(),
            quote: "USD".to_string(),
            rate_numerator: 300_000,
            rate_denominator: 100,
            updated_at: now.saturating_sub(45),
            fetched_at: now,
            source: "chainlink".to_string(),
            feed_reference: "0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70".to_string(),
            max_age_seconds: 600,
            conversion_margin_bps: 200,
            confidence_numerator: None,
            confidence_denominator: None,
        }),
    )])));
    kernel.register_tool_server(Box::new(MonetaryCostServer::new(
        "cost-srv",
        1_000_000_000_000_000,
        "ETH",
    )));

    let agent_kp = Keypair::generate();
    let grant = make_monetary_grant("cost-srv", "compute", 400, 1_000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-cross-currency-ok".to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            model_metadata: None,
            supplemental_authorization: None,
            federated_origin_kernel_id: None,
            declassification_grant: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    let metadata = response.receipt.metadata.as_ref().expect("metadata");
    let financial = metadata.get("financial").expect("financial");
    assert_eq!(financial["cost_charged"].as_u64(), Some(306));
    assert_eq!(financial["budget_remaining"].as_u64(), Some(694));
    assert_eq!(financial["settlement_status"], "settled");
    assert_eq!(financial["oracle_evidence"]["base"], "ETH");
    assert_eq!(financial["oracle_evidence"]["quote"], "USD");
    assert_eq!(
        financial["oracle_evidence"]["converted_cost_units"].as_u64(),
        Some(306)
    );
    assert_eq!(
        financial["cost_breakdown"]["oracle_conversion"]["status"],
        "applied"
    );
}

#[test]
fn cross_currency_without_oracle_keeps_provisional_charge_and_marks_failed_settlement() {
    let mut kernel = make_kernel(make_monetary_config());
    install_bounded_budget_authorities(&mut kernel, "cross-currency-no-oracle");
    kernel.register_tool_server(Box::new(MonetaryCostServer::new(
        "cost-srv",
        1_000_000_000_000_000,
        "ETH",
    )));

    let agent_kp = Keypair::generate();
    let grant = make_monetary_grant("cost-srv", "compute", 400, 1_000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-cross-currency-failed".to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            model_metadata: None,
            supplemental_authorization: None,
            federated_origin_kernel_id: None,
            declassification_grant: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    let metadata = response.receipt.metadata.as_ref().expect("metadata");
    let financial = metadata.get("financial").expect("financial");
    assert_eq!(financial["cost_charged"].as_u64(), Some(400));
    assert_eq!(financial["budget_remaining"].as_u64(), Some(600));
    assert_eq!(financial["settlement_status"], "failed");
    assert!(financial.get("oracle_evidence").is_none());
    assert_eq!(
        financial["cost_breakdown"]["oracle_conversion"]["status"],
        "failed"
    );
}

#[tokio::test]
async fn echo_server_invoke_with_cost_returns_none() {
    let server = EchoServer::new("srv-a", vec!["echo"]);
    let args = serde_json::json!({"msg": "hello"});
    let (value, cost) = server
        .invoke_with_cost("echo", args, None)
        .await
        .expect("invoke_with_cost should succeed");
    assert!(cost.is_none(), "EchoServer should return None cost");
    assert!(value.is_object());
}

// ---------------------------------------------------------------------------
// DPoP wiring tests
// ---------------------------------------------------------------------------
