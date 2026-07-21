#[derive(Clone, Copy)]
enum OrdinaryFingerprintConflict {
    Server,
    Tool,
    Agent,
    Tenant,
    Dpop,
    ModelMetadata,
    FederatedOrigin,
    CallerReceiptMetadata,
}

fn ordinary_fingerprint_model_metadata(
    model_id: &str,
) -> chio_core::capability::scope::ModelMetadata {
    chio_core::capability::scope::ModelMetadata {
        model_id: model_id.to_string(),
        safety_tier: Some(chio_core::capability::scope::ModelSafetyTier::High),
        provider: Some("fingerprint-provider".to_string()),
        provenance_class:
            chio_core::capability::governance::ProvenanceEvidenceClass::Asserted,
    }
}

fn ordinary_fingerprint_request(
    kernel: &ChioKernel,
    agent: &Keypair,
    request_id: &str,
) -> (CapabilityToken, ToolGrant, ToolCallRequest) {
    let grant = make_invocation_limited_grant("fingerprint-srv", "execute", 8);
    let capability = make_capability(
        kernel,
        agent,
        make_scope(vec![grant.clone()]),
        3_600,
    );
    let arguments = serde_json::json!({
        "account": "acct-1",
        "amount": 7,
    });
    let dpop_proof = make_dpop_proof(
        agent,
        &capability,
        "fingerprint-srv",
        "execute",
        &arguments,
        "ordinary-fingerprint-dpop-a",
    );
    let request = ToolCallRequest {
        request_id: request_id.to_string(),
        capability: capability.clone(),
        tool_name: "execute".to_string(),
        server_id: "fingerprint-srv".to_string(),
        agent_id: agent.public_key().to_hex(),
        arguments,
        supplemental_authorization: None,
        dpop_proof: Some(dpop_proof),
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: Some(ordinary_fingerprint_model_metadata("fingerprint-model-a")),
        federated_origin_kernel_id: Some("origin-kernel-a".to_string()),
        declassification_grant: None,
    };
    (capability, grant, request)
}

fn ordered_caller_metadata(first: (&str, u64), second: (&str, u64)) -> serde_json::Value {
    let mut metadata = serde_json::Map::new();
    metadata.insert(first.0.to_string(), serde_json::json!(first.1));
    metadata.insert(second.0.to_string(), serde_json::json!(second.1));
    serde_json::Value::Object(metadata)
}

fn ordinary_fingerprint_federation_peer(
    kernel_id: &str,
    now: u64,
) -> chio_federation::trust_establishment::FederationPeer {
    chio_federation::trust_establishment::FederationPeer {
        kernel_id: kernel_id.to_string(),
        public_key: Keypair::generate().public_key(),
        conformance_tier: Default::default(),
        established_at: now,
        rotation_due: now.saturating_add(3_600),
        capabilities: chio_core::capability::features::CapabilityNegotiation::t1_default(),
        ladder_manifest_ref: None,
    }
}

fn ordinary_fingerprint_declassification_grant() -> chio_core_types::SignedDeclassificationGrant {
    let record_id = |value: &str| {
        chio_security_types::ports::RecordId::new(value)
            .unwrap_or_else(|error| panic!("declassification record id: {error}"))
    };
    let now = current_unix_timestamp();
    let body = chio_security_types::DeclassificationGrantBody::new(
        chio_security_types::DeclassificationGrantClaims {
            grant_id: chio_security_types::ports::GrantId::new("fingerprint-grant")
                .unwrap_or_else(|error| panic!("declassification grant id: {error}")),
            capability_id: record_id("fingerprint-capability"),
            tenant_id: chio_security_types::ports::TenantId::new("fingerprint-tenant")
                .unwrap_or_else(|error| panic!("declassification tenant id: {error}")),
            subject_id: chio_security_types::flow::PrincipalId::new("fingerprint-subject")
                .unwrap_or_else(|error| panic!("declassification subject id: {error}")),
            agent_id: record_id("fingerprint-agent"),
            session_id: chio_security_types::ports::SessionId::new("fingerprint-session")
                .unwrap_or_else(|error| panic!("declassification session id: {error}")),
            source_label_hash: chio_security_types::ports::Digest32::new([1; 32]),
            target_label: chio_security_types::flow::InformationLabel::bottom(),
            destination_id: chio_security_types::ports::DestinationId::new(
                "fingerprint-destination",
            )
            .unwrap_or_else(|error| panic!("declassification destination id: {error}")),
            tool_name: record_id("fingerprint-tool"),
            purpose: chio_security_types::flow::DeclassificationPurpose::new("fingerprint")
                .unwrap_or_else(|error| panic!("declassification purpose: {error}")),
            request_hash: chio_security_types::ports::Digest32::new([2; 32]),
            issued_at_unix_seconds: now,
            expires_at_unix_seconds: now.saturating_add(300),
            authority_key_id: record_id("fingerprint-authority"),
        },
    )
    .unwrap_or_else(|error| panic!("declassification grant body: {error}"));
    chio_core_types::SignedDeclassificationGrant::sign(body, &Keypair::generate())
        .unwrap_or_else(|error| panic!("signed declassification grant: {error}"))
}

#[test]
fn ordinary_request_fingerprint_is_domain_separated_canonical_and_presence_sensitive() {
    let kernel = make_admission_saga_kernel();
    let agent = Keypair::generate();
    let (_capability, _grant, request) =
        ordinary_fingerprint_request(&kernel, &agent, "ordinary-fingerprint-vector");
    let metadata_ab = ordered_caller_metadata(("alpha", 1), ("beta", 2));
    let metadata_ba = ordered_caller_metadata(("beta", 2), ("alpha", 1));
    let _tenant = kernel.scope_receipt_tenant_id_for_request(
        &request.request_id,
        Some("tenant-fingerprint-a".to_string()),
    );

    let baseline = kernel
        .ordinary_request_fingerprint_hash(
            &request,
            &kernel.config.policy_hash,
            Some(&metadata_ab),
        )
        .expect("ordinary request fingerprint");
    let reordered = kernel
        .ordinary_request_fingerprint_hash(
            &request,
            &kernel.config.policy_hash,
            Some(&metadata_ba),
        )
        .expect("reordered ordinary request fingerprint");
    assert_eq!(baseline, reordered);
    assert_eq!(baseline.len(), 64);
    assert!(baseline.bytes().all(|byte| byte.is_ascii_hexdigit()));

    let without_metadata = kernel
        .ordinary_request_fingerprint_hash(&request, &kernel.config.policy_hash, None)
        .expect("metadata-absent ordinary request fingerprint");
    let explicit_null_metadata = kernel
        .ordinary_request_fingerprint_hash(
            &request,
            &kernel.config.policy_hash,
            Some(&serde_json::Value::Null),
        )
        .expect("metadata-null ordinary request fingerprint");
    assert_ne!(without_metadata, explicit_null_metadata);
    let changed_caller_metadata = serde_json::json!({"alpha": 1, "beta": 3});
    assert_ne!(
        baseline,
        kernel
            .ordinary_request_fingerprint_hash(
                &request,
                &kernel.config.policy_hash,
                Some(&changed_caller_metadata),
            )
            .expect("changed-caller-metadata ordinary request fingerprint")
    );

    let mut changed = request.clone();
    let mut vectors = Vec::new();
    changed.request_id = "ordinary-fingerprint-vector-other".to_string();
    vectors.push(changed);
    let mut changed = request.clone();
    changed.capability.id = "ordinary-fingerprint-capability-other".to_string();
    vectors.push(changed);
    let mut changed = request.clone();
    changed.capability.subject = Keypair::generate().public_key();
    vectors.push(changed);
    let mut changed = request.clone();
    changed.capability.expires_at = changed.capability.expires_at.saturating_add(1);
    vectors.push(changed);
    let mut changed = request.clone();
    changed.server_id = "fingerprint-srv-other".to_string();
    vectors.push(changed);
    let mut changed = request.clone();
    changed.tool_name = "execute-other".to_string();
    vectors.push(changed);
    let mut changed = request.clone();
    changed.agent_id = Keypair::generate().public_key().to_hex();
    vectors.push(changed);
    let mut changed = request.clone();
    changed.arguments = serde_json::json!({"account": "acct-2", "amount": 7});
    vectors.push(changed);
    let mut changed = request.clone();
    changed.dpop_proof = None;
    vectors.push(changed);
    let mut changed = request.clone();
    changed.model_metadata = None;
    vectors.push(changed);
    let mut changed = request.clone();
    changed.federated_origin_kernel_id = Some("origin-kernel-b".to_string());
    vectors.push(changed);

    for changed in vectors {
        let changed_hash = kernel
            .ordinary_request_fingerprint_hash(
                &changed,
                &kernel.config.policy_hash,
                Some(&metadata_ab),
            )
            .expect("changed ordinary request fingerprint");
        assert_ne!(baseline, changed_hash);
    }
    assert_ne!(
        baseline,
        kernel
            .ordinary_request_fingerprint_hash(
                &request,
                &"44".repeat(32),
                Some(&metadata_ab),
            )
            .expect("changed-policy ordinary request fingerprint")
    );
    {
        let _changed_tenant = kernel.scope_receipt_tenant_id_for_request(
            &request.request_id,
            Some("tenant-fingerprint-b".to_string()),
        );
        assert_ne!(
            baseline,
            kernel
                .ordinary_request_fingerprint_hash(
                    &request,
                    &kernel.config.policy_hash,
                    Some(&metadata_ab),
                )
                .expect("changed-tenant ordinary request fingerprint")
        );
    }
}

#[test]
fn ordinary_request_fingerprint_binds_all_presented_authority_artifacts() {
    let (mut kernel, capability, _grant, intent, mut request, now) = threshold_test_fixture();
    request.request_id = "ordinary-fingerprint-authority-artifacts".to_string();
    install_valid_threshold_artifacts(&mut kernel, &capability, &intent, &mut request, now);
    let caller_metadata = serde_json::json!({"caller": {"channel": "api"}});
    let _tenant = kernel.scope_receipt_tenant_id_for_request(
        &request.request_id,
        Some("tenant-fingerprint-authority".to_string()),
    );
    let hash = |candidate: &ToolCallRequest| {
        kernel
            .ordinary_request_fingerprint_hash(
                candidate,
                &kernel.config.policy_hash,
                Some(&caller_metadata),
            )
            .expect("authority-artifact ordinary request fingerprint")
    };
    let baseline = hash(&request);

    let mut reordered_approvals = request.clone();
    reordered_approvals.approval_tokens.reverse();
    assert_eq!(baseline, hash(&reordered_approvals));

    let mut changed = request.clone();
    changed.governed_intent = None;
    assert_ne!(baseline, hash(&changed));
    let mut changed = request.clone();
    changed.threshold_approval_proposal = None;
    assert_ne!(baseline, hash(&changed));
    let mut changed = request.clone();
    changed.approval_tokens.pop();
    assert_ne!(baseline, hash(&changed));

    let supplemental = chio_core::OpaqueSupplementalAuthorization::new(
        "fingerprint-supplemental-a",
        vec![1, 2, 3],
    )
    .expect("supplemental authorization");
    let mut with_supplemental = request.clone();
    with_supplemental.supplemental_authorization = Some(supplemental);
    let supplemental_baseline = hash(&with_supplemental);
    assert_ne!(baseline, supplemental_baseline);
    let mut changed_reference = with_supplemental.clone();
    changed_reference.supplemental_authorization = Some(
        chio_core::OpaqueSupplementalAuthorization::new(
            "fingerprint-supplemental-b",
            vec![1, 2, 3],
        )
        .expect("changed supplemental reference"),
    );
    assert_ne!(supplemental_baseline, hash(&changed_reference));
    let mut changed_artifact = with_supplemental.clone();
    changed_artifact.supplemental_authorization = Some(
        chio_core::OpaqueSupplementalAuthorization::new(
            "fingerprint-supplemental-a",
            vec![1, 2, 4],
        )
        .expect("changed supplemental artifact"),
    );
    assert_ne!(supplemental_baseline, hash(&changed_artifact));

    let nonce = mint_nonce_for_request(
        &kernel,
        &capability,
        &request,
        &crate::execution_nonce::ExecutionNonceConfig::default(),
    );
    let mut with_nonce = request.clone();
    with_nonce.execution_nonce = Some(nonce.clone());
    let nonce_baseline = hash(&with_nonce);
    assert_ne!(baseline, nonce_baseline);
    let mut changed_nonce_payload = with_nonce;
    changed_nonce_payload
        .execution_nonce
        .as_mut()
        .expect("presented execution nonce")
        .nonce
        .expires_at += 1;
    assert_eq!(
        changed_nonce_payload
            .execution_nonce
            .as_ref()
            .expect("changed execution nonce")
            .nonce_id(),
        nonce.nonce_id()
    );
    assert_ne!(nonce_baseline, hash(&changed_nonce_payload));

    let mut with_declassification = request;
    with_declassification.declassification_grant =
        Some(ordinary_fingerprint_declassification_grant());
    assert_ne!(baseline, hash(&with_declassification));
}

fn assert_ordinary_fingerprint_conflict_is_pre_mutation(change: OrdinaryFingerprintConflict) {
    let now = current_unix_timestamp();
    let mut kernel = make_admission_saga_kernel().with_federation_peers(vec![
        ordinary_fingerprint_federation_peer("origin-kernel-a", now),
        ordinary_fingerprint_federation_peer("origin-kernel-b", now),
    ]);
    let operation_store = durable_test_admission_operation_store("ordinary-fingerprint-operations");
    let budget_store = durable_atomic_test_budget_store("ordinary-fingerprint-budget");
    kernel
        .set_admission_operation_store_handle(operation_store.clone())
        .expect("ordinary fingerprint operation store");
    kernel
        .set_budget_store_handle(budget_store.clone())
        .expect("ordinary fingerprint budget store");
    let agent = Keypair::generate();
    let (capability, grant, request) = ordinary_fingerprint_request(
        &kernel,
        &agent,
        &format!("ordinary-fingerprint-conflict-{}", change.label()),
    );
    let first_metadata = serde_json::json!({"caller": {"route": "alpha"}});
    let second_metadata = if matches!(change, OrdinaryFingerprintConflict::CallerReceiptMetadata) {
        serde_json::json!({"caller": {"route": "beta"}})
    } else {
        first_metadata.clone()
    };
    let first_tenant = "tenant-fingerprint-a";
    let second_tenant = if matches!(change, OrdinaryFingerprintConflict::Tenant) {
        "tenant-fingerprint-b"
    } else {
        first_tenant
    };

    let first_fingerprint;
    let first_mutation = {
        let _tenant = kernel.scope_receipt_tenant_id_for_request(
            &request.request_id,
            Some(first_tenant.to_string()),
        );
        first_fingerprint = kernel
            .ordinary_request_fingerprint_hash(
                &request,
                &kernel.config.policy_hash,
                Some(&first_metadata),
            )
            .expect("first ordinary fingerprint");
        kernel
            .coordinate_ordinary_protocol_admission(
                &request,
                &capability,
                0,
                &grant,
                false,
                Some(&first_metadata),
                current_unix_timestamp(),
            )
            .expect("first ordinary admission")
    };
    let first_admission = first_mutation
        .ordinary_admission()
        .expect("operation-owned ordinary mutation");
    let hold_id = first_admission.hold_id.clone();
    let operation_id = first_admission.operation_id.clone();
    let hold_before = budget_store
        .get_budget_hold(&hold_id)
        .expect("first hold lookup")
        .expect("first hold");
    let usage_before = budget_store
        .get_usage(&capability.id, 0)
        .expect("first usage lookup");
    let operations_before = operation_store
        .list_unresolved(Some(AdmissionOperationKind::ToolDispatch), 16)
        .expect("first operation inventory");
    let cleanup_before = operation_store
        .load_cleanup_actions(&operation_id)
        .expect("first cleanup inventory");

    let mut changed_request = request.clone();
    match change {
        OrdinaryFingerprintConflict::Server => {
            changed_request.server_id = "fingerprint-srv-other".to_string();
        }
        OrdinaryFingerprintConflict::Tool => {
            changed_request.tool_name = "execute-other".to_string();
        }
        OrdinaryFingerprintConflict::Agent => {
            changed_request.agent_id = Keypair::generate().public_key().to_hex();
        }
        OrdinaryFingerprintConflict::Dpop => {
            changed_request.dpop_proof = Some(make_dpop_proof(
                &agent,
                &capability,
                &request.server_id,
                &request.tool_name,
                &request.arguments,
                "ordinary-fingerprint-dpop-b",
            ));
        }
        OrdinaryFingerprintConflict::ModelMetadata => {
            changed_request.model_metadata =
                Some(ordinary_fingerprint_model_metadata("fingerprint-model-b"));
        }
        OrdinaryFingerprintConflict::FederatedOrigin => {
            changed_request.federated_origin_kernel_id = Some("origin-kernel-b".to_string());
        }
        OrdinaryFingerprintConflict::Tenant
        | OrdinaryFingerprintConflict::CallerReceiptMetadata => {}
    }

    let (second_fingerprint, conflict) = {
        let _tenant = kernel.scope_receipt_tenant_id_for_request(
            &changed_request.request_id,
            Some(second_tenant.to_string()),
        );
        let fingerprint = kernel
            .ordinary_request_fingerprint_hash(
                &changed_request,
                &kernel.config.policy_hash,
                Some(&second_metadata),
            )
            .expect("second ordinary fingerprint");
        let conflict = kernel
            .coordinate_ordinary_protocol_admission(
                &changed_request,
                &capability,
                0,
                &grant,
                false,
                Some(&second_metadata),
                current_unix_timestamp(),
            )
            .err()
            .expect("changed request must conflict with the existing hold");
        (fingerprint, conflict)
    };
    assert_ne!(first_fingerprint, second_fingerprint);
    assert!(conflict.to_string().contains("budget_hold_id"), "{conflict}");
    assert_eq!(
        budget_store
            .get_budget_hold(&hold_id)
            .expect("conflict hold lookup"),
        Some(hold_before)
    );
    assert_eq!(
        budget_store
            .get_usage(&capability.id, 0)
            .expect("conflict usage lookup"),
        usage_before
    );
    assert_eq!(
        operation_store
            .list_unresolved(Some(AdmissionOperationKind::ToolDispatch), 16)
            .expect("conflict operation inventory"),
        operations_before
    );
    assert_eq!(
        operation_store
            .load_cleanup_actions(&operation_id)
            .expect("conflict cleanup inventory"),
        cleanup_before
    );
}

impl OrdinaryFingerprintConflict {
    fn label(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Tool => "tool",
            Self::Agent => "agent",
            Self::Tenant => "tenant",
            Self::Dpop => "dpop",
            Self::ModelMetadata => "model-metadata",
            Self::FederatedOrigin => "federated-origin",
            Self::CallerReceiptMetadata => "caller-receipt-metadata",
        }
    }
}

#[test]
fn ordinary_same_request_security_field_changes_conflict_before_budget_mutation() {
    for change in [
        OrdinaryFingerprintConflict::Server,
        OrdinaryFingerprintConflict::Tool,
        OrdinaryFingerprintConflict::Agent,
        OrdinaryFingerprintConflict::Tenant,
        OrdinaryFingerprintConflict::Dpop,
        OrdinaryFingerprintConflict::ModelMetadata,
        OrdinaryFingerprintConflict::FederatedOrigin,
        OrdinaryFingerprintConflict::CallerReceiptMetadata,
    ] {
        assert_ordinary_fingerprint_conflict_is_pre_mutation(change);
    }
}

#[derive(Clone, Copy)]
enum ThresholdFingerprintConflict {
    Server,
    Tool,
    Agent,
    Tenant,
    Dpop,
    ModelMetadata,
    FederatedOrigin,
    CallerReceiptMetadata,
}

fn prepare_threshold_fingerprint_operation(
    kernel: &ChioKernel,
    request: &ToolCallRequest,
    capability: &CapabilityToken,
    verified: &crate::threshold_approval::VerifiedGovernedApprovalAdmission,
    caller_receipt_metadata: Option<&serde_json::Value>,
    now: u64,
) -> (
    crate::threshold_approval::PreparedGovernedToolAdmission,
    crate::kernel::admission_coordinator::ThresholdProtocolPreparation,
) {
    let protocol = kernel
        .prepare_threshold_protocol_admission(request, capability, 0, now)
        .expect("threshold protocol preparation");
    let request_fingerprint_hash = kernel
        .ordinary_request_fingerprint_hash(
            request,
            &kernel.config.policy_hash,
            caller_receipt_metadata,
        )
        .expect("threshold request fingerprint");
    let coordinator_authority_id = format!("kernel:{}", kernel.public_key().to_hex());
    let prepared = crate::threshold_approval::prepare_governed_tool_admission_operation(
        crate::threshold_approval::GovernedToolAdmissionOperationInput {
            coordinator_authority_id: &coordinator_authority_id,
            request_id: &request.request_id,
            capability_id: &capability.id,
            authorization_capability_hash: verified.authorization_capability_hash(),
            request_fingerprint_hash: &request_fingerprint_hash,
            governed_intent_hash: verified.governed_intent_hash(),
            policy_hash: &kernel.config.policy_hash,
            verified_approval: verified,
            broker_attempt_id: protocol.broker_attempt_id(),
            budget_hold_id: Some(protocol.hold_id()),
            supplemental_authorization_reference: request
                .supplemental_authorization
                .as_ref()
                .map(chio_core::OpaqueSupplementalAuthorization::reference),
            supplemental_authorization_digest: protocol.supplemental_digest(),
            execution_nonce_id: request
                .execution_nonce
                .as_ref()
                .map(crate::execution_nonce::SignedExecutionNonce::nonce_id),
            coordinator_lease_epoch: 1,
        },
    )
    .expect("prepared threshold fingerprint operation");
    (prepared, protocol)
}

fn assert_threshold_fingerprint_conflict_is_pre_mutation(change: ThresholdFingerprintConflict) {
    let (kernel, capability, grant, intent, mut request, now) = threshold_test_fixture();
    let mut kernel = kernel.with_federation_peers(vec![ordinary_fingerprint_federation_peer(
        "threshold-origin-kernel",
        now,
    )]);
    request.request_id = format!("threshold-fingerprint-conflict-{}", change.label());
    install_valid_threshold_artifacts(&mut kernel, &capability, &intent, &mut request, now);
    let operation_store =
        durable_test_admission_operation_store("threshold-fingerprint-operations");
    let budget_store = durable_atomic_test_budget_store("threshold-fingerprint-budget");
    let approval_store = std::sync::Arc::new(DurableThresholdApprovalStore::new());
    kernel
        .set_admission_operation_store_handle(operation_store.clone())
        .expect("threshold fingerprint operation store");
    kernel
        .set_budget_store_handle(budget_store.clone())
        .expect("threshold fingerprint budget store");
    kernel
        .set_approval_store_handle(approval_store.clone())
        .expect("threshold fingerprint approval store");
    let verified = kernel
        .validate_governed_transaction(&request, &capability, &grant, None, now)
        .expect("threshold governed validation")
        .expect("governed threshold admission")
        .verified_governed_approval
        .expect("verified threshold approval");
    let first_caller_metadata = serde_json::json!({"caller": {"channel": "threshold-a"}});
    let second_caller_metadata =
        if matches!(change, ThresholdFingerprintConflict::CallerReceiptMetadata) {
            serde_json::json!({"caller": {"channel": "threshold-b"}})
        } else {
            first_caller_metadata.clone()
        };

    let first_mutation = {
        let _tenant = kernel.scope_receipt_tenant_id_for_request(
            &request.request_id,
            Some("tenant-threshold-a".to_string()),
        );
        let (prepared, protocol) = prepare_threshold_fingerprint_operation(
            &kernel,
            &request,
            &capability,
            &verified,
            Some(&first_caller_metadata),
            now,
        );
        kernel
            .reserve_threshold_tool_admission(
                crate::kernel::admission_coordinator::ThresholdToolAdmissionContext {
                    request: &request,
                    cap: &capability,
                    grant_index: 0,
                    grant: &grant,
                    now,
                    payment_mode:
                        crate::kernel::admission_coordinator::ThresholdPaymentMode::Dispatch,
                },
                prepared,
                protocol,
                None,
            )
            .expect("first threshold fingerprint admission")
            .1
    };
    let first_admission = first_mutation
        .ordinary_admission()
        .expect("operation-owned threshold mutation");
    let hold_id = first_admission.hold_id.clone();
    let operation_id = first_admission.operation_id.clone();
    let first_binding = first_admission.request_binding_hash.clone();
    let hold_before = budget_store
        .get_budget_hold(&hold_id)
        .expect("first threshold hold lookup")
        .expect("first threshold hold");
    let usage_before = budget_store
        .get_usage(&capability.id, 0)
        .expect("first threshold usage lookup");
    let approval_before = approval_store
        .get_approval_reservation(&operation_id)
        .expect("first threshold approval lookup");
    let operations_before = operation_store
        .list_unresolved(Some(AdmissionOperationKind::ToolDispatch), 16)
        .expect("first threshold operation inventory");
    let cleanup_before = operation_store
        .load_cleanup_actions(&operation_id)
        .expect("first threshold cleanup inventory");

    let mut changed_request = request.clone();
    match change {
        ThresholdFingerprintConflict::Server => {
            changed_request.server_id = "threshold-target-other".to_string();
        }
        ThresholdFingerprintConflict::Tool => {
            changed_request.tool_name = "threshold-tool-other".to_string();
        }
        ThresholdFingerprintConflict::Agent => {
            changed_request.agent_id = Keypair::generate().public_key().to_hex();
        }
        ThresholdFingerprintConflict::Dpop => {
            changed_request.dpop_proof = Some(make_dpop_proof(
                &Keypair::generate(),
                &capability,
                &request.server_id,
                &request.tool_name,
                &request.arguments,
                "threshold-fingerprint-dpop",
            ));
        }
        ThresholdFingerprintConflict::ModelMetadata => {
            changed_request.model_metadata =
                Some(ordinary_fingerprint_model_metadata("threshold-fingerprint-model"));
        }
        ThresholdFingerprintConflict::FederatedOrigin => {
            changed_request.federated_origin_kernel_id =
                Some("threshold-origin-kernel".to_string());
        }
        ThresholdFingerprintConflict::Tenant
        | ThresholdFingerprintConflict::CallerReceiptMetadata => {}
    }
    let second_tenant = if matches!(change, ThresholdFingerprintConflict::Tenant) {
        "tenant-threshold-b"
    } else {
        "tenant-threshold-a"
    };
    let (second_binding, conflict) = {
        let _tenant = kernel.scope_receipt_tenant_id_for_request(
            &changed_request.request_id,
            Some(second_tenant.to_string()),
        );
        let (prepared, protocol) = prepare_threshold_fingerprint_operation(
            &kernel,
            &changed_request,
            &capability,
            &verified,
            Some(&second_caller_metadata),
            now,
        );
        let binding = prepared.operation().request_binding_hash().to_string();
        let conflict = kernel
            .reserve_threshold_tool_admission(
                crate::kernel::admission_coordinator::ThresholdToolAdmissionContext {
                    request: &changed_request,
                    cap: &capability,
                    grant_index: 0,
                    grant: &grant,
                    now,
                    payment_mode:
                        crate::kernel::admission_coordinator::ThresholdPaymentMode::Dispatch,
                },
                prepared,
                protocol,
                None,
            )
            .err()
            .expect("changed threshold request must conflict with the existing hold");
        (binding, conflict)
    };
    assert_ne!(first_binding, second_binding);
    assert!(conflict.to_string().contains("budget_hold_id"), "{conflict}");
    assert_eq!(
        budget_store
            .get_budget_hold(&hold_id)
            .expect("conflict threshold hold lookup"),
        Some(hold_before)
    );
    assert_eq!(
        budget_store
            .get_usage(&capability.id, 0)
            .expect("conflict threshold usage lookup"),
        usage_before
    );
    assert_eq!(
        approval_store
            .get_approval_reservation(&operation_id)
            .expect("conflict threshold approval lookup"),
        approval_before
    );
    assert_eq!(
        operation_store
            .list_unresolved(Some(AdmissionOperationKind::ToolDispatch), 16)
            .expect("conflict threshold operation inventory"),
        operations_before
    );
    assert_eq!(
        operation_store
            .load_cleanup_actions(&operation_id)
            .expect("conflict threshold cleanup inventory"),
        cleanup_before
    );
}

impl ThresholdFingerprintConflict {
    fn label(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Tool => "tool",
            Self::Agent => "agent",
            Self::Tenant => "tenant",
            Self::Dpop => "dpop",
            Self::ModelMetadata => "model-metadata",
            Self::FederatedOrigin => "federated-origin",
            Self::CallerReceiptMetadata => "caller-receipt-metadata",
        }
    }
}

#[test]
fn threshold_same_request_security_field_changes_conflict_before_mutation() {
    for change in [
        ThresholdFingerprintConflict::Server,
        ThresholdFingerprintConflict::Tool,
        ThresholdFingerprintConflict::Agent,
        ThresholdFingerprintConflict::Tenant,
        ThresholdFingerprintConflict::Dpop,
        ThresholdFingerprintConflict::ModelMetadata,
        ThresholdFingerprintConflict::FederatedOrigin,
        ThresholdFingerprintConflict::CallerReceiptMetadata,
    ] {
        assert_threshold_fingerprint_conflict_is_pre_mutation(change);
    }
}
