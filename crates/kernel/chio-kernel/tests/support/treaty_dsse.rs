// Shared signed-treaty fixture for kernel unit and SQLite integration tests.
struct TreatyDsseAdmissionHook {
    origin_keypair: Keypair,
    local_keypair: Keypair,
}

impl TreatyDsseAdmissionHook {
    fn new(origin_keypair: Keypair, local_keypair: Keypair) -> Self {
        Self {
            origin_keypair,
            local_keypair,
        }
    }

    fn extensions(
        source_receipt: &ChioReceipt,
    ) -> Result<chio_federation::bilateral_dsse::BilateralPredicateExtensions, KernelError> {
        let capability_lease_ref = chio_federation::bilateral_dsse::CapabilityLeaseRef {
            lease_id: "lease-bilateral".to_string(),
            issuer: "kernel.org-a".to_string(),
            expires_at_unix_ms: 4_102_444_800_000,
            scope_digest: None,
        };
        let policy_evaluation_summary = chio_federation::bilateral_dsse::PolicyEvaluationSummary {
            server_a_verdict: chio_federation::bilateral_dsse::PolicyVerdict {
                verdict: "allow".to_string(),
                policy_id: "policy-a".to_string(),
                policy_version: "v1".to_string(),
                rationale_code: None,
            },
            server_b_verdict: chio_federation::bilateral_dsse::PolicyVerdict {
                verdict: "allow".to_string(),
                policy_id: "policy-b".to_string(),
                policy_version: "v1".to_string(),
                rationale_code: None,
            },
            joint_disposition: Some("allow".to_string()),
        };
        let treaty_binding_ref = chio_federation::bilateral_dsse::TreatyBindingRef {
            treaty_id: "treaty-buyer-vendor".to_string(),
            treaty_scope_sha256: "1".repeat(64),
            ladder_intersection_sha256: "2".repeat(64),
            admission_report_sha256: "3".repeat(64),
            continuation_sha256: "4".repeat(64),
            lineage_bundle_sha256: "5".repeat(64),
            action_class_id: "workflow.destructive.vendor_call".to_string(),
            consistency_model: "totally_ordered".to_string(),
            request_sha256: source_receipt.action.parameter_hash.clone(),
            outcome_sha256: source_receipt.content_hash.clone(),
            local_receipt_sha256: "7".repeat(64),
            remote_receipt_sha256: chio_core::crypto::sha256_hex(
                &chio_core::canonical::canonical_json_bytes(source_receipt)
                    .map_err(|error| KernelError::Internal(error.to_string()))?,
            ),
            lease_refs: vec!["lease-bilateral".to_string()],
            governance_refs: Vec::new(),
            signer_kernel_ids: vec!["kernel.org-a".to_string(), "kernel.org-b".to_string()],
        };
        Ok(
            chio_federation::bilateral_dsse::BilateralPredicateExtensions {
                capability_lease_ref: Some(capability_lease_ref),
                policy_evaluation_summary: Some(policy_evaluation_summary),
                governance_receipt_ref: None,
                consistency_anchor: Some("anchor-live".to_string()),
                consistency_model: Some("totally_ordered".to_string()),
                cross_org_visibility: Some("treaty_only".to_string()),
                treaty_binding_ref: Some(treaty_binding_ref),
            },
        )
    }

    fn verified_material(
        &self,
        context: &RuntimeAdmissionContext<'_>,
    ) -> Result<VerifiedFederationTreatyMaterial, KernelError> {
        let action = ToolCallAction::from_parameters(context.request.arguments.clone())
            .map_err(|error| KernelError::Internal(error.to_string()))?;
        let source_receipt = ChioReceipt::sign(
            ChioReceiptBody {
                id: format!("source-{}", context.request.request_id),
                timestamp: context.now_unix_secs,
                capability_id: context.request.capability.id.clone(),
                tool_server: context.request.server_id.clone(),
                tool_name: context.request.tool_name.clone(),
                action,
                decision: Some(Decision::Allow),
                receipt_kind: chio_core::receipt::kinds::ReceiptKind::MediatedDecision,
                boundary_class: chio_core::receipt::kinds::BoundaryClass::Prevent,
                observation_outcome: None,
                tool_origin: chio_core::receipt::kinds::ToolOrigin::CallerExecuted,
                redaction_mode: chio_core::receipt::kinds::RedactionMode::None,
                actor_chain: Vec::new(),
                content_hash: "6".repeat(64),
                policy_hash: "9".repeat(64),
                evidence: Vec::new(),
                metadata: None,
                trust_level: chio_core::receipt::kinds::TrustLevel::default(),
                tenant_id: None,
                kernel_key: self.local_keypair.public_key(),
                bbs_projection_version: None,
            },
            &self.local_keypair,
        )
        .map_err(|error| KernelError::Internal(error.to_string()))?;
        let envelope = chio_federation::bilateral_dsse::sign_chio_bilateral_dsse_envelope(
            &source_receipt,
            &self.origin_keypair,
            &self.local_keypair,
            "kernel.org-a",
            "kernel.org-b",
            &context.request.tool_name,
            context.now_unix_ms,
            Self::extensions(&source_receipt)?,
        )
        .map_err(|error| KernelError::Internal(error.to_string()))?;
        let origin_public_key = self.origin_keypair.public_key();
        let local_public_key = self.local_keypair.public_key();
        VerifiedFederationTreatyMaterial::verify(FederationTreatyVerification {
            envelope: &envelope,
            participant_kernel_ids: ["kernel.org-a", "kernel.org-b"],
            participant_public_keys: [&origin_public_key, &local_public_key],
            request: context.request,
            local_kernel_id: &context.local_kernel_id,
            admission: FederationTreatyAdmissionBinding {
                accepted: true,
                admission_report_sha256: &"3".repeat(64),
                treaty_id: "treaty-buyer-vendor",
                treaty_scope_sha256: &"1".repeat(64),
                ladder_intersection_sha256: &"2".repeat(64),
                action_class_id: "workflow.destructive.vendor_call",
                consistency_model: "totally_ordered",
                co_sign: "bilateral_required",
            },
            now_unix_ms: context.now_unix_ms,
        })
    }
}

impl RuntimeAdmissionHook for TreatyDsseAdmissionHook {
    fn name(&self) -> &str {
        "test-federation-treaty-dsse-admission"
    }

    fn evaluate(
        &self,
        context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        Ok(
            RuntimeAdmissionDecision::allow_with_verified_treaty_material(
                Some(serde_json::json!({
                    "chio_runtime": {
                        "admission_id": context.request.request_id,
                        "accepted": true,
                        "failure_code": null,
                    }
                })),
                self.verified_material(context)?,
            ),
        )
    }
}
