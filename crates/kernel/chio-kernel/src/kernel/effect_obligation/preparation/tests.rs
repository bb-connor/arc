use super::*;

fn fixture() -> (DischargeBinding, PreparedFaultReceipt, chio_core::Keypair) {
    let keypair = chio_core::Keypair::generate();
    let action = ToolCallAction::from_parameters(serde_json::json!({"input": 1})).unwrap();
    let binding = DischargeBinding {
        evaluation_id: "evaluation-a".into(),
        namespace: "namespace-a".into(),
        request_id: "request-a".into(),
        operation_id: None,
        capability_id: "capability-a".into(),
        server_id: "server-a".into(),
        tool_name: "tool-a".into(),
        policy_hash: "policy-a".into(),
        parameter_hash: action.parameter_hash.clone(),
        grant_index: 2,
    };
    let body = ChioReceiptBody {
        id: "prepared-fault".into(),
        timestamp: 1_700_000_000,
        capability_id: binding.capability_id.clone(),
        tool_server: binding.server_id.clone(),
        tool_name: binding.tool_name.clone(),
        action,
        decision: Some(Decision::Cancelled {
            reason: "fault".into(),
        }),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash: chio_core::crypto::sha256_hex(b"null"),
        policy_hash: binding.policy_hash.clone(),
        evidence: Vec::new(),
        metadata: Some(serde_json::json!({
            "receipt_context": {
                "request_id": binding.request_id,
                "request_namespace_digest": binding.namespace,
                "evaluation_id": binding.evaluation_id
            },
            "attribution": { "grant_index": binding.grant_index }
        })),
        trust_level: Default::default(),
        tenant_id: None,
        kernel_key: keypair.public_key(),
        bbs_projection_version: None,
    };
    (
        binding,
        PreparedFaultReceipt {
            body,
            canonical_content: b"null".to_vec(),
        },
        keypair,
    )
}

#[test]
fn a_terminal_receipt_is_bound_to_its_evaluation_and_authority() {
    let (binding, fault, keypair) = fixture();
    let receipt = ChioReceipt::sign(fault.body, &keypair).unwrap();
    assert!(binding.validate_receipt(&receipt).is_ok());
    for field in [
        "evaluation",
        "namespace",
        "request",
        "operation",
        "capability",
        "server",
        "tool",
        "policy",
        "input",
        "grant",
    ] {
        let mut wrong = binding.clone();
        match field {
            "evaluation" => wrong.evaluation_id = "another-evaluation".into(),
            "namespace" => wrong.namespace = "another-namespace".into(),
            "request" => wrong.request_id = "another-request".into(),
            "operation" => wrong.operation_id = Some("another-operation".into()),
            "capability" => wrong.capability_id = "another-capability".into(),
            "server" => wrong.server_id = "another-server".into(),
            "tool" => wrong.tool_name = "another-tool".into(),
            "policy" => wrong.policy_hash = "another-policy".into(),
            "input" => wrong.parameter_hash = "another-input".into(),
            "grant" => wrong.grant_index = 3,
            _ => unreachable!(),
        }
        assert!(
            wrong.validate_receipt(&receipt).is_err(),
            "wrong {field} binding"
        );
    }
}

#[test]
fn an_audit_receipt_or_inconsistent_action_cannot_discharge_an_effect() {
    let (binding, fault, keypair) = fixture();
    let mut receipt = ChioReceipt::sign(fault.body, &keypair).unwrap();
    receipt.action.parameters = serde_json::json!({"input": 2});
    assert!(binding.validate_receipt(&receipt).is_err());
    receipt.action.parameters = serde_json::json!({"input": 1});
    receipt.receipt_kind = chio_core::receipt::kinds::ReceiptKind::TraceObservation;
    receipt.decision = None;
    assert!(binding.validate_receipt(&receipt).is_err());
}

#[test]
fn released_payment_truth_survives_fault_preparation() {
    let (_, mut fault, keypair) = fixture();
    let authorization = PaymentAuthorization {
        authorization_id: "authorization-a".into(),
        state: crate::payment::PaymentAuthorizationState::Held,
        metadata: serde_json::Value::Null,
    };
    let result = crate::payment::PaymentResult {
        transaction_id: "release-a".into(),
        settlement_status: crate::payment::RailSettlementStatus::Released,
        metadata: serde_json::Value::Null,
    };
    fault.observe_payment_result(&authorization, &result, 100, true);
    let receipt = ChioReceipt::sign(fault.body, &keypair).unwrap();
    let financial = receipt.metadata.as_ref().unwrap().get("financial").unwrap();
    assert_eq!(financial.get("cost_charged"), Some(&serde_json::json!(0)));
    assert_eq!(
        financial.get("rail_status"),
        Some(&serde_json::json!("released"))
    );
    assert_eq!(
        financial.get("payment_release_confirmed"),
        Some(&serde_json::json!(true))
    );
    assert_eq!(
        financial.get("payment_authorization_retained"),
        Some(&serde_json::json!(false))
    );
}

#[test]
fn unpredictable_payment_references_are_bounded_and_exactly_hashed() {
    let (_, mut fault, keypair) = fixture();
    let reference = "é".repeat(257);
    let body_bytes = chio_core::canonical::canonical_json_bytes(&fault.body)
        .unwrap()
        .len();
    fault.observe_economics(Some(&serde_json::json!({
        "financial": {
            "payment_reference": reference,
            "cost_charged": u64::MAX,
            "settlement_status": "settled",
            "payment_authorization_retained": true,
            "oracle_evidence": "not retained".repeat(100_000)
        },
        "budget_authority": { "terminal": {
            "disposition": "captured", "event_id": reference,
            "budget_commit_index": u64::MAX, "realized_spend_units": u64::MAX
        }}
    })));
    let encoded = chio_core::canonical::canonical_json_bytes(&fault.body).unwrap();
    assert!(encoded.len() < body_bytes + FAULT_RESERVE_HEADROOM);
    let receipt = ChioReceipt::sign(fault.body, &keypair).unwrap();
    let metadata = receipt.metadata.unwrap();
    let financial = metadata.get("financial").unwrap();
    assert_eq!(
        financial.get("payment_reference"),
        Some(&serde_json::Value::Null)
    );
    assert_eq!(
        financial.get("payment_reference_sha256"),
        Some(&serde_json::json!(chio_core::crypto::sha256_hex(
            reference.as_bytes()
        )))
    );
    assert_eq!(
        financial.get("payment_reference_omitted"),
        Some(&serde_json::json!(true))
    );
    assert_eq!(
        financial.get("cost_charged_decimal"),
        Some(&serde_json::json!(u64::MAX.to_string()))
    );
    assert_eq!(
        financial.get("payment_authorization_retained"),
        Some(&serde_json::json!(false))
    );
    assert!(financial.get("oracle_evidence").is_none());
    assert_eq!(
        metadata.pointer("/budget_authority/terminal/realized_spend_units_decimal"),
        Some(&serde_json::json!(u64::MAX.to_string()))
    );
}

#[test]
fn exact_reference_boundary_preserves_bytes_without_a_false_reference() {
    for bytes in [511, 512, 513] {
        let reference = "x".repeat(bytes);
        let mut bounded = serde_json::Map::new();
        retain_bounded_reference(&mut bounded, "reference", &serde_json::json!(reference));
        if bytes <= 512 {
            assert_eq!(
                bounded.get("reference"),
                Some(&serde_json::json!(reference))
            );
            assert!(bounded.get("reference_omitted").is_none());
        } else {
            assert_eq!(bounded.get("reference"), Some(&serde_json::Value::Null));
            assert_eq!(
                bounded.get("reference_sha256"),
                Some(&serde_json::json!(chio_core::crypto::sha256_hex(
                    reference.as_bytes()
                )))
            );
            assert_eq!(
                bounded.get("reference_omitted"),
                Some(&serde_json::json!(true))
            );
        }
    }
}

#[test]
fn post_effect_ownership_has_no_copy_or_plain_result_escape() {
    trait AmbiguousIfClone<A> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfClone<()> for T {}
    impl<T: Clone> AmbiguousIfClone<u8> for T {}
    trait AmbiguousIfDefault<A> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfDefault<()> for T {}
    impl<T: Default> AmbiguousIfDefault<u8> for T {}
    let _ = <PostEffectObligation<'static> as AmbiguousIfClone<_>>::marker;
    let _ = <Discharged<'static> as AmbiguousIfClone<_>>::marker;
    let _ = <PostEffectObligation<'static> as AmbiguousIfDefault<_>>::marker;
    let _ = <Discharged<'static> as AmbiguousIfDefault<_>>::marker;
    let _: fn(PostEffectObligation<'static>, ObservedToolReturn) -> Discharged<'static> =
        run_post_effect;
}
