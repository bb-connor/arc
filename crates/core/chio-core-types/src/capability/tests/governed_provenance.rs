use super::*;

#[test]
fn governed_call_chain_provenance_separates_asserted_and_verified_views() {
    let asserted_context = GovernedCallChainContext {
        chain_id: "chain-prov-1".to_string(),
        parent_request_id: "req-parent-prov-1".to_string(),
        parent_receipt_id: Some("rc-parent-prov-1".to_string()),
        origin_subject: "origin-asserted".to_string(),
        delegator_subject: "delegator-asserted".to_string(),
    };
    let verified_context = GovernedCallChainContext {
        chain_id: "chain-prov-1".to_string(),
        parent_request_id: "req-parent-prov-1".to_string(),
        parent_receipt_id: Some("rc-parent-prov-1".to_string()),
        origin_subject: "origin-verified".to_string(),
        delegator_subject: "delegator-verified".to_string(),
    };
    let provenance = GovernedCallChainProvenance::verified(verified_context.clone())
        .with_asserted_context(asserted_context.clone())
        .with_continuation_token_id("continuation-1")
        .with_session_anchor_id("anchor-1")
        .with_receipt_lineage_statement_id("statement-1");

    let encoded = serde_json::to_value(&provenance).unwrap();

    assert!(provenance.is_verified());
    assert_eq!(provenance.asserted_context(), Some(&asserted_context));
    assert_eq!(provenance.verified_context(), Some(&verified_context));
    assert_eq!(encoded["continuationTokenId"], "continuation-1");
    assert_eq!(encoded["sessionAnchorId"], "anchor-1");
    assert_eq!(encoded["receiptLineageStatementId"], "statement-1");
    assert_eq!(
        encoded["assertedContext"]["originSubject"],
        "origin-asserted"
    );
    assert_eq!(encoded["originSubject"], "origin-verified");
}

fn pinned_call_chain_provenance() -> GovernedCallChainProvenance {
    GovernedCallChainProvenance::verified(GovernedCallChainContext {
        chain_id: "chain-wire-1".to_string(),
        parent_request_id: "req-parent-wire-1".to_string(),
        parent_receipt_id: Some("rc-parent-wire-1".to_string()),
        origin_subject: "origin-wire".to_string(),
        delegator_subject: "delegator-wire".to_string(),
    })
    .with_evidence_sources([
        GovernedCallChainEvidenceSource::SessionParentRequestLineage,
        GovernedCallChainEvidenceSource::LocalParentReceiptLinkage,
    ])
    .with_asserted_context(GovernedCallChainContext {
        chain_id: "chain-wire-1".to_string(),
        parent_request_id: "req-parent-wire-1".to_string(),
        parent_receipt_id: None,
        origin_subject: "origin-asserted".to_string(),
        delegator_subject: "delegator-asserted".to_string(),
    })
    .with_continuation_token_id("continuation-wire-1")
    .with_session_anchor_id("anchor-wire-1")
    .with_receipt_lineage_statement_id("statement-wire-1")
}

fn pinned_call_chain_provenance_wire() -> serde_json::Value {
    serde_json::json!({
        "evidenceClass": "verified",
        "evidenceSources": ["session_parent_request_lineage", "local_parent_receipt_linkage"],
        "assertedContext": {
            "chainId": "chain-wire-1",
            "parentRequestId": "req-parent-wire-1",
            "originSubject": "origin-asserted",
            "delegatorSubject": "delegator-asserted"
        },
        "continuationTokenId": "continuation-wire-1",
        "sessionAnchorId": "anchor-wire-1",
        "receiptLineageStatementId": "statement-wire-1",
        "chainId": "chain-wire-1",
        "parentRequestId": "req-parent-wire-1",
        "parentReceiptId": "rc-parent-wire-1",
        "originSubject": "origin-wire",
        "delegatorSubject": "delegator-wire"
    })
}

#[test]
fn governed_call_chain_provenance_wire_shape_is_pinned() {
    let provenance = pinned_call_chain_provenance();
    let wire = pinned_call_chain_provenance_wire();

    assert_eq!(serde_json::to_value(&provenance).unwrap(), wire);
    assert_eq!(
        canonical_json_bytes(&provenance).unwrap(),
        canonical_json_bytes(&wire).unwrap()
    );
    let decoded: GovernedCallChainProvenance = serde_json::from_value(wire).unwrap();
    assert_eq!(decoded, provenance);

    let minimal = GovernedCallChainProvenance::asserted(GovernedCallChainContext {
        chain_id: "chain-wire-2".to_string(),
        parent_request_id: "req-parent-wire-2".to_string(),
        parent_receipt_id: None,
        origin_subject: "origin-wire".to_string(),
        delegator_subject: "delegator-wire".to_string(),
    });
    let minimal_wire = serde_json::json!({
        "evidenceClass": "asserted",
        "chainId": "chain-wire-2",
        "parentRequestId": "req-parent-wire-2",
        "originSubject": "origin-wire",
        "delegatorSubject": "delegator-wire"
    });
    assert_eq!(serde_json::to_value(&minimal).unwrap(), minimal_wire);
    let mut defaulted = minimal_wire;
    defaulted.as_object_mut().unwrap().remove("evidenceClass");
    let decoded: GovernedCallChainProvenance = serde_json::from_value(defaulted).unwrap();
    assert_eq!(decoded, minimal);
}

#[test]
fn governed_call_chain_provenance_refuses_an_unknown_member() {
    let mut padded = pinned_call_chain_provenance_wire();
    padded
        .as_object_mut()
        .unwrap()
        .insert("pad".to_string(), serde_json::json!(1));

    let error = serde_json::from_value::<GovernedCallChainProvenance>(padded).unwrap_err();
    assert!(error.to_string().contains("unknown field `pad`"), "{error}");
}

#[test]
fn governed_call_chain_provenance_refuses_a_missing_context_member() {
    for member in [
        "chainId",
        "parentRequestId",
        "originSubject",
        "delegatorSubject",
    ] {
        let mut wire = pinned_call_chain_provenance_wire();
        wire.as_object_mut().unwrap().remove(member);
        let error = serde_json::from_value::<GovernedCallChainProvenance>(wire).unwrap_err();
        assert!(
            error
                .to_string()
                .contains(&format!("missing field `{member}`")),
            "{member}: {error}"
        );
    }
}

#[test]
fn governed_call_chain_provenance_refuses_a_padded_asserted_context() {
    let mut padded = pinned_call_chain_provenance_wire();
    padded["assertedContext"]
        .as_object_mut()
        .unwrap()
        .insert("pad".to_string(), serde_json::json!(1));

    let error = serde_json::from_value::<GovernedCallChainProvenance>(padded).unwrap_err();
    assert!(error.to_string().contains("unknown field `pad`"), "{error}");
}

#[test]
fn governed_transaction_intent_refuses_a_padded_call_chain() {
    let intent = GovernedTransactionIntent {
        id: "intent-padded-chain-1".to_string(),
        server_id: "srv-pay".to_string(),
        tool_name: "charge".to_string(),
        purpose: "pay supplier".to_string(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: Some(GovernedCallChainContext {
            chain_id: "chain-padded-1".to_string(),
            parent_request_id: "req-parent-padded-1".to_string(),
            parent_receipt_id: None,
            origin_subject: "origin-padded".to_string(),
            delegator_subject: "delegator-padded".to_string(),
        }),
        autonomy: None,
        context: None,
        body: GovernedTransactionIntentBody::ToolInvocation,
    };
    let wire = serde_json::to_value(&intent).unwrap();
    let decoded: GovernedTransactionIntent = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(decoded, intent);

    let mut padded = wire;
    padded["call_chain"]
        .as_object_mut()
        .unwrap()
        .insert("pad".to_string(), serde_json::json!(1));
    let error = serde_json::from_value::<GovernedTransactionIntent>(padded).unwrap_err();
    assert!(error.to_string().contains("unknown field `pad`"), "{error}");
}
