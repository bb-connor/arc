//! Integrated runtime, commerce and settlement passport bundle builders.

use super::*;

pub(crate) fn build_integrated_runtime_commerce_settlement_agent_web_bundle(
) -> (tempfile::TempDir, PathBuf) {
    build_integrated_runtime_commerce_settlement_agent_web_bundle_for_commerce_order(
        "order-public-settlement-valid",
    )
}

pub(crate) fn build_integrated_runtime_commerce_settlement_agent_web_bundle_with_mismatched_orders(
) -> (tempfile::TempDir, PathBuf) {
    build_integrated_runtime_commerce_settlement_agent_web_bundle_for_commerce_order(
        "order-commerce-001",
    )
}

pub(crate) fn build_integrated_runtime_commerce_settlement_agent_web_bundle_for_commerce_order(
    commerce_order_id: &str,
) -> (tempfile::TempDir, PathBuf) {
    let (tempdir, bundle) = build_runtime_commerce_passport_bundle();
    let settlement_source =
        workspace_root().join("fixtures/proof-room/public-settlement/valid-offline-finality");
    let agent_web_source =
        workspace_root().join("fixtures/proof-room/agent-web/valid-webhook-cloudevents");
    retarget_commerce_order_id(&bundle, commerce_order_id);

    let passport_path = bundle.join("transaction-passport.json");
    let agent_web_passport: serde_json::Value = serde_json::from_slice(
        &std::fs::read(agent_web_source.join("transaction-passport.json"))
            .test_expect("read Agent Web passport"),
    )
    .test_expect("Agent Web passport parses");
    let passport_id = agent_web_passport["id"]
        .as_str()
        .test_expect("Agent Web passport has id");

    let policy_path = bundle.join("verifier-policy.json");
    let mut policy: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&policy_path).test_expect("read verifier policy"))
            .test_expect("verifier policy parses");
    let current_passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    append_required_claims_from_policy(
        &mut policy,
        &settlement_source.join("verifier-policy.json"),
    );
    remove_required_claim(
        &mut policy,
        "claim.public_settlement.trust_market_refs_bound",
    );
    append_required_claims_from_policy(&mut policy, &agent_web_source.join("verifier-policy.json"));
    write_json(&policy_path, &policy);
    let policy_sha256 = sha256_file(&policy_path);
    let claim_set_sha256 = refresh_claim_set_for_policy(
        &bundle,
        passport_id,
        current_passport["issued_at"]
            .as_str()
            .test_expect("passport issued_at"),
        &policy,
    );
    let mut receipt_passport = current_passport;
    receipt_passport["id"] = serde_json::Value::String(passport_id.to_string());
    receipt_passport["claim_set_sha256"] = serde_json::Value::String(claim_set_sha256.clone());
    receipt_passport["claim_set_path"] = serde_json::Value::String("claim-set.json".to_string());
    receipt_passport["verifier_policy_sha256"] = serde_json::Value::String(policy_sha256.clone());
    write_json(&passport_path, &receipt_passport);

    for path in [
        "execution-lease.json",
        "route-plan-receipt.json",
        "allow-receipt.json",
    ] {
        let artifact_path = bundle.join(path);
        let mut artifact: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&artifact_path).test_expect("read artifact"))
                .test_expect("artifact parses");
        match path {
            "execution-lease.json" => {
                artifact["policy_digest"] = serde_json::Value::String(policy_sha256.clone());
                sign_runtime_lease_with_fixture_authority(&mut artifact);
            }
            "route-plan-receipt.json" => {
                artifact["policyDigest"] = serde_json::Value::String(policy_sha256.clone());
                sign_runtime_route_plan_with_fixture_authority(&mut artifact);
            }
            "allow-receipt.json" => {
                artifact["policy_digest"] = serde_json::Value::String(policy_sha256.clone());
                sign_runtime_terminal_receipt_with_fixture_kernel(&mut artifact);
            }
            _ => {}
        }
        write_json(&artifact_path, &artifact);
    }

    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&evidence_graph_path).test_expect("read graph"))
            .test_expect("graph parses");
    upsert_claim_set_graph_binding(&mut evidence_graph, &claim_set_sha256);
    append_graph_artifacts_from_fixture(
        &bundle,
        &settlement_source,
        &mut evidence_graph,
        &[("passport-public-settlement-valid", passport_id)],
    );
    resign_public_settlement_bundle(&bundle);
    append_graph_artifacts_from_fixture(&bundle, &agent_web_source, &mut evidence_graph, &[]);
    remove_graph_nodes_by_path(&mut evidence_graph, "external/settlement-packet.json");
    refresh_agent_web_envelopes_for_subjects(&bundle, &mut evidence_graph);
    resign_agent_web_receipts_for_policy(&bundle, &policy_sha256);
    refresh_commerce_event_authority_receipts(&bundle, &mut evidence_graph, &policy_sha256);
    refresh_commerce_order_passport(&bundle, &mut evidence_graph);
    refresh_evidence_graph_content_ids(&bundle, &mut evidence_graph);
    write_json(&evidence_graph_path, &evidence_graph);
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path);

    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    passport["id"] = serde_json::Value::String(passport_id.to_string());
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256);
    passport["claim_set_sha256"] = serde_json::Value::String(claim_set_sha256);
    passport["claim_set_path"] = serde_json::Value::String("claim-set.json".to_string());
    passport["verifier_policy_sha256"] = serde_json::Value::String(policy_sha256);
    write_json(&passport_path, &passport);
    sync_proof_room_transaction_roots(&bundle);

    (tempdir, bundle)
}

pub(crate) fn retarget_commerce_order_id(bundle: &Path, order_id: &str) {
    let event_log_path = bundle.join("event-log.json");
    let payment_path = bundle.join("payment-lifecycle.json");
    let mandate_path = bundle.join("mandate-allowance-ledger.json");
    let settlement_packet_path = bundle.join("settlement-packet.json");
    let order_context_path = bundle.join("order-context.json");

    let mut order_context: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&order_context_path).test_expect("read order context"),
    )
    .test_expect("order context parses");
    order_context["order_id"] = serde_json::json!(order_id);
    let quote_sha256 = commerce_quote_sha256(&order_context);
    order_context["quote_sha256"] = serde_json::json!(quote_sha256.clone());

    let mut event_log: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&event_log_path).test_expect("read event log"))
            .test_expect("event log parses");
    event_log["order_id"] = serde_json::json!(order_id);
    for event in event_log["events"]
        .as_array_mut()
        .test_expect("event log events array")
    {
        event["order_id"] = serde_json::json!(order_id);
    }
    seal_commerce_event_log(&mut event_log);
    write_json(&event_log_path, &event_log);

    let mut payment_lifecycle: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&payment_path).test_expect("read payment lifecycle"))
            .test_expect("payment lifecycle parses");
    payment_lifecycle["order_id"] = serde_json::json!(order_id);
    payment_lifecycle["transfer_group"] = serde_json::json!(order_id);
    payment_lifecycle["quote_sha256"] = serde_json::json!(quote_sha256.clone());
    sign_commerce_payment_lifecycle(&mut payment_lifecycle);
    write_json(&payment_path, &payment_lifecycle);

    let mut mandate_ledger: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&mandate_path).test_expect("read mandate ledger"))
            .test_expect("mandate ledger parses");
    mandate_ledger["order_id"] = serde_json::json!(order_id);
    mandate_ledger["quote_sha256"] = serde_json::json!(quote_sha256.clone());
    retarget_commerce_mandate_projection_order_ids(&mut mandate_ledger, order_id);
    retarget_commerce_mandate_protocol_payloads(bundle, &mut mandate_ledger, order_id);
    write_json(&mandate_path, &mandate_ledger);

    let mut settlement_packet: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&settlement_packet_path).test_expect("read settlement packet"),
    )
    .test_expect("settlement packet parses");
    settlement_packet["order_id"] = serde_json::json!(order_id);
    settlement_packet["quote_sha256"] = serde_json::json!(quote_sha256);
    write_json(&settlement_packet_path, &settlement_packet);

    order_context["event_log_sha256"] = serde_json::Value::String(sha256_file(&event_log_path));
    order_context["payment_lifecycle_sha256"] =
        serde_json::Value::String(sha256_file(&payment_path));
    order_context["mandate_ledger_sha256"] = serde_json::Value::String(sha256_file(&mandate_path));
    order_context["settlement_packet_sha256"] =
        serde_json::Value::String(sha256_file(&settlement_packet_path));
    write_json(&order_context_path, &order_context);
}

pub(crate) fn commerce_quote_sha256(order_context: &serde_json::Value) -> String {
    let quote_amount_minor = order_context["quote_amount_minor"]
        .as_u64()
        .test_expect("quote amount is u64");
    let binding = serde_json::json!({
        "amount_minor": quote_amount_minor,
        "currency": order_context["quote_currency"],
        "merchant_subject": order_context["merchant_subject"],
        "order_id": order_context["order_id"],
        "quote_id": order_context["quote_id"],
    });
    let canonical =
        chio_core_types::canonical_json_bytes(&binding).test_expect("quote binding canonicalizes");
    hex::encode(Sha256::digest(&canonical))
}

pub(crate) fn seal_commerce_event_log(event_log: &mut serde_json::Value) {
    for event in event_log["events"]
        .as_array_mut()
        .test_expect("event log events array")
    {
        event
            .as_object_mut()
            .test_expect("event object")
            .remove("event_sha256");
        let canonical =
            chio_core_types::canonical_json_bytes(event).test_expect("event canonicalizes");
        event["event_sha256"] = serde_json::Value::String(hex::encode(Sha256::digest(&canonical)));
    }
}

pub(crate) fn refresh_commerce_event_authority_receipts(
    bundle: &Path,
    evidence_graph: &mut serde_json::Value,
    policy_sha256: &str,
) {
    let event_log_path = bundle.join("event-log.json");
    let event_log: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&event_log_path).test_expect("read event log"))
            .test_expect("event log parses");
    let receipt_dir = bundle.join("authority-receipts");
    std::fs::create_dir_all(&receipt_dir).test_expect("create authority receipts dir");
    for event in event_log["events"]
        .as_array()
        .test_expect("event log events array")
    {
        let receipt_ref = event["authority_receipt_ref"]
            .as_str()
            .test_expect("event has authority receipt ref");
        let receipt_path = format!("authority-receipts/{receipt_ref}.json");
        let destination = bundle.join(&receipt_path);
        write_commerce_event_authority_receipt(&destination, event, policy_sha256);
        upsert_graph_node(
            evidence_graph,
            receipt_ref,
            &receipt_path,
            "chio.receipt.v1",
            "receipt",
            &sha256_file(&destination),
        );
    }
}

pub(crate) fn refresh_commerce_order_passport(
    bundle: &Path,
    evidence_graph: &mut serde_json::Value,
) {
    let order_context_path = bundle.join("order-context.json");
    let order_context_bytes = std::fs::read(&order_context_path).test_expect("read order context");
    let order_context: chio_commerce_order::CommerceOrderContext =
        serde_json::from_slice(&order_context_bytes).test_expect("order context parses");
    let event_log_bytes =
        std::fs::read(bundle.join(&order_context.event_log_path)).test_expect("read event log");
    let event_log: serde_json::Value =
        serde_json::from_slice(&event_log_bytes).test_expect("event log parses");
    let event_authority_receipts = event_log["events"]
        .as_array()
        .test_expect("event log events array")
        .iter()
        .map(|event| {
            let receipt_ref = event["authority_receipt_ref"]
                .as_str()
                .test_expect("event has authority receipt ref");
            let receipt_path = bundle.join(format!("authority-receipts/{receipt_ref}.json"));
            chio_commerce_order::CommerceEventAuthorityReceiptArtifact {
                receipt_ref: receipt_ref.to_string(),
                schema: "chio.receipt.v1".to_string(),
                receipt_bytes: std::fs::read(receipt_path).test_expect("read authority receipt"),
            }
        })
        .collect();
    let payment_lifecycle_bytes = std::fs::read(bundle.join(&order_context.payment_lifecycle_path))
        .test_expect("read payment lifecycle");
    let mandate_ledger_bytes = std::fs::read(bundle.join(&order_context.mandate_ledger_path))
        .test_expect("read mandate ledger");
    let provider_passport_bytes = std::fs::read(bundle.join(&order_context.provider_passport_path))
        .test_expect("read provider passport");
    let reputation_snapshot_bytes =
        std::fs::read(bundle.join(&order_context.reputation_snapshot_path))
            .test_expect("read reputation snapshot");
    let federation_trust_bundle_bytes =
        std::fs::read(bundle.join(&order_context.federation_trust_bundle_path))
            .test_expect("read federation trust bundle");
    let settlement_packet_bytes = std::fs::read(bundle.join(&order_context.settlement_packet_path))
        .test_expect("read settlement packet");
    let mandate_protocol_payloads =
        commerce_mandate_protocol_payloads(bundle, &mandate_ledger_bytes);
    let risk_comptroller_report_bytes = order_context
        .coverage_requirement
        .as_ref()
        .filter(|requirement| requirement.required)
        .map(|requirement| {
            std::fs::read(bundle.join(&requirement.risk_comptroller_report_path))
                .test_expect("read risk comptroller report")
        });
    let escrow_ledger_bytes =
        escrow::pinned_escrow_ledger_bytes(bundle, evidence_graph, &order_context);
    let verification_bundle = chio_commerce_order::CommerceOrderVerificationBundle {
        order_context,
        event_log_bytes,
        event_authority_receipts,
        payment_lifecycle_bytes,
        mandate_ledger_bytes,
        provider_passport_bytes,
        reputation_snapshot_bytes,
        federation_trust_bundle_bytes,
        settlement_packet_bytes,
        mandate_protocol_payloads,
        risk_comptroller_report_bytes,
        escrow_ledger_bytes,
        verified_trust_market_context: None,
        trusted_event_authority_receipt_kernel_keys: trusted_public_keys(
            COMMERCE_FIXTURE_TRUSTED_EVENT_AUTHORITY_RECEIPT_KERNEL_KEYS,
        ),
        trusted_payment_signer_keys: trusted_public_keys(
            COMMERCE_FIXTURE_TRUSTED_PAYMENT_SIGNER_KEYS,
        ),
        trusted_provider_trust_signer_keys: trusted_public_keys(
            COMMERCE_FIXTURE_TRUSTED_PROVIDER_KEYS,
        ),
        trusted_risk_comptroller_signer_keys: trusted_public_keys(
            ENTERPRISE_FIXTURE_TRUSTED_RISK_COMPTROLLER_KEYS,
        ),
    };
    let report = chio_commerce_order::verify_commerce_order(&verification_bundle)
        .test_expect("commerce order verifies for order passport");
    let order_passport_path = bundle.join("order-passport.json");
    let report_json =
        serde_json::to_value(report).test_expect("commerce order passport serializes");
    write_json(&order_passport_path, &report_json);
    let order_passport_sha256 = sha256_file(&order_passport_path);
    upsert_graph_node(
        evidence_graph,
        &order_passport_sha256,
        "order-passport.json",
        chio_commerce_order::COMMERCE_ORDER_PASSPORT_SCHEMA_ID,
        "commerce-order-passport",
        &order_passport_sha256,
    );
}
