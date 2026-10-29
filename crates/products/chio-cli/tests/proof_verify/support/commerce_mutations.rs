//! Commerce passport bundle mutations that re-seal and re-sign the touched artifacts.

use super::*;

pub(crate) fn mutate_commerce_event_log(
    bundle_dir: &std::path::Path,
    mutate: impl FnOnce(&mut serde_json::Value),
) {
    let event_log_path = bundle_dir.join("event-log.json");
    let mut event_log: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&event_log_path).test_expect("read event log"))
            .test_expect("parse event log");
    mutate(&mut event_log);
    seal_commerce_event_log_events(&mut event_log);
    let event_log_bytes = serde_json::to_vec(&event_log).test_expect("serialize event log");
    std::fs::write(&event_log_path, &event_log_bytes).test_expect("write event log");
    let event_log_digest = chio_core::sha256_hex(&event_log_bytes);

    let order_context_path = bundle_dir.join("order-context.json");
    let mut order_context: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&order_context_path).test_expect("read order context"),
    )
    .test_expect("parse order context");
    order_context["event_log_sha256"] = serde_json::Value::String(event_log_digest.clone());
    let order_context_bytes =
        serde_json::to_vec(&order_context).test_expect("serialize order context");
    std::fs::write(&order_context_path, &order_context_bytes).test_expect("write order context");
    let order_context_digest = chio_core::sha256_hex(&order_context_bytes);

    let evidence_graph_path = bundle_dir.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("parse evidence graph");
    for node in evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("evidence graph nodes")
    {
        match node.get("path").and_then(serde_json::Value::as_str) {
            Some("event-log.json") => {
                node["sha256"] = serde_json::Value::String(event_log_digest.clone());
            }
            Some("order-context.json") => {
                node["sha256"] = serde_json::Value::String(order_context_digest.clone());
            }
            _ => {}
        }
    }
    refresh_commerce_event_authority_receipts(bundle_dir, &event_log, &mut evidence_graph);
    let evidence_graph_bytes =
        serde_json::to_vec(&evidence_graph).test_expect("serialize evidence graph");
    std::fs::write(&evidence_graph_path, &evidence_graph_bytes).test_expect("write evidence graph");
    set_passport_digest(
        bundle_dir,
        "evidence_graph_sha256",
        chio_core::sha256_hex(&evidence_graph_bytes),
    );
}

pub(crate) fn seal_commerce_event_log_events(event_log: &mut serde_json::Value) {
    for event in event_log["events"]
        .as_array_mut()
        .test_expect("event log events array")
    {
        let event_object = event
            .as_object_mut()
            .test_expect("event log event is an object");
        event_object.remove("event_sha256");
        let canonical = chio_core_types::canonical_json_bytes(event)
            .test_expect("event log event canonicalizes");
        event["event_sha256"] = serde_json::Value::String(chio_core::sha256_hex(&canonical));
    }
}

pub(crate) fn refresh_commerce_event_authority_receipts(
    bundle_dir: &std::path::Path,
    event_log: &serde_json::Value,
    evidence_graph: &mut serde_json::Value,
) {
    let policy_sha256 = chio_core::sha256_hex(
        &std::fs::read(bundle_dir.join("verifier-policy.json")).test_expect("read verifier policy"),
    );
    let receipt_dir = bundle_dir.join("authority-receipts");
    std::fs::create_dir_all(&receipt_dir).test_expect("create authority receipts dir");
    for event in event_log["events"]
        .as_array()
        .test_expect("event log events array")
    {
        let receipt_ref = event["authority_receipt_ref"]
            .as_str()
            .test_expect("event has authority receipt ref");
        let receipt_path = format!("authority-receipts/{receipt_ref}.json");
        let destination = bundle_dir.join(&receipt_path);
        write_commerce_event_authority_receipt(&destination, event, &policy_sha256);
        upsert_evidence_graph_node(
            evidence_graph,
            receipt_ref,
            &receipt_path,
            "chio.receipt.v1",
            "receipt",
            &chio_core::sha256_hex(
                &std::fs::read(&destination).test_expect("read authority receipt"),
            ),
        );
    }
}

pub(crate) fn write_commerce_event_authority_receipt(
    destination: &std::path::Path,
    event: &serde_json::Value,
    policy_sha256: &str,
) {
    let receipt_ref = event["authority_receipt_ref"]
        .as_str()
        .test_expect("event has authority receipt ref");
    let keypair = Keypair::from_seed(&TEST_SIGNATURE_SEED);
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: receipt_ref.to_string(),
            timestamp: 1_781_072_000,
            capability_id: format!("cap-{receipt_ref}"),
            tool_server: "chio-commerce-order-authority".to_string(),
            tool_name: event["transition"]
                .as_str()
                .test_expect("event has transition")
                .to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({
                "authority_receipt_ref": receipt_ref,
                "event_id": event["event_id"],
                "order_id": event["order_id"],
                "transition": event["transition"],
            }))
            .test_expect("commerce authority receipt action hashes"),
            decision: Some(Decision::Allow),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: vec![ActorRef {
                actor_id: event["actor"]
                    .as_str()
                    .test_expect("event has actor")
                    .to_string(),
                actor_kind: Some("agent".to_string()),
            }],
            content_hash: event["event_sha256"]
                .as_str()
                .test_expect("event has event sha256")
                .to_string(),
            policy_hash: policy_sha256.to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: TrustLevel::Mediated,
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        &keypair,
    )
    .test_expect("commerce authority receipt signs");
    let value = serde_json::to_value(receipt).test_expect("commerce receipt serializes");
    write_json(destination, &value);
}

pub(crate) fn upsert_evidence_graph_node(
    evidence_graph: &mut serde_json::Value,
    node_id: &str,
    path: &str,
    schema: &str,
    role: &str,
    sha256: &str,
) {
    let nodes = evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("evidence graph nodes");
    nodes.retain(|node| {
        node.get("id").and_then(serde_json::Value::as_str) != Some(node_id)
            && node.get("path").and_then(serde_json::Value::as_str) != Some(path)
    });
    nodes.push(serde_json::json!({
        "id": sha256,
        "schema": schema,
        "path": path,
        "sha256": sha256,
        "role": role
    }));
}

pub(crate) fn mutate_commerce_payment_lifecycle(
    bundle_dir: &std::path::Path,
    mutate: impl FnOnce(&mut serde_json::Value),
) {
    let payment_lifecycle_path = bundle_dir.join("payment-lifecycle.json");
    let mut payment_lifecycle: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&payment_lifecycle_path).test_expect("read payment lifecycle"),
    )
    .test_expect("parse payment lifecycle");
    mutate(&mut payment_lifecycle);
    sign_commerce_payment_lifecycle(&mut payment_lifecycle);
    let payment_lifecycle_bytes =
        serde_json::to_vec(&payment_lifecycle).test_expect("serialize payment lifecycle");
    std::fs::write(&payment_lifecycle_path, &payment_lifecycle_bytes)
        .test_expect("write payment lifecycle");
    let payment_lifecycle_digest = chio_core::sha256_hex(&payment_lifecycle_bytes);

    let order_context_path = bundle_dir.join("order-context.json");
    let mut order_context: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&order_context_path).test_expect("read order context"),
    )
    .test_expect("parse order context");
    order_context["payment_lifecycle_sha256"] =
        serde_json::Value::String(payment_lifecycle_digest.clone());
    let order_context_bytes =
        serde_json::to_vec(&order_context).test_expect("serialize order context");
    std::fs::write(&order_context_path, &order_context_bytes).test_expect("write order context");
    let order_context_digest = chio_core::sha256_hex(&order_context_bytes);

    let evidence_graph_path = bundle_dir.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("parse evidence graph");
    for node in evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("evidence graph nodes")
    {
        match node.get("path").and_then(serde_json::Value::as_str) {
            Some("payment-lifecycle.json") => {
                node["sha256"] = serde_json::Value::String(payment_lifecycle_digest.clone());
            }
            Some("order-context.json") => {
                node["sha256"] = serde_json::Value::String(order_context_digest.clone());
            }
            _ => {}
        }
    }
    let evidence_graph_bytes =
        serde_json::to_vec(&evidence_graph).test_expect("serialize evidence graph");
    std::fs::write(&evidence_graph_path, &evidence_graph_bytes).test_expect("write evidence graph");
    set_passport_digest(
        bundle_dir,
        "evidence_graph_sha256",
        chio_core::sha256_hex(&evidence_graph_bytes),
    );
}

pub(crate) fn mutate_commerce_mandate_ledger(
    bundle_dir: &std::path::Path,
    mutate: impl FnOnce(&mut serde_json::Value),
) {
    let mandate_path = bundle_dir.join("mandate-allowance-ledger.json");
    let mut mandate_ledger: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&mandate_path).test_expect("read mandate ledger"))
            .test_expect("parse mandate ledger");
    mutate(&mut mandate_ledger);
    let mandate_ledger_bytes =
        serde_json::to_vec(&mandate_ledger).test_expect("serialize mandate ledger");
    std::fs::write(&mandate_path, &mandate_ledger_bytes).test_expect("write mandate ledger");
    let mandate_ledger_digest = chio_core::sha256_hex(&mandate_ledger_bytes);

    let order_context_path = bundle_dir.join("order-context.json");
    let mut order_context: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&order_context_path).test_expect("read order context"),
    )
    .test_expect("parse order context");
    order_context["mandate_ledger_sha256"] =
        serde_json::Value::String(mandate_ledger_digest.clone());
    let order_context_bytes =
        serde_json::to_vec(&order_context).test_expect("serialize order context");
    std::fs::write(&order_context_path, &order_context_bytes).test_expect("write order context");
    let order_context_digest = chio_core::sha256_hex(&order_context_bytes);

    let evidence_graph_path = bundle_dir.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("parse evidence graph");
    for node in evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("evidence graph nodes")
    {
        match node.get("path").and_then(serde_json::Value::as_str) {
            Some("mandate-allowance-ledger.json") => {
                node["sha256"] = serde_json::Value::String(mandate_ledger_digest.clone());
            }
            Some("order-context.json") => {
                node["sha256"] = serde_json::Value::String(order_context_digest.clone());
            }
            _ => {}
        }
    }
    let evidence_graph_bytes =
        serde_json::to_vec(&evidence_graph).test_expect("serialize evidence graph");
    std::fs::write(&evidence_graph_path, &evidence_graph_bytes).test_expect("write evidence graph");
    set_passport_digest(
        bundle_dir,
        "evidence_graph_sha256",
        chio_core::sha256_hex(&evidence_graph_bytes),
    );
}

pub(crate) fn mutate_commerce_provider_passport(
    bundle_dir: &std::path::Path,
    mutate: impl FnOnce(&mut serde_json::Value),
) {
    let provider_passport_path = bundle_dir.join("provider-passport.json");
    let mut provider_passport: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&provider_passport_path).test_expect("read provider passport"),
    )
    .test_expect("parse provider passport");
    mutate(&mut provider_passport);
    let provider_passport_bytes =
        serde_json::to_vec(&provider_passport).test_expect("serialize provider passport");
    std::fs::write(&provider_passport_path, &provider_passport_bytes)
        .test_expect("write provider passport");
    let provider_passport_digest = chio_core::sha256_hex(&provider_passport_bytes);

    let order_context_path = bundle_dir.join("order-context.json");
    let mut order_context: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&order_context_path).test_expect("read order context"),
    )
    .test_expect("parse order context");
    order_context["provider_passport_sha256"] =
        serde_json::Value::String(provider_passport_digest.clone());
    let order_context_bytes =
        serde_json::to_vec(&order_context).test_expect("serialize order context");
    std::fs::write(&order_context_path, &order_context_bytes).test_expect("write order context");
    let order_context_digest = chio_core::sha256_hex(&order_context_bytes);

    let evidence_graph_path = bundle_dir.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("parse evidence graph");
    for node in evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("evidence graph nodes")
    {
        match node.get("path").and_then(serde_json::Value::as_str) {
            Some("provider-passport.json") => {
                node["sha256"] = serde_json::Value::String(provider_passport_digest.clone());
            }
            Some("order-context.json") => {
                node["sha256"] = serde_json::Value::String(order_context_digest.clone());
            }
            _ => {}
        }
    }
    let evidence_graph_bytes =
        serde_json::to_vec(&evidence_graph).test_expect("serialize evidence graph");
    std::fs::write(&evidence_graph_path, &evidence_graph_bytes).test_expect("write evidence graph");
    set_passport_digest(
        bundle_dir,
        "evidence_graph_sha256",
        chio_core::sha256_hex(&evidence_graph_bytes),
    );
}

pub(crate) fn mutate_commerce_order_context(
    bundle_dir: &std::path::Path,
    mutate: impl FnOnce(&mut serde_json::Value),
) {
    let order_context_path = bundle_dir.join("order-context.json");
    let mut order_context: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&order_context_path).test_expect("read order context"),
    )
    .test_expect("parse order context");
    mutate(&mut order_context);
    let order_context_bytes =
        serde_json::to_vec(&order_context).test_expect("serialize order context");
    std::fs::write(&order_context_path, &order_context_bytes).test_expect("write order context");
    let order_context_digest = chio_core::sha256_hex(&order_context_bytes);

    let evidence_graph_path = bundle_dir.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("parse evidence graph");
    for node in evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("evidence graph nodes")
    {
        if node.get("path").and_then(serde_json::Value::as_str) == Some("order-context.json") {
            node["sha256"] = serde_json::Value::String(order_context_digest.clone());
        }
    }
    let evidence_graph_bytes =
        serde_json::to_vec(&evidence_graph).test_expect("serialize evidence graph");
    std::fs::write(&evidence_graph_path, &evidence_graph_bytes).test_expect("write evidence graph");
    set_passport_digest(
        bundle_dir,
        "evidence_graph_sha256",
        chio_core::sha256_hex(&evidence_graph_bytes),
    );
}

pub(crate) fn sign_commerce_payment_lifecycle(payment_lifecycle: &mut serde_json::Value) {
    let keypair = chio_core::Keypair::from_seed(&TEST_SIGNATURE_SEED);
    payment_lifecycle["issuer"] =
        serde_json::Value::String(format!("did:chio:{}", keypair.public_key().to_hex()));
    payment_lifecycle
        .as_object_mut()
        .test_expect("payment lifecycle object")
        .remove("signature");
    let signature = keypair
        .sign_wrapped(
            "chio.commerce.payment-lifecycle.v1",
            &chio_core::canonical::CanonicalBytes::from_serializable(payment_lifecycle)
                .test_expect("canonical signing body"),
        )
        .test_expect("sign payment lifecycle");
    payment_lifecycle["signature"] = serde_json::Value::String(signature.to_hex());
}
