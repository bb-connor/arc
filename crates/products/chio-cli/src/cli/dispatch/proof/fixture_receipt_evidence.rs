use super::*;

pub(super) const RECEIPT_EVIDENCE_SCHEMA: &str = "chio.proof-room.receipt-evidence.v1";

pub(super) fn generate_minimal_receipt_evidence(
    descriptor: &ProofFixtureDescriptor,
    out: &Path,
) -> Result<(), CliError> {
    let bundle = if installed_fixture_path(descriptor).starts_with("minimal-passport/") {
        out.to_path_buf()
    } else if descriptor.id == SINGLE_CALL_AUTHORITY_FIXTURE_ID {
        out.join("proof-room-bundle/negatives/stale-capability")
    } else {
        return Ok(());
    };
    let path = bundle.join("kernel-receipt.json");
    let source = read_json_value(&path)?;
    let keypair = Keypair::from_seed(&[53u8; 32]);
    let mut receipt = serde_json::json!({
        "schema": RECEIPT_EVIDENCE_SCHEMA,
        "kernel_key": keypair.public_key().to_hex(),
    });
    for field in [
        "receipt_id",
        "terminal_status",
        "policy_digest",
        "request_digest",
        "response_digest",
        "capability_id",
        "guard_decision_id",
    ] {
        let value = source
            .get(field)
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                CliError::cli_other_error(format!("fixture receipt evidence missing {field}"))
            })?;
        receipt[field] = serde_json::Value::String(value.to_string());
    }
    sign_receipt_evidence(&mut receipt, &keypair)?;
    write_json_line_file(&path, &receipt)?;
    let graph_path = bundle.join("evidence-graph.json");
    let mut graph = read_json_value(&graph_path)?;
    for node in json_array_mut(&mut graph, "nodes", &graph_path)? {
        if node.get("path").and_then(serde_json::Value::as_str) == Some("kernel-receipt.json") {
            node["schema"] = serde_json::Value::String(RECEIPT_EVIDENCE_SCHEMA.to_string());
        }
    }
    write_json_line_file(&graph_path, &graph)
}

pub(super) fn write_terminal_receipt_evidence(
    destination: &Path,
    receipt_id: &str,
    terminal_status: &str,
    policy_sha256: &str,
) -> Result<(), CliError> {
    let keypair = Keypair::from_seed(&[29u8; 32]);
    let mut receipt = serde_json::json!({
        "schema": RECEIPT_EVIDENCE_SCHEMA,
        "receipt_id": receipt_id,
        "terminal_status": terminal_status,
        "policy_digest": policy_sha256,
        "request_digest": chio_core::sha256_hex(b"{}"),
        "response_digest": chio_core::sha256_hex(b"{}"),
        "kernel_key": keypair.public_key().to_hex(),
    });
    sign_receipt_evidence(&mut receipt, &keypair)?;
    write_json_line_file(destination, &receipt)
}

fn sign_receipt_evidence(
    receipt: &mut serde_json::Value,
    keypair: &Keypair,
) -> Result<(), CliError> {
    let signature =
        fixture_wrapped_signature(keypair, RECEIPT_EVIDENCE_SCHEMA, receipt).map_err(|error| {
            CliError::cli_other_error(format!(
                "proof fixture receipt evidence signing failed: {error}"
            ))
        })?;
    receipt["signature"] = serde_json::Value::String(signature.to_hex());
    Ok(())
}
