use super::*;

pub(crate) fn signed_terminal_receipt(
    receipt_id: &str,
    terminal_status: &str,
    policy_digest: &str,
) -> serde_json::Value {
    sign_terminal_receipt(serde_json::json!({
        "schema": "chio.proof-room.receipt-evidence.v1",
        "request_digest": chio_core::sha256_hex(b"{}"),
        "response_digest": chio_core::sha256_hex(b"{}"),
        "receipt_id": receipt_id,
        "terminal_status": terminal_status,
        "policy_digest": policy_digest
    }))
}

pub(crate) fn sign_terminal_receipt(mut receipt: serde_json::Value) -> serde_json::Value {
    let keypair = Keypair::from_seed(&[23; 32]);
    let receipt_object = receipt
        .as_object_mut()
        .test_expect("terminal receipt is object");
    receipt_object.remove("signature");
    receipt_object.insert(
        "kernel_key".to_string(),
        serde_json::Value::String(keypair.public_key().to_hex()),
    );
    let signature = keypair
        .sign_wrapped(
            "chio.proof-room.receipt-evidence.v1",
            &chio_core::canonical::CanonicalBytes::from_serializable(&receipt)
                .test_expect("canonical signing body"),
        )
        .test_expect("terminal receipt signs");
    receipt["signature"] = serde_json::Value::String(signature.to_hex());
    receipt
}
