use super::*;

#[test]
fn operation_nonce_schema_preserves_both_profiles_and_rejects_unknown_versions() {
    let key = Keypair::generate();
    let mut nonce = make_execution_nonce(&key);
    assert_schema_accepts("kernel/execution_nonce.schema.json", &to_json(&nonce));
    nonce.nonce.schema = "chio.execution_nonce.v2".into();
    nonce.signature = key.sign(
        &chio_core_types::canonical::canonical_json_bytes(&json!({
            "schema": "chio.admission-execution-nonce-signature.v1",
            "operation_id": "a".repeat(64),
            "nonce": nonce.nonce,
        }))
        .expect("canonical signing context"),
    );
    let encoded = to_json(&nonce);
    assert_schema_accepts("kernel/execution_nonce.schema.json", &encoded);
    let decoded: SignedExecutionNonce =
        serde_json::from_value(encoded.clone()).expect("decode nonce");
    assert_eq!(decoded, nonce);
    let mut unknown = encoded.clone();
    unknown["nonce"]["schema"] = json!("chio.execution_nonce.v3");
    assert_schema_rejects("kernel/execution_nonce.schema.json", &unknown);
    let mut unbound = encoded;
    unbound["nonce"]["bound_to"]
        .as_object_mut()
        .expect("binding")
        .remove("request_id");
    assert_schema_rejects("kernel/execution_nonce.schema.json", &unbound);
}
