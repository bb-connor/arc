use super::*;

#[test]
fn operation_nonce_schema_preserves_both_profiles_and_rejects_unknown_versions() {
    let key = Keypair::generate();
    let mut nonce = make_execution_nonce(&key);
    assert_schema_accepts("kernel/execution_nonce.schema.json", &to_json(&nonce));
    nonce.nonce.schema = "chio.operation_execution_nonce.v1".into();
    nonce.signature = key
        .sign_wrapped(
            "chio.operation_execution_nonce.v1",
            &chio_core_types::CanonicalBytes::from_serializable(&json!({
                "operation_id": "a".repeat(64),
                "nonce": nonce.nonce,
            }))
            .expect("canonical signing context"),
        )
        .expect("wrapped nonce signature");
    let encoded = to_json(&nonce);
    assert_schema_accepts("kernel/execution_nonce.schema.json", &encoded);
    let decoded: SignedExecutionNonce =
        serde_json::from_value(encoded.clone()).expect("decode nonce");
    assert_eq!(decoded, nonce);
    for schema in [
        "chio.execution_nonce.v2",
        "chio.execution_nonce.v3",
        "chio.operation_execution_nonce.v2",
        "chio.operation_execution_nonce.v3",
    ] {
        let mut unknown = encoded.clone();
        unknown["nonce"]["schema"] = json!(schema);
        assert_schema_rejects("kernel/execution_nonce.schema.json", &unknown);
    }
    let mut unbound = encoded;
    unbound["nonce"]["bound_to"]
        .as_object_mut()
        .expect("binding")
        .remove("request_id");
    assert_schema_rejects("kernel/execution_nonce.schema.json", &unbound);
}
