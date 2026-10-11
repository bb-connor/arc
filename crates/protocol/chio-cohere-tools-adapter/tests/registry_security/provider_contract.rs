use super::*;

#[test]
fn empty_lifecycle_tool_call_placeholders_preserve_documented_bytes() {
    // The official Cohere v2 stream example includes an empty tool_calls list
    // on message-start. Optional null placeholders also carry no call.
    for placeholder in [json!([]), json!(null)] {
        let start = json!({"type":"message-start","delta":{"message":{
            "role":"assistant","content":[],"tool_calls":placeholder,"tool_plan":""}}});
        let end = json!({"type":"message-end","delta":{"finish_reason":"COMPLETE"}});
        let raw =
            format!("event: message-start\ndata: {start}\n\nevent: message-end\ndata: {end}\n\n")
                .into_bytes();
        let (config, registry, _) = signed_registry();
        let adapter =
            CohereAdapter::new_with_registry(config, Arc::new(MockTransport::new()), &registry)
                .test_unwrap();
        let evaluated = Cell::new(0);
        let gated = adapter
            .gate_sse_stream(&raw, |_| {
                evaluated.set(evaluated.get() + 1);
                Ok(allow())
            })
            .test_unwrap();
        assert_eq!(gated.bytes, raw);
        assert!(gated.invocations.is_empty());
        assert!(gated.verdicts.is_empty());
        assert_eq!(evaluated.get(), 0);
    }
}

#[test]
fn nullable_optional_delta_identity_preserves_exact_bytes_and_registry_flow() {
    let raw = delta_identity::streamed(json!(""), json!({"id":null,"name":null,"type":null}));
    let (config, registry, flow) = signed_registry();
    let adapter =
        CohereAdapter::new_with_registry(config, Arc::new(MockTransport::new()), &registry)
            .test_unwrap();
    let evaluated = Cell::new(0);
    let gated = adapter
        .gate_sse_stream(&raw, |invocation| {
            evaluated.set(evaluated.get() + 1);
            let security = invocation.bridge_security.as_ref().test_unwrap();
            assert!(security.has_registry_coordinates());
            assert_eq!(
                canonical_json_bytes(security.flow().test_unwrap()).test_unwrap(),
                canonical_json_bytes(&flow).test_unwrap()
            );
            assert_eq!(invocation.tool_name, TOOL_NAME);
            assert_eq!(
                invocation.arguments,
                canonical_json_bytes(&json!({"city":"London"})).test_unwrap()
            );
            Ok(allow())
        })
        .test_unwrap();
    assert_eq!(gated.bytes, raw);
    assert_eq!(gated.invocations.len(), 1);
    assert_eq!(gated.verdicts, vec![allow()]);
    assert_eq!(evaluated.get(), 1);
}
