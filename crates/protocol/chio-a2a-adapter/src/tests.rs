#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    include!("tests/support.rs");
    include!("tests/protocol.rs");
    include!("tests/discovery_registry.rs");
    include!("tests/invoke_manifest.rs");
    include!("tests/streaming_lifecycle.rs");
    include!("tests/auth.rs");
    include!("tests/kernel_receipts.rs");
}

#[test]
fn durable_dispatch_message_id_is_the_operation_id() {
    let context = ToolDispatchContext::new(
        "request-9",
        chio_core::provider_attempt::ProviderAttemptBindingV1 {
            operation_id: "c".repeat(64),
            attempt_id: format!("attempt:{}", "c".repeat(64)),
            transport_id: "kernel-tool-server:a2a".into(),
            transport_key_epoch: 2,
        },
    );
    assert_eq!(
        dispatch_message_id(&context),
        format!("chio-a2a-{}", "c".repeat(64))
    );
}
