#![allow(clippy::expect_used, clippy::unwrap_used)]
use crate::discovery::dispatch_message_id;
use chio_kernel::ToolDispatchContext;

mod auth;
mod discovery_registry;
mod invoke_manifest;
mod kernel_receipts;
mod oauth_cache_review;
mod protocol;
mod protocol_boundaries;
mod streaming_lifecycle;
mod support;
mod unsigned_http;

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
