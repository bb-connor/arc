#![allow(clippy::expect_used, clippy::unwrap_used)]

use super::*;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Once;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

use chio_core::capability::{
    scope::{ChioScope, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::Keypair;
use chio_core::receipt::decision::Decision;
use chio_kernel::{
    ChioKernel, KernelConfig, ToolCallRequest, Verdict, DEFAULT_CHECKPOINT_BATCH_SIZE,
    DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair as RcgenKeyPair,
};

#[path = "tests/support.rs"]
mod support;
use support::*;
#[path = "tests/auth.rs"]
mod auth;
#[path = "tests/discovery_registry.rs"]
mod discovery_registry;
#[path = "tests/invoke_manifest.rs"]
mod invoke_manifest;
#[path = "tests/kernel_receipts.rs"]
mod kernel_receipts;
#[path = "tests/oauth_cache_review.rs"]
mod oauth_cache_review;
#[path = "tests/protocol.rs"]
mod protocol;
#[path = "tests/protocol_boundaries.rs"]
mod protocol_boundaries;
#[path = "tests/streaming_lifecycle.rs"]
mod streaming_lifecycle;

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
