//! RFC-0004 F06: the kernel enforces max_stream_total_bytes at the invoke seam.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_kernel::runtime::{enforce_stream_byte_limit, ToolCallChunk, ToolCallStream};
use chio_kernel::KernelError;

fn chunk(payload: &str) -> ToolCallChunk {
    ToolCallChunk {
        data: serde_json::json!({ "text": payload }),
    }
}

#[test]
fn oversized_stream_is_denied_with_overloaded_streambytes() {
    let stream = ToolCallStream {
        chunks: vec![chunk("aaaa"), chunk("bbbb"), chunk("cccc")],
    };
    // A tiny budget forces a breach.
    let err = enforce_stream_byte_limit(&stream, 8).unwrap_err();
    assert!(
        matches!(
            err,
            KernelError::Overloaded {
                resource: chio_kernel::OverloadResource::StreamBytes
            }
        ),
        "expected Overloaded {{ StreamBytes }}, got {err:?}"
    );
}

#[test]
fn within_budget_stream_is_allowed() {
    let stream = ToolCallStream {
        chunks: vec![chunk("x")],
    };
    assert!(enforce_stream_byte_limit(&stream, 0).is_ok(), "0 = unlimited");
    assert!(enforce_stream_byte_limit(&stream, 1_000_000).is_ok());
}
