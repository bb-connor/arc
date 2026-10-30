//! Signed metadata block `stream`: the kernel-counted size of a streamed tool output.
//!
//! Per-chunk digests are not written to any signed field: the content commitment covers the
//! stream preimage. A complete stream is identified by the receipt's completion state, so the
//! block carries no expected chunk count.

use serde::{Deserialize, Serialize};

/// Signed metadata block `stream`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StreamReceiptProjection {
    /// Number of chunks the kernel retained.
    pub chunks_received: u64,
    /// Total canonical JSON bytes of the retained chunks.
    pub total_bytes: u64,
}

impl StreamReceiptProjection {
    /// Decodes the `stream` block of `metadata`. Absent is `Ok(None)`; a present block with a
    /// missing or unknown member refuses.
    pub fn from_metadata(
        metadata: Option<&serde_json::Value>,
    ) -> Result<Option<Self>, serde_json::Error> {
        metadata
            .and_then(|metadata| metadata.get("stream"))
            .map(Self::deserialize)
            .transpose()
    }
}
