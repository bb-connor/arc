use crate::*;

pub(crate) fn receipt_content_for_output(
    output: Option<&ToolCallOutput>,
    stream_chunks_expected: Option<u64>,
) -> Result<ReceiptContent, KernelError> {
    match output {
        Some(ToolCallOutput::Value(value)) => {
            let bytes = canonical_json_bytes(value).map_err(|e| {
                KernelError::ReceiptSigningFailed(format!("failed to hash tool output: {e}"))
            })?;
            Ok(ReceiptContent {
                content_hash: sha256_hex(&bytes),
                metadata: None,
                canonical_content: bytes,
            })
        }
        Some(ToolCallOutput::Stream(stream)) => {
            stream_receipt_content(stream, stream_chunks_expected)
        }
        None => Ok(ReceiptContent {
            content_hash: sha256_hex(b"null"),
            metadata: None,
            canonical_content: b"null".to_vec(),
        }),
    }
}

fn stream_receipt_content(
    stream: &ToolCallStream,
    chunks_expected: Option<u64>,
) -> Result<ReceiptContent, KernelError> {
    let mut chunk_hashes = Vec::with_capacity(stream.chunks.len());
    let mut combined = Vec::new();
    let mut total_bytes = 0u64;

    for chunk in &stream.chunks {
        let bytes = canonical_json_bytes(&chunk.data).map_err(|e| {
            KernelError::ReceiptSigningFailed(format!("failed to hash stream chunk: {e}"))
        })?;
        total_bytes += bytes.len() as u64;
        let chunk_hash = sha256_hex(&bytes);
        combined.extend_from_slice(chunk_hash.as_bytes());
        chunk_hashes.push(chunk_hash);
    }

    Ok(ReceiptContent {
        content_hash: sha256_hex(&combined),
        metadata: Some(serde_json::json!({
            "stream": {
                "chunks_expected": chunks_expected,
                "chunks_received": stream.chunk_count(),
                "total_bytes": total_bytes,
                "chunk_hashes": chunk_hashes,
            }
        })),
        // The signing-boundary recompute must hash the same preimage this
        // `content_hash` was derived from: the concatenated per-chunk digests,
        // not the raw stream payload.
        canonical_content: combined,
    })
}

/// Why a stream was truncated at finalize time (RFC-0004 F06). Reported so the
/// caller can mark the receipt incomplete with a limit-accurate reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamTruncationCause {
    /// Retaining the next chunk would exceed `max_stream_total_bytes`.
    ByteLimit,
    /// The retained-chunk count reached `max_stream_chunks`.
    ChunkLimit,
}

/// Truncate a materialized stream to the configured retention limits, returning
/// the retained prefix, its canonical byte total, and the truncation cause (if
/// any). Bounds BOTH the total bytes (`max_stream_total_bytes`) and the retained
/// chunk COUNT (`max_stream_chunks`); the chunk-count bound stops a flood of tiny
/// chunks from growing the retained `Vec`/per-chunk signing preimage even when the
/// byte cap is never reached (RFC-0004 F06). Both caps use `0 = unlimited`.
pub(crate) fn truncate_stream_to_limits(
    stream: &ToolCallStream,
    max_stream_total_bytes: u64,
    max_stream_chunks: u64,
) -> Result<(ToolCallStream, u64, Option<StreamTruncationCause>), KernelError> {
    let mut accepted = Vec::new();
    let mut total_bytes = 0u64;
    let mut cause = None;

    for chunk in &stream.chunks {
        // Chunk-count bound first: retaining another chunk would exceed the cap.
        if max_stream_chunks > 0 && accepted.len() as u64 >= max_stream_chunks {
            cause = Some(StreamTruncationCause::ChunkLimit);
            break;
        }
        let bytes = canonical_json_bytes(&chunk.data).map_err(|e| {
            KernelError::ReceiptSigningFailed(format!("failed to size stream chunk: {e}"))
        })?;
        let chunk_bytes = bytes.len() as u64;
        if max_stream_total_bytes > 0
            && total_bytes.saturating_add(chunk_bytes) > max_stream_total_bytes
        {
            cause = Some(StreamTruncationCause::ByteLimit);
            break;
        }
        total_bytes += chunk_bytes;
        accepted.push(chunk.clone());
    }

    Ok((ToolCallStream { chunks: accepted }, total_bytes, cause))
}
