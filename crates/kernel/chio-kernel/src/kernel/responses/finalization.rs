use super::*;

pub(crate) struct FinalizeToolOutputCostContext<'a> {
    pub(crate) charge_result: Option<BudgetChargeResult>,
    pub(crate) reported_cost: Option<ToolInvocationCost>,
    pub(crate) payment_authorization: Option<PaymentAuthorization>,
    pub(crate) cap: &'a CapabilityToken,
}

struct PostInvocationHandling {
    output: ToolServerOutput,
    extra_metadata: Option<serde_json::Value>,
    blocked_reason: Option<String>,
    evidence: Vec<chio_core::receipt::metadata::GuardEvidence>,
}

impl ChioKernel {
    pub(crate) fn finalize_tool_output_with_metadata(
        &self,
        request: &ToolCallRequest,
        output: ToolServerOutput,
        elapsed: Duration,
        timestamp: u64,
        matched_grant_index: usize,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        let output = self.apply_stream_limits(output, elapsed)?;
        let post_invocation = self.apply_post_invocation_pipeline(
            request,
            output,
            Some(matched_grant_index),
            extra_metadata,
        )?;
        let _post_invocation_evidence_scope =
            scope_post_invocation_guard_evidence(post_invocation.evidence);
        if let Some(reason) = post_invocation.blocked_reason.as_deref() {
            return self.build_deny_response_with_metadata(
                request,
                reason,
                timestamp,
                Some(matched_grant_index),
                post_invocation.extra_metadata,
            );
        }

        match post_invocation.output {
            ToolServerOutput::Value(value) => self.build_allow_response_with_metadata(
                request,
                ToolCallOutput::Value(value),
                timestamp,
                Some(matched_grant_index),
                post_invocation.extra_metadata,
            ),
            ToolServerOutput::Stream(ToolServerStreamResult::Complete(stream)) => self
                .build_allow_response_with_metadata(
                    request,
                    ToolCallOutput::Stream(stream),
                    timestamp,
                    Some(matched_grant_index),
                    post_invocation.extra_metadata,
                ),
            ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { stream, reason }) => self
                .build_incomplete_response_with_output_and_metadata(
                    request,
                    Some(ToolCallOutput::Stream(stream)),
                    &reason,
                    timestamp,
                    Some(matched_grant_index),
                    post_invocation.extra_metadata,
                ),
        }
    }

    fn apply_post_invocation_pipeline(
        &self,
        request: &ToolCallRequest,
        output: ToolServerOutput,
        matched_grant_index: Option<usize>,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<PostInvocationHandling, KernelError> {
        if self.post_invocation_pipeline.is_empty() {
            return Ok(PostInvocationHandling {
                output,
                extra_metadata,
                blocked_reason: None,
                evidence: Vec::new(),
            });
        }

        let response = self.output_to_post_invocation_value(&output);
        let context = crate::post_invocation::PostInvocationContext::from_request(
            request,
            matched_grant_index,
        );
        let outcome = self
            .post_invocation_pipeline
            .evaluate_with_context_and_evidence(&context, &response);
        let metadata =
            merge_metadata_objects(extra_metadata, self.post_invocation_metadata(&outcome));

        match outcome.verdict {
            crate::post_invocation::PostInvocationVerdict::Allow
            | crate::post_invocation::PostInvocationVerdict::Escalate(_) => {
                Ok(PostInvocationHandling {
                    output,
                    extra_metadata: metadata,
                    blocked_reason: None,
                    evidence: outcome.evidence,
                })
            }
            crate::post_invocation::PostInvocationVerdict::Block(reason) => {
                Ok(PostInvocationHandling {
                    output,
                    extra_metadata: metadata,
                    blocked_reason: Some(reason),
                    evidence: outcome.evidence,
                })
            }
            crate::post_invocation::PostInvocationVerdict::Redact(redacted) => {
                // Redaction replaces the retained stream with hook-supplied
                // content that never passed `apply_stream_limits` (that ran on the
                // ORIGINAL output, before this hook). Re-apply the byte + chunk
                // caps to the redacted stream so a sanitizer/custom hook that emits
                // more than `max_stream_total_bytes` / `max_stream_chunks` cannot
                // grow the final signed output and receipt preimage past the
                // configured budget (RFC-0004 F06, codex finding 3555410410).
                let redacted_output = self.apply_redacted_output(redacted)?;
                Ok(PostInvocationHandling {
                    output: self.reapply_stream_caps_after_redaction(redacted_output)?,
                    extra_metadata: metadata,
                    blocked_reason: None,
                    evidence: outcome.evidence,
                })
            }
        }
    }

    fn output_to_post_invocation_value(&self, output: &ToolServerOutput) -> serde_json::Value {
        match output {
            ToolServerOutput::Value(value) => serde_json::json!({
                "kind": "value",
                "value": value,
            }),
            ToolServerOutput::Stream(ToolServerStreamResult::Complete(stream)) => {
                serde_json::json!({
                    "kind": "stream",
                    "stream": {
                        "complete": true,
                        "chunks": stream.chunks.iter().map(|chunk| chunk.data.clone()).collect::<Vec<_>>(),
                    }
                })
            }
            ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { stream, reason }) => {
                serde_json::json!({
                    "kind": "stream",
                    "stream": {
                        "complete": false,
                        "reason": reason,
                        "chunks": stream.chunks.iter().map(|chunk| chunk.data.clone()).collect::<Vec<_>>(),
                    }
                })
            }
        }
    }

    fn apply_redacted_output(
        &self,
        redacted: serde_json::Value,
    ) -> Result<ToolServerOutput, KernelError> {
        parse_redacted_output(redacted)
    }

    /// Re-apply the byte + chunk stream caps to output produced by a
    /// post-invocation `Redact` hook.
    ///
    /// `apply_stream_limits` runs on the ORIGINAL tool output, before the
    /// post-invocation pipeline. A `Redact` verdict swaps in hook-supplied content
    /// that has not been capped, so without this pass a hook could emit a stream
    /// with more than `max_stream_chunks` retained chunks (or more than
    /// `max_stream_total_bytes`) and grow the signed output and receipt preimage
    /// past the configured budget (RFC-0004 F06, codex finding 3555410410).
    ///
    /// Only the retention caps are re-applied. The stream-duration limit is
    /// intentionally NOT re-evaluated: it bounds tool execution time, not redacted
    /// content, and was already decided on the original output. A non-stream
    /// redacted output (a value) is returned unchanged. Any pre-existing
    /// incomplete reason on the redacted stream is preserved unless a cap fires.
    fn reapply_stream_caps_after_redaction(
        &self,
        output: ToolServerOutput,
    ) -> Result<ToolServerOutput, KernelError> {
        let ToolServerOutput::Stream(stream_result) = output else {
            return Ok(output);
        };

        let (stream, base_reason) = match stream_result {
            ToolServerStreamResult::Complete(stream) => (stream, None),
            ToolServerStreamResult::Incomplete { stream, reason } => (stream, Some(reason)),
        };

        let (stream, _total_bytes, truncation_cause) = truncate_stream_to_limits(
            &stream,
            self.config.max_stream_total_bytes,
            self.config.memory_budget.max_stream_chunks,
        )?;

        let reason = match truncation_cause {
            Some(StreamTruncationCause::ByteLimit) => Some(format!(
                "CHIO_SERVER_STREAM_LIMIT: stream exceeded max total bytes of {}",
                self.config.max_stream_total_bytes
            )),
            Some(StreamTruncationCause::ChunkLimit) => Some(format!(
                "CHIO_SERVER_STREAM_LIMIT: stream exceeded max chunk count of {}",
                self.config.memory_budget.max_stream_chunks
            )),
            None => base_reason,
        };

        Ok(match reason {
            Some(reason) => {
                ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { stream, reason })
            }
            None => ToolServerOutput::Stream(ToolServerStreamResult::Complete(stream)),
        })
    }

    fn post_invocation_metadata(
        &self,
        outcome: &crate::post_invocation::PipelineOutcome,
    ) -> Option<serde_json::Value> {
        let mut metadata = serde_json::Map::new();

        if matches!(
            outcome.verdict,
            crate::post_invocation::PostInvocationVerdict::Redact(_)
        ) {
            metadata.insert("sanitized".to_string(), serde_json::Value::Bool(true));
        }
        if !outcome.escalations.is_empty() {
            metadata.insert(
                "escalations".to_string(),
                serde_json::Value::Array(
                    outcome
                        .escalations
                        .iter()
                        .cloned()
                        .map(serde_json::Value::String)
                        .collect(),
                ),
            );
        }

        if metadata.is_empty() {
            None
        } else {
            Some(serde_json::json!({ "post_invocation": metadata }))
        }
    }

    pub(crate) fn apply_stream_limits(
        &self,
        output: ToolServerOutput,
        elapsed: Duration,
    ) -> Result<ToolServerOutput, KernelError> {
        let ToolServerOutput::Stream(stream_result) = output else {
            return Ok(output);
        };

        let duration_limit = Duration::from_secs(self.config.max_stream_duration_secs);
        let duration_exceeded =
            self.config.max_stream_duration_secs > 0 && elapsed > duration_limit;

        let (stream, base_reason) = match stream_result {
            ToolServerStreamResult::Complete(stream) => (stream, None),
            ToolServerStreamResult::Incomplete { stream, reason } => (stream, Some(reason)),
        };

        let (stream, total_bytes, truncation_cause) = truncate_stream_to_limits(
            &stream,
            self.config.max_stream_total_bytes,
            self.config.memory_budget.max_stream_chunks,
        )?;

        let limit_reason = match truncation_cause {
            Some(StreamTruncationCause::ByteLimit) => Some(format!(
                "CHIO_SERVER_STREAM_LIMIT: stream exceeded max total bytes of {}",
                self.config.max_stream_total_bytes
            )),
            Some(StreamTruncationCause::ChunkLimit) => Some(format!(
                "CHIO_SERVER_STREAM_LIMIT: stream exceeded max chunk count of {}",
                self.config.memory_budget.max_stream_chunks
            )),
            None if duration_exceeded => Some(format!(
                "CHIO_SERVER_STREAM_LIMIT: stream exceeded max duration of {}s",
                self.config.max_stream_duration_secs
            )),
            None => None,
        };

        if let Some(reason) = limit_reason {
            warn!(
                request_bytes = total_bytes,
                elapsed_ms = elapsed.as_millis(),
                "stream output exceeded configured limits"
            );
            return Ok(ToolServerOutput::Stream(
                ToolServerStreamResult::Incomplete { stream, reason },
            ));
        }

        if let Some(reason) = base_reason {
            Ok(ToolServerOutput::Stream(
                ToolServerStreamResult::Incomplete { stream, reason },
            ))
        } else {
            Ok(ToolServerOutput::Stream(ToolServerStreamResult::Complete(
                stream,
            )))
        }
    }
}

fn parse_redacted_output(redacted: serde_json::Value) -> Result<ToolServerOutput, KernelError> {
    let envelope = redacted.as_object().ok_or_else(|| {
        KernelError::Internal(
            "post-invocation hook returned a non-object output envelope".to_string(),
        )
    })?;
    let kind = envelope
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            KernelError::Internal(
                "post-invocation hook output envelope is missing kind".to_string(),
            )
        })?;

    match kind {
        "value" => Ok(ToolServerOutput::Value(
            envelope
                .get("value")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        )),
        "stream" => {
            let stream = envelope
                .get("stream")
                .and_then(serde_json::Value::as_object)
                .ok_or_else(|| {
                    KernelError::Internal(
                        "post-invocation hook output envelope is missing stream".to_string(),
                    )
                })?;
            let chunks = stream
                .get("chunks")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| {
                    KernelError::Internal(
                        "post-invocation hook stream envelope is missing chunks".to_string(),
                    )
                })?
                .iter()
                .cloned()
                .map(|data| ToolCallChunk { data })
                .collect();
            let tool_stream = ToolCallStream { chunks };
            let complete = stream
                .get("complete")
                .and_then(serde_json::Value::as_bool)
                .ok_or_else(|| {
                    KernelError::Internal(
                        "post-invocation hook stream envelope is missing complete".to_string(),
                    )
                })?;
            if complete {
                Ok(ToolServerOutput::Stream(ToolServerStreamResult::Complete(
                    tool_stream,
                )))
            } else {
                let reason = stream
                    .get("reason")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| {
                        KernelError::Internal(
                            "post-invocation hook incomplete stream is missing reason".to_string(),
                        )
                    })?;
                Ok(ToolServerOutput::Stream(
                    ToolServerStreamResult::Incomplete {
                        stream: tool_stream,
                        reason: reason.to_string(),
                    },
                ))
            }
        }
        other => Err(KernelError::Internal(format!(
            "post-invocation hook returned unsupported output kind {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacted_stream_requires_complete_flag() {
        let err = parse_redacted_output(serde_json::json!({
            "kind": "stream",
            "stream": {
                "chunks": []
            }
        }))
        .expect_err("missing complete flag should be rejected");

        match err {
            KernelError::Internal(message) => {
                assert!(
                    message.contains("missing complete"),
                    "unexpected error message: {message}"
                );
            }
            other => panic!("expected KernelError::Internal, got {other:?}"),
        }
    }
}
