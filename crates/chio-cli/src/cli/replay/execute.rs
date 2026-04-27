// Re-execution dispatcher for `chio replay traffic --against <policy-ref>`.
//
// Owned by M10.P2.T2. This file is `include!`'d into `main.rs` and reuses
// the shared `use` declarations from `cli/types.rs`. Sibling modules
// (`policy_ref`, `receipt_partition`, `validate`, `ndjson`) are also
// `include!`'d at the top level, so all references below are unqualified.
//
// Pipeline invariants (per `.planning/trajectory/10-tee-replay-harness.md`
// Phase 2 task 3):
//
// 1. Resolve the supplied [`PolicyRef`] into a materialized
//    [`policy::LoadedPolicy`] (workspace-path arm only in T2; the
//    manifest-hash and package-version arms surface
//    [`PolicyRefError::NotResolvable`] until the registry crates land).
// 2. Build a fresh [`ChioKernel`] under that policy and a fresh
//    ephemeral keypair so re-execution does not contaminate any
//    long-lived production state.
// 3. Allocate a fresh [`StorePartition::Replay`] (random or
//    user-supplied run-id). The dispatcher type-fences this against the
//    production partition: the same kernel cannot accept production
//    writes inside the replay run; the inverse (replay writes against a
//    production-flagged store) is also refused. See
//    `receipt_partition.rs` for the bidirectional refusal contract
//    pinned by milestone-doc line 568.
// 4. For each frame in the NDJSON capture, validate the frame
//    structurally (schema-version + invocation), evaluate the
//    `chio_tool_call_fabric::ToolInvocation` against the kernel, and
//    record a structured per-frame [`TrafficFrameOutcome`] under the
//    namespaced receipt id `replay:<run_id>:<frame_id>`.
// 5. Aggregate the outcomes into a [`TrafficReplayReport`]. The diff renderer
//    in M10.P2.T3 / T4 walks this report; T2 only ships the structural
//    surface plus tests.
//
// The kernel-level evaluation is intentionally narrow: T2 produces a
// recomputed verdict per frame, not a full kernel-state replay (the
// receipt-store wiring stays kernel-default; no on-disk persistence is
// triggered). T4 layers the diff renderer on top; T5 lands the
// integration tests for the canonical M04 exit codes.

/// Per-frame outcome: replay-receipt id, recomputed verdict, and the
/// captured (production) verdict from the source frame. The diff
/// renderer in T4 compares the two to compute drift class.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct TrafficFrameOutcome {
    /// 1-based source line in the input NDJSON.
    pub line: u64,
    /// Source frame `event_id` (used as `frame_id` in the replay
    /// receipt namespace).
    pub frame_id: String,
    /// Namespaced replay receipt id: `replay:<run_id>:<frame_id>`.
    pub replay_receipt_id: String,
    /// Verdict captured by the production tee on the original frame.
    pub captured_verdict: chio_tee_frame::Verdict,
    /// Verdict recomputed by re-running the captured invocation against
    /// the supplied policy-ref. `None` when re-execution failed (the
    /// `error` field carries the detail).
    pub replay_verdict: Option<chio_tee_frame::Verdict>,
    /// Optional re-execution error string. Empty when re-execution
    /// produced a verdict.
    pub error: Option<String>,
}

/// Aggregate report shape returned by [`run_traffic_replay`]. The diff
/// renderer in M10.P2.T3 / T4 consumes this surface; T2 only emits the
/// structural fields.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TrafficReplayReport {
    /// Run-id of the replay partition (mirrors `<run_id>` in receipt
    /// ids). Empty string when the dispatcher ran in production-mode
    /// for some reason; T2 always allocates a replay partition so this
    /// is non-empty in practice.
    pub run_id: String,
    /// `--against` argument verbatim, for log round-tripping.
    pub against_label: String,
    /// Total NDJSON lines processed (excluding skipped blank lines).
    pub total: u64,
    /// Frames whose recomputed verdict matched the captured verdict.
    pub matches: u64,
    /// Frames whose recomputed verdict differed from the captured
    /// verdict ("drift").
    pub drifts: u64,
    /// Frames where re-execution failed (e.g. the kernel could not
    /// evaluate the captured invocation against the new policy).
    pub errors: u64,
    /// Per-frame outcomes in source order.
    pub outcomes: Vec<TrafficFrameOutcome>,
}

impl TrafficReplayReport {
    /// `true` when no drift and no errors were observed.
    pub fn ok(&self) -> bool {
        self.drifts == 0 && self.errors == 0
    }
}

/// Errors surfaced by [`run_traffic_replay`].
#[derive(Debug, thiserror::Error)]
pub enum ExecuteError {
    /// `--against` parse or resolve failure.
    #[error("policy-ref invalid: {0}")]
    PolicyRef(#[from] PolicyRefError),

    /// Failed to open the NDJSON capture stream.
    #[error("failed to open NDJSON capture {path}: {source}")]
    Capture {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// Partition allocation or refusal failure.
    #[error("partition error: {0}")]
    Partition(#[from] PartitionError),

    /// A non-line-level failure during dispatch.
    #[error("execute error: {0}")]
    Other(String),
}

/// Entry point for `chio replay traffic --against <policy-ref>`.
///
/// Walks the NDJSON capture in `args.from`, evaluates each frame's
/// captured `ToolInvocation` against the policy resolved from
/// `against`, and aggregates the outcomes into a [`TrafficReplayReport`].
/// The replay partition is allocated fresh per call so two parallel
/// replay runs cannot collide on receipt ids.
pub fn run_traffic_replay(
    args: &TrafficArgs,
    against: &PolicyRef,
) -> Result<TrafficReplayReport, ExecuteError> {
    // 1. Resolve the policy-ref. T2 only supports the workspace-path arm
    //    fully; the others surface NotResolvable from inside resolve().
    let _resolved = against.resolve()?;
    let loaded_policy = against.load_workspace_policy()?;
    let against_label = against.label();

    // 2. Allocate a fresh replay partition so receipt ids are
    //    namespace-isolated from production. The dispatcher always
    //    allocates a Replay variant; ReplayPartition::new fences this
    //    at the type level. When the caller supplied `--run-id` the
    //    deterministic constructor is used; otherwise a fresh UUID-v4.
    let store_partition = match args.run_id.as_deref() {
        Some(id) => StorePartition::replay_with_run_id(id)?,
        None => StorePartition::replay_with_random_run_id(),
    };
    let replay_partition = ReplayPartition::new(&store_partition)?;
    let run_id = replay_partition.run_id().to_string();

    // 3. Bidirectional refusal sanity check: a production-flagged
    //    request against this replay partition must error. Trip-wire
    //    only; we do not actually run a production write here.
    debug_assert!(store_partition
        .ensure_compatible_with(&StorePartition::Production)
        .is_err());

    // 4. Build the ephemeral kernel under the resolved policy.
    let kernel_kp = chio_core::crypto::Keypair::generate();
    let mut kernel = build_kernel(loaded_policy, &kernel_kp);
    // Register a stub tool server so capability evaluation has a
    // server-id target. This mirrors the pattern in cli::runtime::cmd_check.
    kernel.register_tool_server(Box::new(StubToolServer {
        id: REPLAY_STUB_SERVER_ID.to_string(),
    }));

    // 5. Iterate the NDJSON stream and recompute verdicts.
    let iter = open_ndjson(&args.from).map_err(|e| ExecuteError::Capture {
        path: args.from.display().to_string(),
        source: e,
    })?;

    let mut outcomes: Vec<TrafficFrameOutcome> = Vec::new();
    let mut total: u64 = 0;
    let mut matches: u64 = 0;
    let mut drifts: u64 = 0;
    let mut errors: u64 = 0;

    for record in iter {
        total = total.saturating_add(1);
        match record {
            Ok(record) => {
                let frame_id = record.frame.event_id.clone();
                let replay_id = replay_partition
                    .replay_receipt_id(&frame_id)
                    .map_err(ExecuteError::Partition)?;
                let captured = record.frame.verdict;
                let outcome = match recompute_verdict(&mut kernel, &record.frame) {
                    Ok(replay_verdict) => {
                        if replay_verdict == captured {
                            matches = matches.saturating_add(1);
                        } else {
                            drifts = drifts.saturating_add(1);
                        }
                        TrafficFrameOutcome {
                            line: record.line,
                            frame_id,
                            replay_receipt_id: replay_id,
                            captured_verdict: captured,
                            replay_verdict: Some(replay_verdict),
                            error: None,
                        }
                    }
                    Err(err) => {
                        errors = errors.saturating_add(1);
                        TrafficFrameOutcome {
                            line: record.line,
                            frame_id,
                            replay_receipt_id: replay_id,
                            captured_verdict: captured,
                            replay_verdict: None,
                            error: Some(err),
                        }
                    }
                };
                outcomes.push(outcome);
            }
            Err(err) => {
                // NDJSON-level parse error: surface as a partial outcome
                // with the line number and a stub frame id so the diff
                // renderer can still report on it. Frame id is
                // `parse-error:<line>` so it sorts deterministically.
                errors = errors.saturating_add(1);
                let line = err.line();
                let frame_id = format!("parse-error:{line}");
                let replay_id = replay_partition
                    .replay_receipt_id(&frame_id)
                    .map_err(ExecuteError::Partition)?;
                outcomes.push(TrafficFrameOutcome {
                    line,
                    frame_id,
                    replay_receipt_id: replay_id,
                    captured_verdict: chio_tee_frame::Verdict::Deny,
                    replay_verdict: None,
                    error: Some(err.to_string()),
                });
            }
        }
    }

    Ok(TrafficReplayReport {
        run_id,
        against_label,
        total,
        matches,
        drifts,
        errors,
        outcomes,
    })
}

/// Server id used by the replay stub. Pinned so log lines remain
/// stable across replay runs.
const REPLAY_STUB_SERVER_ID: &str = "chio-replay-stub";

/// Recompute the kernel verdict for a single frame.
///
/// The captured `frame.invocation` is deserialized into a
/// `chio_tool_call_fabric::ToolInvocation`, mapped onto a session
/// operation, and evaluated. The resulting verdict (Allow / Deny /
/// Rewrite) is mapped back into the [`chio_tee_frame::Verdict`] enum so
/// the comparison surface stays uniform with the captured verdict.
fn recompute_verdict(
    kernel: &mut ChioKernel,
    frame: &chio_tee_frame::Frame,
) -> Result<chio_tee_frame::Verdict, String> {
    use chio_tool_call_fabric::ToolInvocation;

    let invocation: ToolInvocation = serde_json::from_value(frame.invocation.clone())
        .map_err(|e| format!("frame.invocation does not deserialize: {e}"))?;

    // The captured `arguments` field is canonical-JSON bytes (M01).
    // Parse them into a serde_json::Value for the kernel surface.
    let arguments: serde_json::Value = serde_json::from_slice(&invocation.arguments)
        .map_err(|e| format!("invocation.arguments not valid JSON: {e}"))?;

    // Allocate an agent keypair and seed an empty default capability so
    // the session opens; the policy under evaluation drives the
    // verdict. This matches the cmd_check pattern in cli::runtime.
    let agent_kp = chio_core::crypto::Keypair::generate();
    let agent_pk = agent_kp.public_key();
    let session_agent_id = agent_pk.to_hex();

    let cap = kernel
        .issue_capability(&agent_pk, ChioScope::default(), 300)
        .map_err(|e| format!("issue replay capability: {e}"))?;
    let session_id = kernel.open_session(session_agent_id.clone(), vec![cap.clone()]);
    kernel
        .activate_session(&session_id)
        .map_err(|e| format!("activate replay session: {e}"))?;

    let context = OperationContext::new(
        session_id.clone(),
        RequestId::new("chio-replay-001"),
        session_agent_id,
    );
    let operation = SessionOperation::ToolCall(ToolCallOperation {
        capability: cap,
        server_id: REPLAY_STUB_SERVER_ID.to_string(),
        tool_name: invocation.tool_name.clone(),
        arguments,
        model_metadata: None,
    });

    match kernel.evaluate_session_operation(&context, &operation) {
        Ok(SessionOperationResponse::ToolCall(response)) => {
            // Map the kernel's `Verdict` (Allow / Deny / PendingApproval)
            // onto the wire-level `chio_tee_frame::Verdict` (Allow / Deny
            // / Rewrite). PendingApproval is treated as Deny in T2 so
            // the diff renderer flags it as material drift; the richer
            // mapping (Rewrite for guard-rewrites, etc.) lands in T4
            // alongside the structured drift class table.
            Ok(map_kernel_verdict_to_frame(response.verdict))
        }
        Ok(_) => {
            // Non-ToolCall responses fall through as Deny so the diff
            // renderer can flag them as material drift.
            Ok(chio_tee_frame::Verdict::Deny)
        }
        Err(e) => Err(format!("kernel evaluate_session_operation: {e}")),
    }
}

/// Coarse-grained mapping from a kernel-level [`chio_kernel::Verdict`] to
/// the wire-level [`chio_tee_frame::Verdict`] enum. This is intentionally
/// simple in T2; the diff renderer in T4 layers the structured drift
/// class (allow-flip, guard-delta, reason-delta) on top of this.
fn map_kernel_verdict_to_frame(verdict: chio_kernel::Verdict) -> chio_tee_frame::Verdict {
    match verdict {
        chio_kernel::Verdict::Allow => chio_tee_frame::Verdict::Allow,
        chio_kernel::Verdict::Deny | chio_kernel::Verdict::PendingApproval => {
            chio_tee_frame::Verdict::Deny
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod replay_execute_tests {
    use super::*;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};

    fn signing_keypair() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn canonical_invocation() -> serde_json::Value {
        use chio_tool_call_fabric::{Principal, ProviderId, ProvenanceStamp, ToolInvocation};
        use std::time::SystemTime;
        let invocation = ToolInvocation {
            provider: ProviderId::OpenAi,
            tool_name: "search".to_string(),
            arguments: br#"{"q":"hello"}"#.to_vec(),
            provenance: ProvenanceStamp {
                provider: ProviderId::OpenAi,
                request_id: "req_abc".to_string(),
                api_version: "2025-10-01".to_string(),
                principal: Principal::OpenAiOrg {
                    org_id: "org_42".to_string(),
                },
                received_at: SystemTime::UNIX_EPOCH,
            },
        };
        let bytes = chio_core::canonical::canonical_json_bytes(&invocation).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn signed_frame(kp: &SigningKey, event_id: &str) -> chio_tee_frame::Frame {
        let mut frame = chio_tee_frame::Frame {
            schema_version: chio_tee_frame::SCHEMA_VERSION.to_string(),
            event_id: event_id.to_string(),
            ts: "2026-04-25T18:02:11.418Z".to_string(),
            tee_id: "tee-prod-1".to_string(),
            upstream: chio_tee_frame::Upstream {
                system: chio_tee_frame::UpstreamSystem::Openai,
                operation: "responses.create".to_string(),
                api_version: "2025-10-01".to_string(),
            },
            invocation: canonical_invocation(),
            provenance: chio_tee_frame::Provenance {
                otel: chio_tee_frame::Otel {
                    trace_id: "0".repeat(32),
                    span_id: "0".repeat(16),
                },
                supply_chain: None,
            },
            request_blob_sha256: "a".repeat(64),
            response_blob_sha256: "b".repeat(64),
            redaction_pass_id: "m06-redactors@1.4.0+default".to_string(),
            verdict: chio_tee_frame::Verdict::Allow,
            deny_reason: None,
            would_have_blocked: false,
            tenant_sig: format!("ed25519:{}", "A".repeat(86)),
        };
        let payload = signing_payload(&frame).unwrap();
        let sig = kp.sign(&payload);
        let encoded = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
        frame.tenant_sig = format!("ed25519:{encoded}");
        frame
    }

    fn write_capture(frames: &[chio_tee_frame::Frame], dir: &std::path::Path) -> PathBuf {
        let path = dir.join("capture.ndjson");
        let mut buf = String::new();
        for f in frames {
            buf.push_str(&serde_json::to_string(f).unwrap());
            buf.push('\n');
        }
        std::fs::write(&path, buf).unwrap();
        path
    }

    fn allow_all_policy(dir: &std::path::Path) -> PathBuf {
        // Minimal Chio YAML policy with permissive defaults. The kernel
        // built from this policy issues capabilities by default and
        // accepts tool calls.
        let path = dir.join("policy.yaml");
        let body = r#"
kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 4
  allow_sampling: false
  allow_sampling_tool_use: false
  allow_elicitation: false
  require_web3_evidence: false
  checkpoint_batch_size: 100
guards: {}
capabilities: {}
"#;
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn run_traffic_replay_emits_namespaced_receipt_ids() {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = allow_all_policy(dir.path());
        let kp = signing_keypair();
        let frame = signed_frame(&kp, "01H7ZZZZZZZZZZZZZZZZZZZZZZ");
        let ndjson_path = write_capture(&[frame], dir.path());

        let args = TrafficArgs {
            from: ndjson_path,
            schema: "chio-tee-frame.v1".to_string(),
            tenant_pubkey: None,
            json: false,
            against: None,
            run_id: None,
        };
        let against = PolicyRef::WorkspacePath(policy_path);
        let report = run_traffic_replay(&args, &against).unwrap();

        assert_eq!(report.total, 1);
        assert_eq!(report.outcomes.len(), 1);
        let outcome = &report.outcomes[0];
        assert_eq!(outcome.line, 1);
        assert_eq!(outcome.frame_id, "01H7ZZZZZZZZZZZZZZZZZZZZZZ");
        assert!(
            outcome
                .replay_receipt_id
                .starts_with(&format!("replay:{}:", report.run_id)),
            "id: {}",
            outcome.replay_receipt_id
        );
        assert!(outcome
            .replay_receipt_id
            .ends_with(":01H7ZZZZZZZZZZZZZZZZZZZZZZ"));
    }

    #[test]
    fn run_traffic_replay_aggregates_total_and_outcomes() {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = allow_all_policy(dir.path());
        let kp = signing_keypair();
        let frames = vec![
            signed_frame(&kp, "01H7ZZZZZZZZZZZZZZZZZZZZZA"),
            signed_frame(&kp, "01H7ZZZZZZZZZZZZZZZZZZZZZB"),
            signed_frame(&kp, "01H7ZZZZZZZZZZZZZZZZZZZZZC"),
        ];
        let ndjson_path = write_capture(&frames, dir.path());

        let args = TrafficArgs {
            from: ndjson_path,
            schema: "chio-tee-frame.v1".to_string(),
            tenant_pubkey: None,
            json: false,
            against: None,
            run_id: None,
        };
        let against = PolicyRef::WorkspacePath(policy_path);
        let report = run_traffic_replay(&args, &against).unwrap();

        assert_eq!(report.total, 3);
        assert_eq!(report.outcomes.len(), 3);
        // All outcomes are namespaced under the same run-id.
        for o in &report.outcomes {
            assert!(o.replay_receipt_id.starts_with(&format!("replay:{}:", report.run_id)));
        }
    }

    #[test]
    fn run_traffic_replay_ndjson_parse_error_routes_to_errors_bucket() {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = allow_all_policy(dir.path());
        let ndjson_path = dir.path().join("capture.ndjson");
        std::fs::write(&ndjson_path, "{not valid json\n").unwrap();

        let args = TrafficArgs {
            from: ndjson_path,
            schema: "chio-tee-frame.v1".to_string(),
            tenant_pubkey: None,
            json: false,
            against: None,
            run_id: None,
        };
        let against = PolicyRef::WorkspacePath(policy_path);
        let report = run_traffic_replay(&args, &against).unwrap();

        assert_eq!(report.total, 1);
        assert_eq!(report.errors, 1);
        assert_eq!(report.outcomes.len(), 1);
        let outcome = &report.outcomes[0];
        assert!(outcome.replay_verdict.is_none());
        assert!(outcome.error.is_some());
        // Parse-error frame ids carry the line number for diff-renderer
        // continuity.
        assert!(outcome.frame_id.starts_with("parse-error:"));
    }

    #[test]
    fn run_traffic_replay_propagates_unresolvable_policy_ref() {
        let dir = tempfile::tempdir().unwrap();
        let kp = signing_keypair();
        let frame = signed_frame(&kp, "01H7ZZZZZZZZZZZZZZZZZZZZZZ");
        let ndjson_path = write_capture(&[frame], dir.path());

        let args = TrafficArgs {
            from: ndjson_path,
            schema: "chio-tee-frame.v1".to_string(),
            tenant_pubkey: None,
            json: false,
            against: None,
            run_id: None,
        };
        // Manifest-hash arm is NotResolvable in T2.
        let hash_str = "ab".repeat(32);
        let against = PolicyRef::parse(&hash_str).unwrap();
        let err = run_traffic_replay(&args, &against).unwrap_err();
        match err {
            ExecuteError::PolicyRef(PolicyRefError::NotResolvable(_)) => {}
            other => panic!("expected NotResolvable, got {other:?}"),
        }
    }

    #[test]
    fn run_traffic_replay_propagates_workspace_load_error() {
        let dir = tempfile::tempdir().unwrap();
        let kp = signing_keypair();
        let frame = signed_frame(&kp, "01H7ZZZZZZZZZZZZZZZZZZZZZZ");
        let ndjson_path = write_capture(&[frame], dir.path());

        let args = TrafficArgs {
            from: ndjson_path,
            schema: "chio-tee-frame.v1".to_string(),
            tenant_pubkey: None,
            json: false,
            against: None,
            run_id: None,
        };
        let against = PolicyRef::parse("path:/no/such/policy.yaml").unwrap();
        let err = run_traffic_replay(&args, &against).unwrap_err();
        match err {
            ExecuteError::PolicyRef(PolicyRefError::Load(_)) => {}
            other => panic!("expected Load, got {other:?}"),
        }
    }

    #[test]
    fn run_traffic_replay_partition_fences_production_writes() {
        // The dispatcher always allocates a Replay partition. Verify
        // the bidirectional refusal trip-wire holds: a Production
        // partition cannot be ensured-compatible with the dispatcher's
        // Replay partition. This is the type-level dual of the M10
        // milestone-doc line 568 contract.
        let store = StorePartition::replay_with_random_run_id();
        let err = store
            .ensure_compatible_with(&StorePartition::Production)
            .unwrap_err();
        assert!(matches!(err, PartitionError::Mismatch { .. }));
    }

    #[test]
    fn frame_replay_outcome_serializes_namespace_under_replay_prefix() {
        // Stable wire-shape check: the JSON encoding carries the
        // `replay_receipt_id` field with the milestone-pinned prefix.
        let outcome = TrafficFrameOutcome {
            line: 1,
            frame_id: "frame-x".to_string(),
            replay_receipt_id: "replay:run-7:frame-x".to_string(),
            captured_verdict: chio_tee_frame::Verdict::Allow,
            replay_verdict: Some(chio_tee_frame::Verdict::Allow),
            error: None,
        };
        let v = serde_json::to_value(&outcome).unwrap();
        assert_eq!(
            v.get("replay_receipt_id").and_then(|s| s.as_str()),
            Some("replay:run-7:frame-x")
        );
    }

    #[test]
    fn replay_report_ok_returns_true_when_no_drift_or_errors() {
        let report = TrafficReplayReport {
            run_id: "run-1".to_string(),
            against_label: "/tmp/p.yaml".to_string(),
            total: 3,
            matches: 3,
            drifts: 0,
            errors: 0,
            outcomes: vec![],
        };
        assert!(report.ok());
    }

    #[test]
    fn replay_report_ok_returns_false_on_drift() {
        let report = TrafficReplayReport {
            run_id: "run-1".to_string(),
            against_label: "/tmp/p.yaml".to_string(),
            total: 3,
            matches: 2,
            drifts: 1,
            errors: 0,
            outcomes: vec![],
        };
        assert!(!report.ok());
    }

    #[test]
    fn replay_report_ok_returns_false_on_error() {
        let report = TrafficReplayReport {
            run_id: "run-1".to_string(),
            against_label: "/tmp/p.yaml".to_string(),
            total: 3,
            matches: 2,
            drifts: 0,
            errors: 1,
            outcomes: vec![],
        };
        assert!(!report.ok());
    }
}
