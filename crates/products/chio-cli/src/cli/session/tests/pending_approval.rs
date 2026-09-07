//! Pending approval delivery through the real stdio handler and durable admission.

use super::*;
use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    GovernedTransactionIntent, ThresholdApprovalProposal,
};
use chio_core::capability::scope::{Constraint, MonetaryAmount};
use chio_core::capability::threshold_approval::{
    ThresholdApprovalRequirement, ThresholdApproverIdentity,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct CountingServer(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl chio_kernel::ToolServerConnection for CountingServer {
    fn server_id(&self) -> &str {
        "pending-server"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["echo".into()]
    }
    async fn invoke(
        &self,
        _tool: &str,
        arguments: serde_json::Value,
        _bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<serde_json::Value, chio_kernel::KernelError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(arguments)
    }
}

struct Fixture {
    kernel: ChioKernel,
    session_id: SessionId,
    agent_id: String,
    message: AgentMessage,
    stats: SessionStats,
    calls: Arc<AtomicUsize>,
    approver: Keypair,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let policy = policy::parse_policy(
            "capabilities:\n  default:\n    tools:\n      - server: pending-server\n        tool: echo\n        operations: [invoke]\n        ttl: 300\n",
        )?;
        let mut kernel = build_kernel_with_receipt_store(
            load_test_policy_runtime(&policy),
            &Keypair::generate(),
        );
        let calls = Arc::new(AtomicUsize::new(0));
        kernel.register_tool_server(Box::new(CountingServer(calls.clone())));
        let approver = Keypair::generate();
        let requirement = ThresholdApprovalRequirement::new(
            chio_core::sha256_hex(b"test-runtime-policy"),
            1,
            vec![ThresholdApproverIdentity {
                identifier: "reviewer".into(),
                public_key: approver.public_key(),
            }],
            "pending-test-directory".into(),
            120,
        )?;
        kernel.set_threshold_approval_requirement_resolver(Arc::new(
            move |policy_hash: &str, server: &str, tool: &str| {
                Ok((policy_hash == requirement.policy_hash
                    && server == "pending-server"
                    && tool == "echo")
                    .then(|| requirement.clone()))
            },
        ));
        let agent = Keypair::generate();
        let mut scope = first_default_capability(&kernel, &policy, &agent).scope;
        scope.grants[0]
            .constraints
            .push(Constraint::RequireCumulativeApprovalAbove {
                threshold: MonetaryAmount {
                    units: 100,
                    currency: "USD".into(),
                },
                approval_budget_id: "pending-test-budget".into(),
                approval_budget_epoch: 1,
                cumulative_approval_root_binding: None,
            });
        let capability = kernel.issue_capability(&agent.public_key(), scope, 300)?;
        let agent_id = agent.public_key().to_hex();
        let session_id = open_ready_session(&mut kernel, &agent_id, vec![capability.clone()]);
        Ok(Self {
            kernel,
            session_id,
            agent_id,
            calls,
            approver,
            stats: SessionStats::default(),
            message: AgentMessage::ToolCallRequest {
                id: "pending-request".into(),
                capability_token: Box::new(capability),
                server_id: "pending-server".into(),
                tool: "echo".into(),
                params: Box::new(serde_json::json!({"text": "original parameters"})),
                governed_intent: Some(Box::new(GovernedTransactionIntent {
                    id: "pending-intent".into(),
                    server_id: "pending-server".into(),
                    tool_name: "echo".into(),
                    purpose: "authorize a bounded mutation".into(),
                    max_amount: Some(MonetaryAmount {
                        units: 100,
                        currency: "USD".into(),
                    }),
                    commerce: None,
                    metered_billing: None,
                    runtime_attestation: None,
                    call_chain: None,
                    autonomy: None,
                    context: None,
                    body: Default::default(),
                })),
                approval_token: None,
                approval_tokens: Vec::new(),
                threshold_approval_proposal: None,
                supplemental_authorization: None,
                execution_nonce: None,
            },
        })
    }

    fn send(&mut self) -> TestResult<KernelMessage> {
        use chio_kernel::transport::{read_frame, write_frame, ChioTransport};
        use std::io::Cursor;

        let mut inbound = Vec::new();
        write_frame(
            &mut inbound,
            &chio_core::canonical_json_bytes(&self.message)?,
        )?;
        let mut outbound = Vec::new();
        let mut transport = ChioTransport::new(Cursor::new(inbound), &mut outbound);
        let request = transport.recv()?;
        let messages = handle_agent_message(
            &mut self.kernel,
            &request,
            &self.session_id,
            &self.agent_id,
            &mut self.stats,
        );
        assert_eq!(messages.len(), 1);
        transport.send(messages.first().ok_or("response missing")?)?;
        drop(transport);
        let mut output = Cursor::new(outbound);
        let response = serde_json::from_slice(&read_frame(&mut output)?)?;
        assert_eq!(output.position(), output.get_ref().len() as u64);
        Ok(response)
    }

    fn approve(&mut self, proposal: ThresholdApprovalProposal) -> TestResult {
        let AgentMessage::ToolCallRequest {
            approval_tokens,
            threshold_approval_proposal,
            ..
        } = &mut self.message
        else {
            return Err("tool request missing".into());
        };
        *approval_tokens = vec![GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: "pending-vote".into(),
                approver: self.approver.public_key(),
                subject: proposal.body.subject.clone(),
                governed_intent_hash: proposal.body.governed_intent_hash.clone(),
                request_id: proposal.body.request_id.clone(),
                threshold_proposal_hash: Some(proposal.artifact_digest()?),
                issued_at: proposal.body.proposal_created_at,
                expires_at: proposal.body.proposal_deadline,
                decision: GovernedApprovalDecision::Approved,
            },
            &self.approver,
        )?];
        *threshold_approval_proposal = Some(Box::new(proposal));
        Ok(())
    }
}

#[test]
fn pending_approval_projection_rejects_broken_shape_and_signed_content_bindings() -> TestResult {
    let fixture = Fixture::new()?;
    let (context, operation) =
        normalize_agent_message(&fixture.message, &fixture.session_id, &fixture.agent_id);
    let SessionOperationResponse::ToolCall(response) = fixture
        .kernel
        .evaluate_session_operation(&context, &operation)?
    else {
        return Err("tool response missing".into());
    };
    assert_eq!(response.verdict, chio_kernel::Verdict::PendingApproval);
    type Mutation = (&'static str, fn(&mut chio_kernel::ToolCallResponse));
    let mutations: &[Mutation] = &[
        ("missing proposal", |response| response.output = None),
        ("stream payload", |response| {
            response.output = Some(ToolCallOutput::Stream(ToolCallStream {
                chunks: vec![chio_kernel::ToolCallChunk {
                    data: serde_json::json!({"must_not_escape": true}),
                }],
            }))
        }),
        ("terminal completion", |response| {
            response.terminal_state = OperationTerminalState::Completed
        }),
        ("other incomplete state", |response| {
            response.terminal_state = OperationTerminalState::Incomplete {
                reason: "different".into(),
            }
        }),
        ("response request", |response| {
            response.request_id = "other-request".into()
        }),
        ("receipt request", |response| {
            response.receipt.metadata =
                Some(serde_json::json!({"receipt_context": {"request_id": "other-request"}}))
        }),
        ("receipt content", |response| {
            response.receipt.content_hash = "0".repeat(64)
        }),
        ("unknown proposal field", |response| {
            if let Some(ToolCallOutput::Value(value)) = &mut response.output {
                value["unsigned_extension"] = serde_json::json!(true);
            }
        }),
        ("proposal request", |response| {
            if let Some(ToolCallOutput::Value(value)) = &mut response.output {
                value["request_id"] = serde_json::json!("other-request");
            }
        }),
        ("empty quorum", |response| {
            if let Some(ToolCallOutput::Value(value)) = &mut response.output {
                value["threshold"] = serde_json::json!(0);
            }
        }),
        ("rewritten algorithm encoding", |response| {
            if let Some(ToolCallOutput::Value(value)) = &mut response.output {
                value["algorithm"] = serde_json::json!("ed25519");
            }
        }),
    ];
    for (label, mutate) in mutations {
        let mut altered = chio_kernel::ToolCallResponse {
            request_id: response.request_id.clone(),
            verdict: response.verdict,
            output: response.output.clone(),
            reason: response.reason.clone(),
            terminal_state: response.terminal_state.clone(),
            receipt: response.receipt.clone(),
            execution_nonce: response.execution_nonce.clone(),
        };
        mutate(&mut altered);
        assert!(
            tool_response_messages("pending-request".into(), altered).is_err(),
            "accepted {label}"
        );
    }
    assert!(tool_response_messages("other-request".into(), response).is_err());
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn pending_approval_projection_rejects_execution_authority() -> TestResult {
    use chio_core::message::{ExecutionNonce, NonceBinding, SignedExecutionNonce};

    let fixture = Fixture::new()?;
    let (context, operation) =
        normalize_agent_message(&fixture.message, &fixture.session_id, &fixture.agent_id);
    let SessionOperationResponse::ToolCall(mut response) = fixture
        .kernel
        .evaluate_session_operation(&context, &operation)?
    else {
        return Err("tool response missing".into());
    };
    let nonce = ExecutionNonce {
        schema: "chio.execution_nonce.v1".into(),
        nonce_id: "not-an-approval".into(),
        issued_at: 1,
        expires_at: 2,
        bound_to: NonceBinding {
            subject_id: fixture.agent_id.clone(),
            request_id: "pending-request".into(),
            capability_id: "capability".into(),
            tool_server: "pending-server".into(),
            tool_name: "echo".into(),
            parameter_hash: "0".repeat(64),
        },
        reserved_hold_id: None,
        reserving_request_id: None,
    };
    let signature = fixture.approver.sign_canonical(&nonce)?.0;
    response.execution_nonce = Some(Box::new(SignedExecutionNonce { nonce, signature }));
    assert!(tool_response_messages("pending-request".into(), response).is_err());
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn pending_approval_altered_retry_preserves_the_original_wait() -> TestResult {
    let mut fixture = Fixture::new()?;
    let KernelMessage::ToolCallResponse {
        result: ToolCallResult::PendingApproval { proposal },
        ..
    } = fixture.send()?
    else {
        return Err("pending response missing".into());
    };
    fixture.approve(*proposal)?;
    let original = fixture.message.clone();
    if let AgentMessage::ToolCallRequest { params, .. } = &mut fixture.message {
        **params = serde_json::json!({"text": "replacement parameters"});
    }
    let rejected = fixture.send()?;
    assert!(matches!(
        rejected,
        KernelMessage::ToolCallResponse {
            result: ToolCallResult::Err { .. },
            ..
        }
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    fixture.message = original;
    assert!(matches!(
        fixture.send()?,
        KernelMessage::ToolCallResponse {
            result: ToolCallResult::Ok { .. },
            ..
        }
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn pending_approval_transports_the_signed_proposal_without_dispatch() -> TestResult {
    let mut fixture = Fixture::new()?;
    let response = fixture.send()?;
    let wire = serde_json::to_value(&response)?;
    assert_eq!(wire["result"]["status"], "pending_approval");
    let proposal: ThresholdApprovalProposal =
        serde_json::from_value(wire["result"]["proposal"].clone())?;
    assert!(proposal.verify_signature()?);
    assert_eq!(proposal.body.request_id, "pending-request");
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    let KernelMessage::ToolCallResponse {
        receipt,
        execution_nonce,
        ..
    } = response
    else {
        return Err("tool response missing".into());
    };
    assert!(execution_nonce.is_none());
    assert!(receipt.verify_signature()?);
    assert_eq!(
        receipt.kernel_key,
        fixture.kernel.receipt_signing_public_key()
    );
    assert_eq!(
        receipt.content_hash,
        chio_core::sha256_hex(&chio_core::canonical_json_bytes(&proposal)?)
    );
    assert_eq!(fixture.stats.denied, 0);
    assert_eq!(fixture.stats.allowed, 0);
    assert_eq!(fixture.stats.pending_approval, 1);
    assert!(fixture
        .kernel
        .receipt_log()
        .receipts()
        .iter()
        .any(|record| record.id == receipt.id));
    Ok(())
}

#[test]
fn pending_approval_round_trip_resumes_the_original_request_once() -> TestResult {
    let mut fixture = Fixture::new()?;
    let bytes = chio_core::canonical_json_bytes(&fixture.send()?)?;
    let returned: KernelMessage = serde_json::from_slice(&bytes)?;
    let KernelMessage::ToolCallResponse {
        result: ToolCallResult::PendingApproval { proposal },
        receipt,
        ..
    } = returned
    else {
        return Err("pending proposal missing".into());
    };
    assert_eq!(
        receipt.content_hash,
        chio_core::sha256_hex(&chio_core::canonical_json_bytes(&proposal)?)
    );
    fixture.approve(*proposal)?;
    // Retry material is reconstructed from the actual wire reply, not read from
    // the kernel's retained proposal or a separately re-created artifact.
    fixture.message = serde_json::from_slice(&chio_core::canonical_json_bytes(&fixture.message)?)?;
    {
        let reply = fixture.send()?;
        let KernelMessage::ToolCallResponse {
            id,
            result: ToolCallResult::Ok { value },
            receipt,
            ..
        } = reply
        else {
            return Err("approved retry did not complete".into());
        };
        assert_eq!(id, "pending-request");
        assert_eq!(value, serde_json::json!({"text": "original parameters"}));
        assert!(receipt.verify_signature()?);
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    }
    let session = fixture
        .kernel
        .session(&fixture.session_id)
        .ok_or("session missing")?;
    assert!(session.inflight().is_empty());
    assert_eq!(
        session.terminal().get(&RequestId::new("pending-request")),
        Some(OperationTerminalState::Completed)
    );
    // Completed live-session requests are not restarted. Durable terminal
    // recovery is a separate contract; this transport change does not add it.
    let duplicate = fixture.send()?;
    assert!(matches!(
        duplicate,
        KernelMessage::ToolCallResponse {
            result: ToolCallResult::Err { .. },
            ..
        }
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.stats.requests, 3);
    assert_eq!(fixture.stats.pending_approval, 1);
    assert_eq!(fixture.stats.allowed, 1);
    assert_eq!(fixture.stats.denied, 0);
    assert_eq!(fixture.stats.evaluation_errors, 1);
    Ok(())
}
