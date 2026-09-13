//! Failure reporting through the actual stdio session handler and durable stores.

use super::*;
use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
};
use chio_core::receipt::body::ChioReceipt;
use chio_core::receipt::kinds::{BoundaryClass, ObservationOutcome, ReceiptKind};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    kernel: ChioKernel,
    receipt_db_path: std::path::PathBuf,
    session_id: SessionId,
    agent_id: String,
    message: AgentMessage,
    stats: SessionStats,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let policy = policy::parse_policy(
            "capabilities:\n  default:\n    tools:\n      - server: failure-server\n        tool: echo\n        operations: [invoke]\n        ttl: 300\n",
        )?;
        let loaded = load_test_policy_runtime(&policy);
        let admission_db_path = unique_db_path("chio-cli-failure-admission");
        let admission = open_durable_admission_runtime(
            loaded.kernel.durable_admission_mode,
            Some(&admission_db_path),
        )?
        .ok_or("durable admission disabled")?;
        let mut kernel = build_kernel(loaded, &admission.kernel_keypair());
        let receipt_db_path = unique_db_path("chio-cli-failure-receipts");
        configure_receipt_store(&mut kernel, Some(&receipt_db_path), None, None)?;
        admission.attach(&mut kernel)?;
        kernel.register_tool_server(Box::new(StubToolServer {
            id: "failure-server".into(),
        }));
        let agent = Keypair::generate();
        let capability = first_default_capability(&kernel, &policy, &agent);
        let agent_id = agent.public_key().to_hex();
        let session_id = open_ready_session(&mut kernel, &agent_id, vec![capability.clone()]);
        Ok(Self {
            kernel,
            receipt_db_path,
            session_id,
            agent_id,
            message: AgentMessage::ToolCallRequest {
                id: "failure-receipt-request".into(),
                capability_token: Box::new(capability),
                server_id: "failure-server".into(),
                tool: "echo".into(),
                params: Box::new(serde_json::json!({"text": "original parameters"})),
                governed_intent: None,
                approval_token: None,
                approval_tokens: Vec::new(),
                threshold_approval_proposal: None,
                supplemental_authorization: None,
                execution_nonce: None,
            },
            stats: SessionStats::default(),
        })
    }

    fn send(&mut self) -> TestResult<(ToolCallResult, ChioReceipt)> {
        let messages = handle_agent_message(
            &mut self.kernel,
            &self.message,
            &self.session_id,
            &self.agent_id,
            &mut self.stats,
        );
        if messages.len() != 1 {
            return Err("expected one response".into());
        }
        let Some(KernelMessage::ToolCallResponse {
            result, receipt, ..
        }) = messages.into_iter().next()
        else {
            return Err("tool response missing".into());
        };
        Ok((result, *receipt))
    }

    fn complete(&mut self) -> TestResult<ChioReceipt> {
        let (result, receipt) = self.send()?;
        assert!(matches!(result, ToolCallResult::Ok { .. }), "{result:?}");
        Ok(receipt)
    }

    fn conflict(&mut self) -> TestResult {
        let AgentMessage::ToolCallRequest {
            capability_token,
            approval_tokens,
            ..
        } = &mut self.message
        else {
            return Err("tool request missing".into());
        };
        let approver = Keypair::generate();
        approval_tokens.push(GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: "conflicting-approval".into(),
                approver: approver.public_key(),
                subject: capability_token.subject.clone(),
                governed_intent_hash: chio_core::sha256_hex(b"intent"),
                request_id: "failure-receipt-request".into(),
                threshold_proposal_hash: None,
                issued_at: 1000,
                expires_at: 2000,
                decision: GovernedApprovalDecision::Approved,
            },
            &approver,
        )?);
        assert!(self.message.authorization_conflict().is_some());
        Ok(())
    }

    fn assert_authority(&self, receipt: &ChioReceipt) -> TestResult {
        assert_eq!(receipt.kernel_key, self.kernel.receipt_signing_public_key());
        assert_eq!(
            receipt.policy_hash,
            chio_core::sha256_hex(b"test-runtime-policy")
        );
        assert!(receipt.verify_signature()?);
        assert!(receipt.action.verify_hash()?);
        Ok(())
    }

    fn assert_recorded(&self, receipt: &ChioReceipt) -> TestResult {
        let receipts = self.kernel.receipt_log().receipts();
        let recorded = receipts
            .iter()
            .find(|candidate| candidate.id == receipt.id)
            .ok_or("response receipt omitted from kernel log")?;
        assert_eq!(
            chio_core::canonical_json_bytes(receipt)?,
            chio_core::canonical_json_bytes(recorded)?
        );
        Ok(())
    }

    fn assert_durable_after_shutdown(self, receipts: &[ChioReceipt]) -> TestResult {
        use chio_kernel::ReceiptStore;
        drop(self.kernel);
        let reopened = chio_store_sqlite::SqliteReceiptStore::open_existing(&self.receipt_db_path)?;
        for receipt in receipts {
            let recorded = reopened
                .load_chio_receipt(&receipt.id)?
                .ok_or("durable receipt missing after reopen")?;
            assert_eq!(
                chio_core::canonical_json_bytes(receipt)?,
                chio_core::canonical_json_bytes(&recorded)?
            );
            assert!(recorded.verify_signature()?);
        }
        Ok(())
    }
}

#[test]
fn conflict_receipt_uses_kernel_authority_and_policy() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.conflict()?;
    let (result, receipt) = fixture.send()?;
    assert!(matches!(
        result,
        ToolCallResult::Err {
            error: ToolCallError::PolicyDenied { .. }
        }
    ));
    fixture.assert_authority(&receipt)
}

#[test]
fn conflict_receipt_is_recorded_before_response() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.conflict()?;
    let (_, receipt) = fixture.send()?;
    fixture.assert_recorded(&receipt)
}

#[test]
fn evaluator_failure_receipt_uses_kernel_authority() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.complete()?;
    let (_, receipt) = fixture.send()?;
    fixture.assert_authority(&receipt)
}

#[test]
fn evaluator_failure_is_observation_not_execution_decision() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.complete()?;
    let (result, receipt) = fixture.send()?;
    assert!(matches!(
        result,
        ToolCallResult::Err {
            error: ToolCallError::InternalError(_)
        }
    ));
    assert_eq!(receipt.receipt_kind, ReceiptKind::TraceObservation);
    assert_eq!(receipt.boundary_class, BoundaryClass::DetectOnly);
    assert_eq!(
        receipt.observation_outcome,
        Some(ObservationOutcome::Observed)
    );
    assert!(receipt.decision.is_none());
    assert!(!receipt.is_allowed());
    assert!(receipt.financial_budget_authority_metadata().is_none());
    assert_eq!(fixture.stats.allowed, 1);
    assert_eq!(fixture.stats.denied, 0);
    assert_eq!(fixture.stats.evaluation_errors, 1);
    Ok(())
}

#[test]
fn evaluator_failure_observation_is_recorded_before_response() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.complete()?;
    let (_, receipt) = fixture.send()?;
    fixture.assert_recorded(&receipt)
}

#[test]
fn successful_stdio_receipt_remains_kernel_owned() -> TestResult {
    let mut fixture = Fixture::new()?;
    let receipt = fixture.complete()?;
    fixture.assert_authority(&receipt)?;
    fixture.assert_recorded(&receipt)
}

#[test]
fn evaluator_failure_preserves_original_completed_lineage() -> TestResult {
    let mut fixture = Fixture::new()?;
    let original = fixture.complete()?;
    let request_id = RequestId::new("failure-receipt-request");
    let before = fixture
        .kernel
        .session(&fixture.session_id)
        .ok_or("session missing")?
        .request_lineage(&request_id)
        .ok_or("lineage missing")?;
    fixture.send()?;
    let after = fixture
        .kernel
        .session(&fixture.session_id)
        .ok_or("session missing")?
        .request_lineage(&request_id)
        .ok_or("lineage missing")?;
    assert_eq!(before, after);
    fixture.assert_recorded(&original)
}

#[test]
fn conflict_receipt_survives_real_store_shutdown_and_reopen() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.conflict()?;
    let (result, receipt) = fixture.send()?;
    let ToolCallResult::Err {
        error: ToolCallError::PolicyDenied { guard, reason },
    } = result
    else {
        return Err("conflict denial missing".into());
    };
    assert!(
        matches!(receipt.decision.as_ref(), Some(chio_core::receipt::decision::Decision::Deny {
        guard: signed_guard, reason: signed_reason,
    }) if signed_guard == &guard && signed_reason == &reason)
    );
    fixture.assert_durable_after_shutdown(&[receipt])
}

#[test]
fn completed_and_failure_receipts_survive_real_store_shutdown_and_reopen() -> TestResult {
    let mut fixture = Fixture::new()?;
    let completed = fixture.complete()?;
    let (_, observation) = fixture.send()?;
    fixture.assert_durable_after_shutdown(&[completed, observation])
}

struct RefusingReportStore;

impl chio_kernel::ReceiptStore for RefusingReportStore {
    fn append_chio_receipt(&self, _: &ChioReceipt) -> Result<(), chio_kernel::ReceiptStoreError> {
        Err(chio_kernel::ReceiptStoreError::Conflict(
            "test report store unavailable".into(),
        ))
    }
    fn append_child_receipt(
        &self,
        _: &chio_core::receipt::lineage::ChildRequestReceipt,
    ) -> Result<(), chio_kernel::ReceiptStoreError> {
        Ok(())
    }
}

#[test]
fn failed_report_persistence_drops_response_without_substitute_receipt() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.complete()?;
    fixture
        .kernel
        .set_receipt_store(Box::new(RefusingReportStore))?;
    let before = fixture.kernel.receipt_log().receipts().len();
    let response = handle_agent_message(
        &mut fixture.kernel,
        &fixture.message,
        &fixture.session_id,
        &fixture.agent_id,
        &mut fixture.stats,
    );
    assert!(response.is_empty());
    assert_eq!(fixture.kernel.receipt_log().receipts().len(), before);
    Ok(())
}
