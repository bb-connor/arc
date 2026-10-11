//! Trusted protocol observation path. No normal admission or tool dispatch.

use super::*;
use crate::ingress::HostProtocolRefusal;
use chio_core::receipt::body::ChioReceipt;
use chio_kernel::{KernelError, ProtocolRefusalReason, ProtocolRefusalSummary};

fn record_scoped_refusal(
    kernel: &ChioKernel,
    session_id: &SessionId,
    agent_id: &str,
    summary: &ProtocolRefusalSummary,
) -> Result<ChioReceipt, KernelError> {
    let context = OperationContext::new(
        session_id.clone(),
        RequestId::new(format!(
            "protocol-refusal:{}",
            summary.request_digest().sha256()
        )),
        agent_id.into(),
    );
    let result = kernel.record_session_protocol_refusal(&context, summary);
    let status = if result.is_ok() {
        "retained"
    } else {
        "unavailable"
    };
    if result.is_ok() {
        crate::metrics::record_receipt_write_verdict(Verdict::Deny);
    } else {
        crate::metrics::record_receipt_write(crate::metrics::RECEIPT_WRITE_OUTCOME_ERROR);
    }
    // Each field is a closed label or fixed-size hash. Client logging controls
    // cannot suppress this operator diagnostic or the receipt-write metric.
    eprintln!(
        "MCP protocol refusal reason={} request_sha256={} evidence={status}",
        summary.reason().as_str(),
        summary.request_digest().sha256()
    );
    result
}

pub(super) fn persist_host_refusal(
    kernel: &ChioKernel,
    context: &OperationContext,
    command: Box<HostProtocolRefusal>,
) {
    let result = record_scoped_refusal(
        kernel,
        &context.session_id,
        &context.agent_id,
        &command.summary,
    );
    let _ = command.acknowledgement.send(result);
    // The reservation remains live through persistence and acknowledgement.
    drop(command.reservation);
}

impl ChioMcpEdge {
    pub(super) fn handle_host_protocol_refusal(&self, command: Box<HostProtocolRefusal>) {
        let context = match &self.state {
            EdgeState::Ready { session_id } => OperationContext::new(
                session_id.clone(),
                RequestId::new("host-protocol-refusal"),
                self.agent_id.clone(),
            ),
            _ => {
                let _ = command.acknowledgement.send(Err(KernelError::Internal(
                    "MCP session is not ready for scoped refusal evidence".into(),
                )));
                return;
            }
        };
        persist_host_refusal(&self.kernel, &context, command);
    }

    pub(super) fn protocol_refusal_evidence(
        &self,
        session_id: &SessionId,
        method: &str,
        target: &str,
        reason: ProtocolRefusalReason,
    ) -> Value {
        let Some(digest) = self.active_protocol_request_digest.clone() else {
            crate::metrics::record_receipt_write(crate::metrics::RECEIPT_WRITE_OUTCOME_ERROR);
            eprintln!(
                "MCP protocol refusal evidence=unavailable reason={}",
                reason.as_str()
            );
            return json!({"status":"unavailable"});
        };
        let summary = ProtocolRefusalSummary::new(reason, method, Some(target), digest);
        match record_scoped_refusal(&self.kernel, session_id, &self.agent_id, &summary) {
            Ok(receipt) => json!({"status":"retained", "receiptId":receipt.id, "receipt":receipt}),
            Err(_) => json!({"status":"unavailable"}),
        }
    }
}

pub(super) fn attach_refusal_evidence(mut response: Value, evidence: Value) -> Value {
    if let Some(result) = response.get_mut("result").and_then(Value::as_object_mut) {
        let metadata = result.entry("_meta").or_insert_with(|| json!({}));
        metadata["chioProtocolRefusal"] = evidence;
    } else if let Some(error) = response.get_mut("error").and_then(Value::as_object_mut) {
        let data = error.entry("data").or_insert_with(|| json!({}));
        data["chioProtocolRefusal"] = evidence;
    }
    response
}
