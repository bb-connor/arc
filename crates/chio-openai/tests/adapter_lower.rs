#![cfg(feature = "provider-adapter")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

use chio_core::canonical::canonical_json_bytes;
use chio_openai::adapter::OpenAiAdapter;
use chio_tool_call_fabric::{
    DenyReason, ProviderAdapter, ProviderError, ReceiptId, ToolResult, VerdictResult,
};
use serde_json::{json, Value};

struct NoopWaker;

impl Wake for NoopWaker {
    fn wake(self: Arc<Self>) {}
}

fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::from(Arc::new(NoopWaker));
    let mut cx = Context::from_waker(&waker);
    let mut future = Box::pin(future);

    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn tool_result(value: Value) -> ToolResult {
    ToolResult(canonical_json_bytes(&value).unwrap())
}

fn response_json(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap()
}

#[test]
fn lower_allow_batch_into_openai_tool_outputs() {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let result = tool_result(json!([
        {
            "call_id": "call_weather_1",
            "output": {
                "forecast": "sunny",
                "temperature_c": 21
            }
        },
        {
            "tool_call_id": "call_search_1",
            "output": "top result"
        }
    ]));
    let verdict = VerdictResult::Allow {
        redactions: vec![],
        receipt_id: ReceiptId("rcpt_allow_1".to_string()),
    };

    let response = block_on(adapter.lower(verdict, result)).unwrap();
    let payload = response_json(&response.0);
    let outputs = payload["tool_outputs"].as_array().unwrap();

    assert_eq!(outputs.len(), 2);
    assert_eq!(outputs[0]["type"], "function_call_output");
    assert_eq!(outputs[0]["call_id"], "call_weather_1");
    assert_eq!(
        outputs[0]["output"],
        "{\"forecast\":\"sunny\",\"temperature_c\":21}"
    );
    assert_eq!(outputs[1]["type"], "function_call_output");
    assert_eq!(outputs[1]["call_id"], "call_search_1");
    assert_eq!(outputs[1]["output"], "top result");
}

#[test]
fn lower_deny_emits_synthetic_tool_output_with_reason() {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let result = tool_result(json!({
        "call_id": "call_sensitive_1"
    }));
    let verdict = VerdictResult::Deny {
        reason: DenyReason::PolicyDeny {
            rule_id: "deny_pii".to_string(),
        },
        receipt_id: ReceiptId("rcpt_deny_1".to_string()),
    };

    let response = block_on(adapter.lower(verdict, result)).unwrap();
    let payload = response_json(&response.0);
    let outputs = payload["tool_outputs"].as_array().unwrap();
    let deny_payload: Value = serde_json::from_str(outputs[0]["output"].as_str().unwrap()).unwrap();

    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0]["type"], "function_call_output");
    assert_eq!(outputs[0]["call_id"], "call_sensitive_1");
    assert_eq!(deny_payload["verdict"], "deny");
    assert_eq!(deny_payload["synthetic"], true);
    assert_eq!(deny_payload["error"], "chio_denied_tool_call");
    assert_eq!(deny_payload["receipt_id"], "rcpt_deny_1");
    assert_eq!(deny_payload["reason"]["kind"], "policy_deny");
    assert_eq!(deny_payload["reason"]["rule_id"], "deny_pii");
}

#[test]
fn lower_fails_closed_when_call_id_is_missing() {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let result = tool_result(json!({
        "output": "orphaned result"
    }));
    let verdict = VerdictResult::Allow {
        redactions: vec![],
        receipt_id: ReceiptId("rcpt_allow_1".to_string()),
    };

    let err = match block_on(adapter.lower(verdict, result)) {
        Ok(_) => panic!("missing call_id must fail"),
        Err(err) => err,
    };

    assert!(matches!(err, ProviderError::Malformed(_)));
    assert!(err.to_string().contains("missing non-empty call_id"));
}

#[test]
fn lower_fails_closed_when_allow_output_is_missing() {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let result = tool_result(json!({
        "call_id": "call_empty_1"
    }));
    let verdict = VerdictResult::Allow {
        redactions: vec![],
        receipt_id: ReceiptId("rcpt_allow_1".to_string()),
    };

    let err = match block_on(adapter.lower(verdict, result)) {
        Ok(_) => panic!("missing output must fail"),
        Err(err) => err,
    };

    assert!(matches!(err, ProviderError::Malformed(_)));
    assert!(err.to_string().contains("missing output for allow verdict"));
}
