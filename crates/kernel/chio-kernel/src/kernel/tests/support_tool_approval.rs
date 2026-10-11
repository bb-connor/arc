//! Explicit approval policy for monetary and dispatch fixture owners.
use super::*;
use chio_test_support::plain::TestResultOk;

pub(super) fn bind_test_tool_approval(
    kernel: &mut ChioKernel,
    capability: &CapabilityToken,
    arguments: &serde_json::Value,
    request_id: &str,
    intent: &mut GovernedTransactionIntent,
) {
    // These fixtures deliberately give their local signer the approver role.
    // General kernel construction must not infer that role from receipt trust.
    kernel
        .set_governed_approval_policy("dispatch-fixture-tenant".into(), vec![kernel.public_key()])
        .test_unwrap();
    crate::approval::ToolApprovalContext::bind(
        intent,
        capability,
        arguments,
        request_id,
        kernel.policy_hash(),
        "dispatch-fixture-tenant",
    )
    .test_unwrap();
}
