mod support;

use std::sync::Arc;

use chio_anthropic_tools_adapter::transport::MockTransport;
#[cfg(feature = "computer-use")]
use chio_anthropic_tools_adapter::{AnthropicAdapter, AnthropicAdapterConfig};
use chio_manifest::ServerTool;
use chio_tool_call_fabric::{
    ProviderError, ProviderRequest, ToolInvocation, ToolInvocationValidationError,
};
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[cfg(feature = "computer-use")]
fn config() -> AnthropicAdapterConfig {
    AnthropicAdapterConfig::new(
        "anthropic-1",
        "Anthropic Messages",
        "0.1.0",
        "deadbeef",
        "wks_test",
    )
}

fn tool_use_payload(name: &str) -> Result<ProviderRequest, serde_json::Error> {
    let payload = json!({
        "type": "message",
        "id": "msg_01",
        "role": "assistant",
        "content": [{
            "type": "tool_use",
            "id": "toolu_01",
            "name": name,
            "input": {"command": "pwd"}
        }]
    });
    serde_json::to_vec(&payload).map(ProviderRequest)
}

#[test]
#[cfg(not(feature = "computer-use"))]
fn server_tools_fail_closed_without_computer_use_feature() -> TestResult {
    let adapter = support::adapter_with_manifest_options(
        Arc::new(MockTransport::new()),
        vec![ServerTool::Bash],
        None,
    );
    let result = adapter.lift_batch(tool_use_payload("bash_20241022")?);

    assert!(matches!(
        result,
        Err(ProviderError::Malformed(message))
            if message.contains("requires the `computer-use` cargo feature")
    ));
    Ok(())
}

#[test]
#[cfg(not(feature = "computer-use"))]
fn date_suffixed_server_tools_need_computer_use_feature() -> TestResult {
    let adapter = support::adapter_with_manifest_options(
        Arc::new(MockTransport::new()),
        vec![ServerTool::Bash],
        None,
    );
    let result = adapter.lift_batch(tool_use_payload("bash_20250124")?);

    assert!(matches!(
        result,
        Err(ProviderError::Malformed(message))
            if message.contains("requires the `computer-use` cargo feature")
    ));
    Ok(())
}

#[test]
#[cfg(feature = "computer-use")]
fn server_tools_fail_closed_without_manifest_allowlist() -> TestResult {
    let adapter = AnthropicAdapter::new(config(), Arc::new(MockTransport::new()));
    let result = adapter.lift_batch(tool_use_payload("bash_20241022")?);

    assert!(matches!(
        result,
        Err(ProviderError::Malformed(message))
            if message.contains("manifest server_tools does not allow")
    ));
    Ok(())
}

#[test]
#[cfg(feature = "computer-use")]
fn server_tools_manifest_allowlist_allows_matching_tool() -> TestResult {
    let adapter = support::adapter_with_manifest_options(
        Arc::new(MockTransport::new()),
        vec![ServerTool::Bash],
        None,
    );
    let invocations = adapter.lift_batch(tool_use_payload("bash_20241022")?)?;

    assert_eq!(invocations.len(), 1);
    assert_eq!(invocations[0].tool_name, "bash_20241022");
    Ok(())
}

#[test]
#[cfg(feature = "computer-use")]
fn server_tools_manifest_allows_date_suffixed_family() -> TestResult {
    let adapter = support::adapter_with_manifest_options(
        Arc::new(MockTransport::new()),
        vec![ServerTool::Bash],
        None,
    );
    let invocations = adapter.lift_batch(tool_use_payload("bash_20250124")?)?;

    assert_eq!(invocations.len(), 1);
    assert_eq!(invocations[0].tool_name, "bash_20250124");
    Ok(())
}

#[test]
#[cfg(feature = "computer-use")]
fn server_tools_manifest_allowlist_denies_unlisted_peer() -> TestResult {
    let adapter = support::adapter_with_manifest_options(
        Arc::new(MockTransport::new()),
        vec![ServerTool::TextEditor],
        None,
    );
    let result = adapter.lift_batch(tool_use_payload("bash_20241022")?);

    assert!(matches!(
        result,
        Err(ProviderError::Malformed(message))
            if message.contains("`bash_20241022`") && message.contains("`bash`")
    ));
    Ok(())
}

#[test]
fn server_tools_gate_ignores_regular_custom_tools() -> TestResult {
    let adapter = support::adapter(Arc::new(MockTransport::new()));
    let invocations = adapter.lift_batch(tool_use_payload("regular_tool")?)?;

    assert_eq!(invocations.len(), 1);
    assert_eq!(invocations[0].tool_name, "regular_tool");
    invocations[0].validate()?;
    Ok(())
}

fn nontrivial_registry_flow() -> Result<chio_manifest::ToolFlowDeclaration, serde_json::Error> {
    serde_json::from_value(json!({
        "output_label": {
            "kind": "known",
            "owners": {},
            "compartments": ["audit", "pii"]
        },
        "input_clearance": {
            "kind": "known",
            "owners": {},
            "compartments": ["customer", "restricted"]
        },
        "egress": true,
        "declassification_purposes": ["audit", "support"]
    }))
}

#[test]
fn registry_admitted_flow_survives_anthropic_invocation_round_trip_canonically() -> TestResult {
    let expected_flow = nontrivial_registry_flow()?;
    let adapter = support::adapter_with_manifest_options(
        Arc::new(MockTransport::new()),
        vec![
            ServerTool::ComputerUse,
            ServerTool::Bash,
            ServerTool::TextEditor,
        ],
        Some(expected_flow.clone()),
    );
    let invocation = adapter
        .lift_batch(tool_use_payload("regular_tool")?)?
        .into_iter()
        .next()
        .ok_or_else(|| std::io::Error::other("Anthropic lift returned no invocation"))?;
    let admitted_flow = invocation
        .bridge_security
        .as_ref()
        .and_then(chio_manifest::BridgeSecurityMetadata::flow)
        .ok_or_else(|| std::io::Error::other("Anthropic invocation dropped admitted flow"))?;
    let expected_flow_bytes = chio_core::canonical_json_bytes(&expected_flow)?;

    assert_eq!(
        chio_core::canonical_json_bytes(admitted_flow)?,
        expected_flow_bytes
    );
    assert!(invocation
        .bridge_security
        .as_ref()
        .is_some_and(chio_manifest::BridgeSecurityMetadata::effective_egress));

    let invocation_bytes = chio_core::canonical_json_bytes(&invocation)?;
    let round_trip: ToolInvocation = serde_json::from_slice(&invocation_bytes)?;
    let round_trip_flow = round_trip
        .bridge_security
        .as_ref()
        .and_then(chio_manifest::BridgeSecurityMetadata::flow)
        .ok_or_else(|| {
            std::io::Error::other("Anthropic invocation round trip dropped admitted flow")
        })?;
    assert_eq!(
        chio_core::canonical_json_bytes(round_trip_flow)?,
        expected_flow_bytes
    );
    round_trip.validate()?;

    let mut mismatched = round_trip;
    mismatched.tool_name = "different-tool".to_string();
    assert!(matches!(
        mismatched.validate(),
        Err(ToolInvocationValidationError::BridgeToolMismatch {
            invocation,
            admitted
        }) if invocation == "different-tool" && admitted == "regular_tool"
    ));
    Ok(())
}
