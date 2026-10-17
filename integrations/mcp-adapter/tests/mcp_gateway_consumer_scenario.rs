use chio_mcp_adapter_integration::{ProtectedResourceMetadata, StreamableHttpTransport};
use chio_mcp_edge::{McpToolInfo, McpToolResult, McpTransport};
use serde_json::json;

/// Replays a recorded gateway-consumer scenario over the in-memory
/// Streamable HTTP transport. No AWS service, signing, or receipt is involved.
#[test]
fn gateway_consumer_scenario_round_trips_over_in_memory_transport(
) -> Result<(), Box<dyn std::error::Error>> {
    let scenario: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/gateway_consumer/scenario.json"))?;
    assert_eq!(scenario["consumer"], "mcp-gateway-consumer");
    assert_eq!(scenario["oauth"]["grant_type"], "authorization_code_pkce");

    let metadata = ProtectedResourceMetadata::new(
        scenario["resource"].as_str().unwrap_or_default(),
        scenario["authorization_server"]
            .as_str()
            .unwrap_or_default(),
        vec!["tools.call".to_string(), "receipts.read".to_string()],
    )?;
    assert_eq!(metadata.bearer_methods_supported[0], "header");

    let transport = StreamableHttpTransport::builder()
        .bearer_token("gateway-consumer-token")
        .tool(
            McpToolInfo {
                name: "chio.bedrock.invoke".to_string(),
                title: Some("Invoke governed Bedrock".to_string()),
                description: Some("Gateway consumer scenario tool".to_string()),
                input_schema: json!({ "type": "object" }),
                output_schema: None,
                annotations: None,
                execution: None,
            },
            McpToolResult {
                content: vec![json!({ "type": "text", "text": "bedrock ok" })],
                structured_content: None,
                is_error: Some(false),
            },
        )
        .build()?;

    let result = transport.call_tool("chio.bedrock.invoke", json!({ "model": "bedrock" }))?;
    assert_eq!(result.is_error, Some(false));
    assert_eq!(transport.exchange_log()?.len(), 1);
    Ok(())
}
