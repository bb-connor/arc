use chio_mcp_adapter_integration::{
    pkce_challenge, ProtectedResourceMetadata, StreamableHttpTransport,
};
use chio_mcp_edge::{McpToolInfo, McpToolResult, McpTransport};
use serde_json::json;

#[test]
fn transport_lists_and_calls_tool_and_helpers_build() -> Result<(), Box<dyn std::error::Error>> {
    let transport = StreamableHttpTransport::builder()
        .bearer_token("contract-token")
        .tool(
            McpToolInfo {
                name: "chio.fixture.echo".to_string(),
                title: Some("Fixture echo".to_string()),
                description: Some("Echo tool for the contract test".to_string()),
                input_schema: json!({ "type": "object" }),
                output_schema: None,
                annotations: None,
                execution: Some(json!({ "transport": "streamable-http" })),
            },
            McpToolResult {
                content: vec![json!({ "type": "text", "text": "ok" })],
                structured_content: Some(json!({ "ok": true })),
                is_error: Some(false),
            },
        )
        .build()?;

    assert_eq!(transport.list_tools()?.len(), 1);
    let result = transport.call_tool("chio.fixture.echo", json!({ "ping": true }))?;
    assert_eq!(result.is_error, Some(false));

    let pkce = pkce_challenge("abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG")?;
    assert_eq!(pkce.method, "S256");
    let metadata = ProtectedResourceMetadata::new(
        "https://mcp.chio.example/mcp",
        "https://auth.chio.example",
        vec!["tools.call".to_string()],
    )?;
    assert_eq!(metadata.authorization_servers.len(), 1);
    Ok(())
}
