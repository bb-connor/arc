use super::*;

#[test]
fn jsonrpc_tool_call_cannot_omit_required_swarm_context() -> Result<(), Box<dyn std::error::Error>>
{
    let mut edge = make_edge_with_config(10, false);
    edge.kernel.require_swarm_admission();
    initialize_edge(&mut edge);
    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": { "name": "read_file", "arguments": { "path": "/tmp/demo.txt" } }
        }))
        .ok_or_else(|| std::io::Error::other("missing JSON-RPC response"))?;
    assert_eq!(response["result"]["isError"], true, "{response}");
    let log = edge.kernel.receipt_log();
    let receipts = log.receipts();
    let receipt = receipts
        .last()
        .ok_or_else(|| std::io::Error::other("missing denial receipt"))?;
    assert!(receipt.verify_signature()?);
    let metadata = receipt
        .metadata
        .as_ref()
        .ok_or_else(|| std::io::Error::other("missing denial metadata"))?;
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "missing_chio_swarm_context"
    );
    Ok(())
}
