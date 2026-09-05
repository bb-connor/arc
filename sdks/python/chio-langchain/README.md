# chio-langchain

Execute LangChain tools through the Chio Rust kernel and verify the signed
receipt before returning output to the agent.

## Kernel-mediated MCP tools

The 0.2.0 source package adds `chio-langchain[mcp]`. Run the complete local
[LangChain kernel example](../../../examples/langchain-kernel/README.md) from this
checkout to build the CLI and install the matching Python packages. The example
performs two real writes, then checks that Chio denies the third invocation.

With an initialized MCP session connected to Chio:

```python
from chio_langchain.mcp import ChioMcpToolkit

toolkit = ChioMcpToolkit(
    session,
    server_id="journal",
    trusted_signers=[operator_pinned_kernel_public_key],
)
tools = await toolkit.get_tools()
# Supply these tools to your async LangChain agent or LangGraph ToolNode.
```

Keep the session open throughout the agent run. Tool input schemas are preserved,
including nested JSON Schema constraints. The Python client checks the pinned
signer, receipt integrity, mediation, fresh request identity, tool, arguments,
and exact output commitment. It returns only the verified output. The operator
must obtain the signing key through a trusted channel, separate from tool output.

Successful ToolCall invocations return a LangChain ToolMessage with a
`{receipt, output}` artifact. Invoking with a plain argument dictionary returns
JSON text. A verified denial or tool failure raises `ChioMcpToolError`, a
`ToolException` with invocation-local `receipt` and `output` attributes. You can
configure LangChain's ordinary tool-error handling to let the agent respond to a
denial. Missing or invalid evidence raises `McpReceiptError`; it is not converted
into normal tool output. Transport errors propagate without retries because an
effect may already have occurred.

This API requires async invocation, MCP Python 1.28 through 1.x, and LangChain core
0.3.86+ or 1.x. It accepts complete value results and rejects stream commitments. Tool
output and receipt artifacts may contain sensitive data. OS process isolation and
aggregate session issuance policy are the operator's responsibility.

## Legacy advisory API

```bash
uv pip install chio-langchain
# or
pip install chio-langchain
```

The package depends on `chio-sdk-python`, `chio-adapter-base`, and
`langchain-core`.

### Advisory example

Discover the tools associated with a capability and hand them to an agent:

```python
from chio_langchain import ChioToolkit


async def build_tools() -> list:
    toolkit = ChioToolkit(
        capability_id="cap-123",
        sidecar_url="http://127.0.0.1:9090",
    )
    # Fetch tool definitions from the sidecar and wrap them.
    return await toolkit.get_tools(server_id="search-srv")
```

Or construct a single tool when you already know its definition:

```python
tool = toolkit.create_tool(
    name="search_documents",
    description="Search the corpus",
    server_id="search-srv",
)
```

### Advisory tools

- `ChioToolkit` -- builds LangChain tools from Chio tool-server manifests.
  Use `get_tools(...)` to discover tools from the sidecar, or
  `create_tool(...)` to declare one explicitly.
- `ChioTool` -- a LangChain `BaseTool` whose invocation is evaluated through
  the sidecar for advisory audit and bound to a capability id.

### Advisory behavior

Tool calls fail closed for authorization: advisory evaluation never becomes a
successful execution authorization. `ChioTool` returns JSON error strings for
advisory denial, sidecar errors, and non-authorizing advisory observations
(for example `{"error": "non_authorizing", ...}`). Sensitive arguments are
redacted according to the toolkit's redaction policy (the Chio default unless
you override it).

## License

Apache-2.0
