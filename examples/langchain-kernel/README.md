# Run LangChain tools through the Chio kernel

Keep your agent in LangChain. Let Chio execute its tools, enforce invocation
limits, and return signed evidence that Python verifies before exposing output.

This example starts a real MCP journal server behind `chio mcp serve` and invokes
it through LangChain `BaseTool` objects. It makes two writes and verifies that the
third call is denied before the journal changes. It needs Python 3.11+, Rust, and
[uv](https://docs.astral.sh/uv/). It runs locally without a model API key; the three
tool requests are prescribed so the acceptance check is repeatable.

## Run from this checkout

```bash
./scripts/check-langchain-kernel.sh
```

The script builds Chio, installs the locked Python dependencies from this checkout,
and runs the example. Expect:

```json
{"effects": 2, "verified_receipts": 3, "denied_before_effect": true}
```

Keep the signed receipts and actual journal in a new private directory:

```bash
./scripts/check-langchain-kernel.sh --state-dir /tmp/my-chio-run
```

The directory must not already exist. `evidence.json` contains the receipts and
journal entries. `receipts.sqlite` stores the kernel receipt log; `session.sqlite`
stores durable admission, revocation, and budget state. Keep the directory private:
it includes the kernel signing seed and full tool arguments and outputs. This is
local acceptance evidence, not an independently witnessed transparency checkpoint.

To use an already built binary, set `CHIO_BIN` to its absolute path. The binary
must include the MCP receipt export and policy invocation limit in this change.
These Python APIs are prepared for version 0.2.0; this example uses source packages
and does not require an unpublished version to exist on PyPI.

## Use your own agent and tools

Wrap your existing MCP server with `chio mcp serve`. With its MCP session open:

```python
from chio_langchain.mcp import ChioMcpToolkit

toolkit = ChioMcpToolkit(
    session,
    server_id="journal",
    trusted_signers=[operator_pinned_kernel_public_key],
)
tools = await toolkit.get_tools()
# Give tools to your async LangChain agent or LangGraph ToolNode.
```

The MCP session lifetime must include the complete agent run. The operator pins
the kernel public key through a trusted channel. This local example reads it from
the private state directory of the kernel process it launched. Never trust a key
merely because it arrived inside a tool response.

A successful LangChain ToolCall yields a `ToolMessage` whose `artifact` contains
`receipt` and the exact committed `output`. Plain argument-dictionary invocation
returns the output as JSON text. `ChioMcpToolError`, a LangChain `ToolException`,
carries the verified receipt and output for a denial or tool failure. An agent can
handle that normal tool error and choose different work. Integrity failures raise
`McpReceiptError` and must stop the run; transport failures propagate without an
automatic retry because the effect may already have occurred.

The journal server owns the output path, outside model arguments. The kernel owns
the two-invocation allowance. `max_invocations` applies to the issued capability's
tool grant. It is not a lifetime limit on a tool server: starting a new session can
issue a fresh grant. Configure agent issuance separately for an aggregate budget.

## Scope of the guarantee

The client validates the pinned signer, receipt integrity, mediated decision,
server and tool identity, a fresh request ID, exact arguments, and the output hash.
It returns the committed output, ignoring separately rendered MCP display content.
It rejects missing receipts, unsupported commitments, and altered evidence.

Chio mediates this MCP route. This example does not provide an OS sandbox or block
a process with direct filesystem access from writing elsewhere. A signed receipt
attests the kernel's decision and observed tool output; it does not independently
prove that an arbitrary tool told the truth about its external effect. The check
also reads the real journal to establish this example's two writes.
