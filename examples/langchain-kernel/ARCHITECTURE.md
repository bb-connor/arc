# LangChain kernel integration architecture

## Process boundary

`run.py` owns the official Python MCP client session and obtains LangChain tools
from `ChioMcpToolkit`. The client launches the Chio CLI as a separate process. Chio
wraps `tools.py`, a real MCP server, using the existing MCP adapter and kernel
execution path. The journal destination is chosen by the operator and is never a
model-controlled tool argument. No local callback performs the write after an
advisory policy check. The three requests are prescribed acceptance inputs; this
example does not invoke a language model or measure its planning quality.

## Authority and evidence

The policy issues a short-lived tool grant permitting two invocations. Durable
admission owns budget reservation and terminal receipt persistence. The edge
exports the actual signed receipt with the exact output value used to calculate
its content hash. The Python verifier pins the kernel signer using a key obtained
from the operator-owned state directory. It binds the receipt to a fresh request
identifier, tool, server, arguments, and complete output before returning a value.
LangChain ToolMessage artifacts carry successful evidence; typed tool exceptions
carry denied or failed call evidence without shared mutable receipt state.

The trust boundary covers invocation through this MCP connection. It does not
isolate a malicious process from the operating system, validate arbitrary remote
side effects independently, or establish external adoption. Receipt data can
contain sensitive arguments and outputs, so retained local state is private.

## Verification

`scripts/check-langchain-kernel.sh` builds the real CLI and runs the example using
locked Python dependencies. Acceptance requires exactly two journal entries,
three verified receipts, and an allow, allow, deny sequence. Python unit tests
cover altered signatures and output, replayed request identities, wrong tools,
concurrent calls, bounded discovery, and transport failure without effect retry.
Rust tests exercise exported receipts on direct, stdio, and channel MCP paths and
verify that YAML invocation limits reach runtime capability grants.
