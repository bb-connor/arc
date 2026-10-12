# chio-reference-tools

Three MCP stdio servers for the Chio cage reference runtime, plus a small
library for implementing the same line-delimited JSON-RPC tool interface.
The tools apply local path and byte limits; the cage and kernel supply process
isolation, capability evaluation, guards, and signed receipts.

| Binary | Arguments | Tool surface |
| --- | --- | --- |
| `chio-tool-repo-reader` | `--root <absolute directory>` | `list_directory`, `read_file`, `stat` |
| `chio-tool-artifact-writer` | `--artifact <absolute file>` | `write_file`, `read_file`, `stat` |
| `chio-tool-digest` | None | `sha256`, `canonical_json` |

## Usage

Serve a tool set over in-memory streams. `serve` also accepts locked stdin and
stdout for a real stdio server. This example performs no file or network I/O.

```rust
use chio_reference_tools::{serve, ToolDescriptor, ToolError, ToolOutput, ToolServer};
use serde_json::Value;

struct EmptyTools;
impl ToolServer for EmptyTools {
    fn name(&self) -> &str { "example" }
    fn version(&self) -> &str { "1" }
    fn tools(&self) -> Vec<ToolDescriptor> { Vec::new() }
    fn call(&mut self, name: &str, _: &Value) -> Result<ToolOutput, ToolError> {
        Err(ToolError::InvalidArguments(format!("unknown tool {name}")))
    }
}
let input = br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
let mut output = Vec::new();
serve(EmptyTools, &input[..], &mut output)?;
let response: Value = serde_json::from_slice(&output)?;
assert_eq!(response["result"], serde_json::json!({}));
# Ok::<(), Box<dyn std::error::Error>>(())
```

This package declares no Cargo features. A caged launch needs read grants for
the repository root or read/write grants for the artifact, as appropriate.
Static targets need no declared runtime files; dynamic targets need their
interpreter and shared objects included in the launch policy.

## Guarantees

`serve` bounds request lines to `MAX_LINE_BYTES` (4 MiB), drains oversized
frames, and resumes at the next line. `handle` dispatches initialize, ping,
tool listing, and calls; notifications produce no reply. Argument errors use
JSON-RPC invalid params, while refused/failed operations use `isError` results.

`RepoReader::resolve` checks plain relative paths and canonical containment.
Reads allow 64 distinct files, 4 MiB per session, and 256 KiB per call.
`ArtifactWriter::require_artifact_path` requires the configured spelling;
startup requires an existing regular file, and writes replace its content.
The digest server caps text/canonical output at 1 MiB and canonicalizes JSON
through `chio_core_types::canonical_json_string` before hashing.

## Status

Implemented reference tools with publication disabled. Local tests spawn the
binaries directly and check protocol behavior and path/size refusal.
Filesystem checks precede separate opens; host enforcement and runtime
qualification establish the surrounding cage boundary. Directory enumeration
also needs a syscall profile permitting `getdents64`.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol MCP surface](../../../spec/PROTOCOL.md#82-mcp-compatibility)
- [Process runtime](../../kernel/chio-process/README.md)
- [Conformance tooling](../chio-conformance/README.md)

Licensed under [Apache-2.0](../../../LICENSE).
