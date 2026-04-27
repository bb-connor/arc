# chio-anthropic-tools-adapter

Provider-native adapter that mediates Anthropic Messages API tool-use
traffic through the Chio kernel. Implements the
[`chio-tool-call-fabric`](../chio-tool-call-fabric/) `ProviderAdapter`
trait so a single Chio policy file enforces uniformly across OpenAI
Responses, Anthropic Messages, and Bedrock Converse.

## Pinned upstream API

- `anthropic-version: 2023-06-01` (verbatim header value).
- Exposed in code as `chio_anthropic_tools_adapter::transport::ANTHROPIC_VERSION`.
- Recorded in `Cargo.toml` under `[package.metadata.chio]`.

Bumping the pin is a deliberate PR with a fixture re-record; CI never
auto-bumps. See `.planning/trajectory/07-provider-native-adapters.md`,
"Pinned upstream API versions" section.

## Cargo features

| Feature        | Default | Effect                                                                                                     |
| -------------- | ------- | ---------------------------------------------------------------------------------------------------------- |
| `computer-use` | off     | Compiles the Anthropic server-tool variants (`computer_use_20241022`, `bash_20241022`, `text_editor_20241022`) and lets the transport stamp `anthropic-beta: computer-use-2025-01-24` on outgoing requests. |

The `computer-use` feature alone is not sufficient to enable the
server-tool surface at runtime. M07.P3.T4 adds a `chio-manifest`
`server_tools: [...]` allowlist that the adapter consults at lift time.
Default deny applies even with the feature on.

## M07.P3 ticket sequence

| Ticket | Deliverable                                                                  | Status |
| ------ | ---------------------------------------------------------------------------- | ------ |
| T1     | Crate scaffold, API pin, `computer-use` feature, native types, transport trait | this PR |
| T2     | `ProviderAdapter::lift`/`lower` for batch `messages.create` tool_use blocks  | pending |
| T3     | SSE streaming with verdict at `content_block_start` for `tool_use`           | pending |
| T4     | `chio-manifest` `server_tools` allowlist gating the beta surface             | pending |
| T5     | 12 conformance fixtures (incl. 2 server-tool sessions behind the feature)    | pending |
| T6     | Native-error envelope -> `ProviderError` taxonomy doctest                    | pending |

## Crate layout

```text
crates/chio-anthropic-tools-adapter/
  Cargo.toml         pin metadata, computer-use feature, workspace lints
  README.md          this file
  src/
    lib.rs           AnthropicAdapter, AnthropicAdapterConfig, error type
    transport.rs     Transport trait, MockTransport, ANTHROPIC_VERSION pin
    native.rs        ToolUseBlock, ToolResultBlock, server-tool variants
```

T2 will add `src/adapter.rs` (batch `lift`/`lower`); T3 will add
`src/streaming.rs` (SSE state-machine wiring on top of
`chio-tool-call-fabric::stream`); T4 will add `src/server_tools.rs`
(allowlist enforcement).

## Building

```bash
cargo build -p chio-anthropic-tools-adapter
cargo build -p chio-anthropic-tools-adapter --features computer-use
```

Both invocations must succeed for T1 to merge (gate-check defined in
`.planning/trajectory/tickets/M07/P3.yml`).

## House rules

- No em dashes (U+2014) anywhere in code, comments, or documentation.
- Workspace clippy lints `unwrap_used = "deny"` and `expect_used = "deny"`
  apply; no exceptions.
- Fail-closed: server-tool requests without the `computer-use` feature
  surface a structured error rather than silently downgrading.

## References

- Trajectory doc: `.planning/trajectory/07-provider-native-adapters.md`
  Phase 3 (lines 393-420).
- Ticket spec: `.planning/trajectory/tickets/M07/P3.yml` (T1).
- Fabric trait surface: `crates/chio-tool-call-fabric/src/lib.rs`.
- Conformance harness skeleton: `crates/chio-provider-conformance/`
  (lands in M07.P2).
