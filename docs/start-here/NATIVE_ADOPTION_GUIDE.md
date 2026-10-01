# Native Adoption Guide

Choose the Chio interface for the application you are building. The native
process host runs agent workers with persistent operation identities, scoped
tool authority and recoverable outcomes. Native Rust services implement the
tools those workers call. Existing MCP servers can also enter through the
MCP edge.

## Choose a starting point

| Application | Start here | What the example exercises |
| --- | --- | --- |
| Python and Node workers | [Process starter](../../examples/process-starter/README.md) | Install local SDK artifacts, run both worker languages, recover an interrupted mailbox handoff and verify original receipts. |
| A coding task against a Git commit | [Repository coding session](../../sdks/python/chio-mini-swe/SESSION.md) | Run mini-SWE-agent through the native host, preserve the source checkout, recover recorded model/tool outcomes and export a patch with verified receipts. |
| An existing AI SDK 6 or 7 application | [AI SDK process integration](../../sdks/typescript/packages/ai-sdk-process/README.md) | Keep the application's model loop while routing its tools through native processes; use the journaled agent loop when provider-response recovery is required. |
| A Rust tool, resource or prompt | [Native service authoring](#native-service-authoring) | Build and sign one service implementing the kernel's tool, resource and prompt traits. |
| An existing MCP server | [MCP migration](../guides/MIGRATING-FROM-MCP.md) | Wrap the server, apply a policy and check an allow, a deny and a signed receipt. |

The process starter and coding session are experimental, source-built Linux
development profiles. Their instructions identify the installed packages,
binary, images and execution boundary each profile requires. Their controlled
recovery qualifications do not establish a signed public release or live
coding quality. Use the [process direction and evidence](../architecture/AGENT_PROCESS_DIRECTION.md)
to assess the remaining operational and adoption work.

For a package-sized task in a larger repository, the coding session accepts
explicit committed `source_paths`. Only those paths enter the workspace, and
the recipient supplies the expected scope when verifying the exported patch.
The [repository execution contract](../../sdks/python/chio-mini-swe/REPOSITORY.md)
defines the size limits, container boundary and scope checks.

## Native service authoring

Use `NativeChioServiceBuilder` when you are implementing a Rust service for
the kernel. A worker using an existing service can start from the application
profiles above without first writing a service or deploying an MCP wrapper.

## Canonical policy path

For new guard-policy authoring, use HushSpec.

- `examples/policies/canonical-hushspec.yaml` is the recommended starting point.
- `examples/policies/hushspec-guard-heavy.yaml` exercises the full shipped guard surface.

Host process configuration, tool grants and launch authorization have their
own contracts in the selected application profile. Follow that profile when
provisioning worker and tool-server authority.

## Migration path: wrapped MCP to native Chio

1. Keep the same policy intent, but move policy authoring to HushSpec.
2. Start from the wrapped path you already have with `chio mcp serve` or `chio mcp serve-http`.
3. Replace the wrapped subprocess with a native service built through `NativeChioServiceBuilder`.
4. Register that native service with the kernel and expose it through the same edge surface you already use.

That lets a team migrate one server at a time without changing the trust, receipt, or guard model around it.

## Minimal native authoring surface

`chio-mcp-adapter` now ships a small higher-level native service builder:

- `NativeChioServiceBuilder`
- `NativeTool`
- `NativeResource`
- `NativePrompt`

The builder creates one service value that:

- emits a valid Chio manifest
- implements `ToolServerConnection`
- implements `ResourceProvider`
- implements `PromptProvider`
- can emit late `ToolServerEvent`s through an internal queue

Advanced users can still drop to the lower-level kernel traits directly for custom streaming, resource templates, or transport-specific behavior.

When you expose a native service through a Chio edge, the runtime contract does
not change:

- stdio and hosted edges still require `initialize` followed by `notifications/initialized`
- hosted HTTP uses `POST /mcp` for requests and `GET /mcp` plus `Last-Event-ID` for live notification replay
- caller-supplied `_meta.modelMetadata` enters the runtime as asserted provenance unless a trusted subsystem upgrades it later

## Example

The maintained example is [examples/hello-tool](../../examples/hello-tool), which now uses `NativeChioServiceBuilder` instead of hand-assembling only a manifest.

The flow is:

1. generate a server keypair
2. build the service with a tool, resource, and prompt
3. sign the generated manifest
4. invoke the service through the normal trait surface

## Remaining service authoring work

- resource-template authoring ergonomics are still lower-level
- completion helpers are still lower-level
- transport bootstrapping is still a separate concern from service authoring

These are service authoring limits. The process runtime's deployment and
recovery boundaries are documented with its application profiles.
