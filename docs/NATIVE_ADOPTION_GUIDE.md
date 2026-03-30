# Native Adoption Guide

This guide closes the gap between the current wrapped-MCP path and the first supported native ARC authoring path.

## Canonical policy path

For new policy authoring, use HushSpec.

- `examples/policies/canonical-hushspec.yaml` is the recommended starting point.
- `examples/policies/hushspec-guard-heavy.yaml` exercises the full shipped guard surface.
- the legacy PACT YAML format remains supported as a compatibility input for existing operators and tests, but it is no longer the recommended authoring path for new work

Both inputs compile into the same runtime policy materialization inside `arc-cli`. The difference is product guidance, not an execution split.

## Migration path: wrapped MCP to native ARC

1. Keep the same policy intent, but move policy authoring to HushSpec.
2. Start from the wrapped path you already have with `arc mcp serve` or `arc mcp serve-http`.
3. Replace the wrapped subprocess with a native service built through `NativeArcServiceBuilder`.
4. Register that native service with the kernel and expose it through the same edge surface you already use.

That lets a team migrate one server at a time without changing the trust, receipt, or guard model around it.

## Minimal native authoring surface

`arc-mcp-adapter` now ships a small higher-level native service builder:

- `NativeArcServiceBuilder`
- `NativeTool`
- `NativeResource`
- `NativePrompt`

The builder creates one service value that:

- emits a valid ARC manifest
- implements `ToolServerConnection`
- implements `ResourceProvider`
- implements `PromptProvider`
- can emit late `ToolServerEvent`s through an internal queue

Advanced users can still drop to the lower-level kernel traits directly for custom streaming, resource templates, or transport-specific behavior.

## Example

The maintained example is [examples/hello-tool](/Users/connor/Medica/backbay/standalone/arc/examples/hello-tool), which now uses `NativeArcServiceBuilder` instead of hand-assembling only a manifest.

The flow is:

1. generate a server keypair
2. build the service with a tool, resource, and prompt
3. sign the generated manifest
4. invoke the service through the normal trait surface

## What this does not solve yet

- resource-template authoring ergonomics are still lower-level
- completion helpers are still lower-level
- transport bootstrapping is still a separate concern from service authoring

That is deliberate. The first native surface is meant to make common service authoring coherent, not hide every runtime primitive.
