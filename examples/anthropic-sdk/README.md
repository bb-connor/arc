# Anthropic SDK Example

This example shows how to expose ARC-governed tools to Claude through the
Anthropic SDK while the hosted session itself is managed by
`@arc-protocol/sdk`.

## What it does

- initializes a hosted ARC session through `@arc-protocol/sdk`
- lists tools from the hosted edge and maps them into Anthropic tool
  definitions
- routes `tool_use` requests back through ARC's typed client
- resolves the resulting receipt through the trust service query API

## Prerequisites

- Node.js 22+
- the phase `309` demo stack running locally, or equivalent direct
  `arc trust serve` plus `arc mcp serve-http` processes
- optional: `ANTHROPIC_API_KEY` for a live Claude call

## Install

From this directory:

```bash
npm --prefix ../../packages/sdk/arc-ts ci
npm --prefix ../../packages/sdk/arc-ts run build
npm install
```

## Offline verification

The script defaults to the Docker quickstart endpoints:

- `ARC_BASE_URL=http://127.0.0.1:8931`
- `ARC_CONTROL_URL=http://127.0.0.1:8940`
- `ARC_AUTH_TOKEN=demo-token`

`--dry-run` exercises the ARC SDK path only. It initializes the hosted session,
lists tools, performs a governed `echo_text` call, and resolves the resulting
receipt.

```bash
node run.mjs --dry-run
```

## Live Claude run

```bash
ANTHROPIC_API_KEY=... node run.mjs "Use the echo_text tool to say hello from Claude."
```

Optional environment variables:

- `ANTHROPIC_MODEL`: defaults to `claude-sonnet-4-20250514`
- `ARC_BASE_URL`: hosted edge base URL
- `ARC_CONTROL_URL`: trust service base URL
- `ARC_AUTH_TOKEN`: bearer token accepted by both services

See also:

- [docs/PROGRESSIVE_TUTORIAL.md](/Users/connor/Medica/backbay/standalone/arc/docs/PROGRESSIVE_TUTORIAL.md)
- [examples/docker/README.md](/Users/connor/Medica/backbay/standalone/arc/examples/docker/README.md)
