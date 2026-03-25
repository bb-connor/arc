# Compatibility Matrix and Fixture Design

## Purpose

This document defines the reporting and fixture model for E8 Slice A.

It answers:

- what a scenario is
- how results should be recorded
- how the generated matrix should be structured
- how to keep reports honest as PACT adds both MCP-core and PACT-specific behavior

## Core Design Rule

The compatibility matrix must be generated from machine-readable run artifacts.

Never hand-edit the matrix.

Human-written analysis can explain the matrix, but it must not replace it.

## Scenario Descriptor Shape

Each scenario should be represented as structured data.

Suggested shape:

```json
{
  "id": "tools-call-simple-text",
  "title": "Tool call returns a simple text result",
  "area": "tools",
  "specVersions": ["2025-11-25"],
  "transport": ["stdio", "streamable-http"],
  "peerRoles": ["client_to_pact_server", "pact_client_to_server"],
  "deploymentModes": ["wrapped_stdio", "native_stdio", "remote_http"],
  "category": "mcp-core",
  "requiredCapabilities": {
    "server": ["tools"],
    "client": []
  },
  "expected": "pass"
}
```

Recommended top-level fields:

- `id`
- `title`
- `area`
- `category`
- `specVersions`
- `transport`
- `peerRoles`
- `deploymentModes`
- `requiredCapabilities`
- `tags`
- `expected`
- `timeoutMs`

## Categories

Every scenario should belong to exactly one category:

- `mcp-core`
- `mcp-experimental`
- `pact-extension`
- `infra`

### `mcp-core`

Required for compatibility claims.

Examples:

- initialize
- tools/list
- tools/call
- resources/read
- prompts/get

### `mcp-experimental`

In-spec but explicitly experimental or version-sensitive enough to report separately.

Examples:

- tasks
- some auth edge cases if treated separately

### `pact-extension`

PACT-native behavior that should be reported, but never counted as MCP compliance.

Examples:

- deny receipts
- child-request receipts
- `notifications/pact/tool_call_chunk`

### `infra`

Harness or environment checks that should not be confused with protocol scenarios.

Examples:

- peer bootstrap
- package manager availability
- fixture provisioning

## Result Artifact Shape

Every executed scenario should emit one result record.

Suggested JSON shape:

```json
{
  "scenarioId": "tools-call-simple-text",
  "peer": "js",
  "peerRole": "client_to_pact_server",
  "deploymentMode": "remote_http",
  "transport": "streamable-http",
  "specVersion": "2025-11-25",
  "category": "mcp-core",
  "status": "pass",
  "durationMs": 184,
  "assertions": [
    { "name": "initialize_succeeds", "status": "pass" },
    { "name": "tool_call_result_shape", "status": "pass" }
  ],
  "artifacts": {
    "transcript": "artifacts/transcripts/tools-call-simple-text-js-remote_http.jsonl"
  }
}
```

Recommended required fields:

- `scenarioId`
- `peer`
- `peerRole`
- `deploymentMode`
- `transport`
- `specVersion`
- `category`
- `status`
- `durationMs`
- `assertions`

Recommended optional fields:

- `notes`
- `artifacts`
- `failureKind`
- `failureMessage`
- `expectedFailure`

## Status Values

Use a small explicit status set:

- `pass`
- `fail`
- `unsupported`
- `skipped`
- `xfail`

Definitions:

### `pass`

The scenario ran and all required assertions passed.

### `fail`

The scenario ran and at least one required assertion failed.

### `unsupported`

The scenario is outside the negotiated or declared capability set for that permutation.

This is not automatically a bug.

It may be the correct result for a mode or peer.

### `skipped`

The scenario was intentionally not run.

Examples:

- nightly-only
- missing optional runtime dependency

### `xfail`

Known failure tracked intentionally.

This is useful during rollout, but should be rare and explicit.

## Compatibility Matrix Shape

The generated Markdown matrix should summarize results by:

- feature area
- scenario
- peer
- deployment mode
- transport

Example:

| Area | Scenario | JS wrapped stdio | JS remote HTTP | Python wrapped stdio | Python remote HTTP |
| --- | --- | --- | --- | --- | --- |
| lifecycle | initialize | pass | pass | pass | pass |
| tools | tools-call-simple-text | pass | pass | pass | fail |
| auth | auth-code-pkce | n/a | pass | n/a | pass |

Rules:

- use separate sections for `mcp-core`, `mcp-experimental`, and `pact-extension`
- show `unsupported` explicitly rather than hiding it
- link scenario IDs to raw JSON artifacts where practical

## Aggregates

The generated report should include aggregates, but only within a category.

Good aggregates:

- MCP-core pass rate
- experimental pass rate
- PACT-extension pass count
- per-peer pass/fail summaries

Bad aggregates:

- one global pass rate across core, experimental, and PACT-only features

That would be misleading.

## Fixture Stability Policy

Scenarios should be stable and versioned.

Rules:

- scenario IDs never change casually
- breaking behavior changes create either:
  - a new scenario ID
  - or a new `specVersion` mapping
- expected results must remain attached to the scenario descriptor, not hidden in test code

## Artifact Requirements

Every failed scenario should preserve enough data to debug without rerunning immediately.

At minimum:

- JSON-RPC transcript or message log
- stderr/stdout capture for the peer process
- deployment metadata
- scenario metadata

For remote/auth cases, also keep:

- HTTP status and headers
- metadata documents returned
- token flow step trace with secrets redacted

## PACT-Specific Reporting Rules

PACT-specific features must never inflate MCP compliance claims.

Report them separately.

Examples:

- deny receipt emitted
- child-request receipt lineage present
- stream receipt chunk hashes present
- distributed revocation enforced
- shared budget denial enforced

These are valuable and should be visible.

They are just not the same as MCP-core compatibility.

## Suggested First Report Sections

1. Summary
2. MCP-core scenario matrix
3. MCP experimental scenario matrix
4. PACT extension matrix
5. Failures by area
6. Failures by peer
7. Raw artifact links

## Suggested First Scenario Inventory

### MCP-core

- `initialize`
- `ping`
- `tools-list`
- `tools-call-simple-text`
- `resources-list`
- `resources-read-text`
- `prompts-list`
- `prompts-get-simple`

### MCP experimental / advanced

- `sampling-create-message`
- `elicitation-create-form`
- `tasks-call-get-result`
- `resources-subscribe-updated`
- `streamable-http-session-reuse`
- `oauth-auth-code-pkce`
- `oauth-token-exchange`

### PACT extension

- `deny-receipt-emitted`
- `child-receipt-lineage`
- `pact-tool-streaming-notification`
- `distributed-revocation-enforced`
- `shared-budget-enforced`

## Decision

The matrix should be:

- generated
- artifact-backed
- category-separated
- spec-versioned

If those properties are preserved, the report can become a credible public compatibility surface instead of another internal engineering note.
