# Proposed Architecture

## Executive Summary

The cleanest `v1` architecture is:

- MCP-compatible JSON-RPC at the edge
- ARC capability enforcement in the middle
- transport-specific tool adapters underneath
- durable trust services beside the runtime

This lets ARC preserve its strongest idea, explicit authority plus signed evidence, without forcing the ecosystem to abandon the MCP interaction model on day one.

## Target Logical Architecture

```text
MCP Client / Host Application
        |
        | JSON-RPC session
        v
ARC Edge Session Layer
        |
        | normalized requests + negotiated features
        v
ARC Kernel
        |
        | capability check -> guard pipeline -> dispatch
        v
ARC Tool Runtime / Adapters
        |
        +--> Native ARC tool servers
        +--> MCP-wrapped tool servers
        +--> Resource providers
        +--> Prompt providers

Trust services:

- capability authority
- revocation service
- receipt log
- identity and key registry
```

## Architectural Layers

## 1. Edge session layer

Responsibilities:

- expose JSON-RPC request, response, and notification handling
- negotiate protocol revision and supported features
- map MCP session concepts onto internal ARC operations
- own in-flight request tracking for progress and cancellation
- own subscriptions, list-change notifications, and pagination cursors

This layer should be protocol-aware but policy-light.

It should not decide authorization beyond coarse session admission.

## 2. Kernel

Responsibilities:

- validate capability tokens
- validate time, scope, delegation, and revocation
- run the compiled guard pipeline
- produce receipts
- dispatch to the correct provider or adapter

This layer should remain the trust core.

The kernel should not know whether a request originated from:

- a local CLI session
- an MCP client over stdio
- an MCP client over HTTP
- a future native ARC edge

It should receive normalized operations.

## 3. Provider layer

Provider types should become explicit instead of everything being treated as a tool:

- tool provider
- resource provider
- prompt provider
- sampling bridge
- elicitation bridge

This matters because the control models differ:

- tools are usually model-controlled
- prompts are usually user-controlled
- resources are usually application-controlled
- sampling and elicitation are nested client features, not ordinary server features

## 4. Trust services

The trust plane should become externalizable.

Services:

- capability issuance
- revocation status
- receipt persistence
- server identity resolution
- key rotation metadata

The local single-process mode can still exist, but it should be a deployment mode, not the only runtime assumption.

## Normalized Internal Operation Model

The current runtime centers tool invocation. `v1` needs a broader internal operation enum.

Suggested shape:

```rust
enum SessionOperation {
    ToolCall(ToolCallOp),
    ResourceList(ResourceListOp),
    ResourceRead(ResourceReadOp),
    ResourceSubscribe(ResourceSubscribeOp),
    PromptList(PromptListOp),
    PromptGet(PromptGetOp),
    SamplingRequest(SamplingOp),
    ElicitationRequest(ElicitationOp),
    Completion(CompletionOp),
}
```

The kernel should not necessarily authorize each operation the same way.

Examples:

- `ToolCall` requires action capabilities and guard execution
- `ResourceRead` may require capability-scoped URI grants
- `PromptGet` may require user-controlled gating instead of pure model-controlled gating
- `SamplingRequest` likely requires both session capability and policy approval hooks

## Session State Model

ARC needs a first-class session object.

Suggested state machine:

```text
Connecting
  -> Initializing
  -> Ready
  -> Draining
  -> Closed
```

Tracked session state should include:

- negotiated protocol version
- peer-advertised capabilities
- session identity and auth context
- root set
- in-flight requests
- subscriptions
- active tasks and streams
- capability cache

## Proposed Repository Shape

The current repo can support this without a total reorg, but `v1` probably wants at least a few new modules or crates.

## Existing crates to preserve

- `arc-core`
- `arc-kernel`
- `arc-guards`
- `arc-policy`
- `arc-manifest`
- `arc-mcp-adapter`

## Likely new crates or major modules

### `arc-session`

Purpose:

- session handshake
- negotiated features
- in-flight request tracking
- progress and cancellation state
- subscription registry

Alternative:

- keep this inside `arc-kernel` as a `session` module

Recommendation:

- new crate if you expect both MCP-edge and native-edge frontends
- module if you want to stay small until `v0.4`

### `arc-jsonrpc`

Purpose:

- JSON-RPC framing, IDs, request dispatch, notifications
- MCP-compatible edge message parsing and validation

Alternative:

- fold into `arc-session`

Recommendation:

- separate crate only if you want reuse or generated schema support

### `arc-edge-mcp`

Purpose:

- implement MCP-compatible server and client feature handling at the edge
- translate edge requests into normalized internal operations

This is likely cleaner than bloating `arc-mcp-adapter`, which currently plays a different role.

### `arc-ca`

Purpose:

- capability issuance
- step-up authorization
- revocation feed publication

Could begin as a library plus in-memory server implementation.

### `arc-receipt-store`

Purpose:

- durable receipt backend
- query APIs
- optional Merkle or transparency-log packaging

Could initially target:

- SQLite
- local append-only file
- object store plus index

## Existing crate evolution

### `arc-core`

Should continue to hold:

- stable protocol datatypes
- signatures and canonicalization
- receipt and capability formats

Should probably gain:

- richer session-level message datatypes
- resource and prompt structures
- pagination cursor and notification datatypes

Should probably not gain:

- transport-specific code
- JSON-RPC plumbing

### `arc-kernel`

Should evolve into:

- operation normalization boundary
- enforcement and dispatch core

Should probably gain:

- operation enum support beyond tool calls
- provider registry instead of tool-server-only registry
- policy-aware nested-flow enforcement hooks
- stream lifecycle support

Should probably stop assuming:

- only one request class matters
- all operations are single-shot
- receipts only represent allow or deny

### `arc-mcp-adapter`

Should remain:

- migration adapter from MCP servers into ARC runtime

Should gain:

- resource and prompt adaptation if feasible
- richer metadata translation
- more transport coverage if MCP transports matter for target deployments

Should not become:

- the only MCP-facing edge layer

That would mix migration responsibilities with first-class protocol hosting.

## Data Model Evolution

## Capabilities

Current capabilities are too tool-centric for `v1`.

The scope model likely needs additional grant families:

- tool grants
- resource grants
- prompt grants
- nested-flow grants

One possible shape:

```rust
enum Grant {
    Tool(ToolGrant),
    Resource(ResourceGrant),
    Prompt(PromptGrant),
    Sampling(SamplingGrant),
    Elicitation(ElicitationGrant),
}
```

This is better than forcing URI and prompt semantics into ad hoc tool constraints.

## Receipts

Current receipts are already a strength, but they need to cover more outcome types:

- allow
- deny
- incomplete
- cancelled
- superseded

Receipts may also need:

- session ID
- request lineage
- parent request ID for nested flows
- stream hash summary
- task ID for durable work

## Identity Model

There are two distinct identities that should remain separate:

- session peer identity
- action subject identity

Examples:

- a desktop client may authenticate a session as a user and device
- the client may then request a capability for a specific assistant persona or worktree-scoped agent

That separation will matter later for enterprise deployments and delegated agents.

## Edge/Core Translation Rules

A useful design rule:

- edge protocol objects are descriptive
- core operation objects are enforceable

For example:

- MCP tool metadata can include display fields and UI annotations
- the kernel only needs the normalized identity, schema, target, and authority context to enforce a call

This keeps the kernel narrow and reduces protocol churn in the trust core.

## Suggested First Implementation Move

The first high-leverage architectural implementation is not resources or prompts.

It is a session abstraction that can sit between:

- current CLI/local transport
- future MCP JSON-RPC edge
- future remote transport

Without that layer, every new feature risks being wired directly into the kernel in incompatible ways.
