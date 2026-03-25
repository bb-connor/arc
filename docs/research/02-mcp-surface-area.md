# MCP Surface Area

## Why This Matters

If PACT wants to replace MCP, it must replace more than `tools/call`.

MCP is not just a tool invocation format. It is a session protocol with:

- lifecycle and capability negotiation
- transport and authorization expectations
- multiple server-side primitives
- client-side features for nested and interactive workflows
- utilities for long-running operations and better UX

Primary references:

- MCP overview: <https://modelcontextprotocol.io/specification/2025-06-18/basic/index>
- MCP lifecycle: <https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle>
- MCP authorization: <https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization>

## The Current MCP Contract

As of the current MCP spec release referenced by the official site, the protocol includes these major areas.

## 1. Base Protocol

MCP requires JSON-RPC 2.0 message semantics:

- requests
- responses
- notifications
- request IDs unique within a session

PACT currently does not expose a JSON-RPC session edge. It uses its own framed message protocol internally.

## 2. Lifecycle

Lifecycle is part of MCP's mandatory core. That includes:

- initialization
- version negotiation
- declared capabilities on both sides
- session-level feature discovery

This is not optional if the goal is true protocol replacement.

PACT implication:

- PACT needs a session handshake and negotiated feature model
- capabilities in the security sense are not the same thing as session capability negotiation

## 3. Authorization and Transport

MCP now defines an authorization model for HTTP-based transports, with OAuth-oriented expectations for protected servers.

Key point:

- MCP transport auth is about authenticating access to a server session
- PACT capability auth is about authorizing tool actions inside the session

PACT implication:

- PACT should not treat its capability model as a substitute for session transport auth
- a real replacement needs both

## 4. Server Features

### Tools

Tools are only one server primitive.

The current MCP tools surface includes:

- `tools/list`
- `tools/call`
- pagination
- list change notifications
- structured tool metadata
- output schema
- mixed content results
- resource links and embedded resources
- execution metadata such as task support

Reference:

- <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>

### Resources

Resources are a separate primitive with their own behavior:

- `resources/list`
- `resources/read`
- `resources/templates/list`
- `resources/subscribe`
- `notifications/resources/updated`
- list-changed notifications
- URI-based identity
- text and binary content
- annotations

Reference:

- <https://modelcontextprotocol.io/specification/2025-11-25/server/resources>

### Prompts

Prompts are user-controlled templates and workflows:

- `prompts/list`
- `prompts/get`
- list-changed notifications
- argumentized prompt retrieval
- prompt messages containing text, images, audio, and embedded resources

Reference:

- <https://modelcontextprotocol.io/specification/2025-11-25/server/prompts>

## 5. Client Features

### Roots

Roots let clients expose filesystem boundaries or workspace boundaries to servers.

This is more than convenience. It is the standard way for a server to know where it is allowed to operate.

Reference:

- <https://modelcontextprotocol.io/specification/2025-11-25/client/roots>

### Sampling

Sampling is one of the biggest conceptual gaps between "tool RPC" and "agent platform protocol."

It lets servers request model generations from the client:

- nested inside another workflow
- under the client's provider credentials
- under client-controlled permissions

Reference:

- <https://modelcontextprotocol.io/specification/2025-11-25/client/sampling>

### Elicitation

Elicitation lets servers ask the user for structured input via the client:

- form mode
- URL mode in newer revisions

Reference:

- <https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation>

## 6. Utilities

### Progress

MCP supports progress notifications for long-running operations.

Reference:

- <https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/progress>

### Pagination

List methods rely on cursor-based pagination.

Reference:

- <https://modelcontextprotocol.io/specification/2025-11-25/server/utilities/pagination>

### Logging

Servers can emit structured logs to clients.

Reference:

- <https://modelcontextprotocol.io/specification/2025-11-25/server/utilities/logging>

### Completion

MCP includes argument completion for prompts and resource templates.

Reference:

- <https://modelcontextprotocol.io/specification/2025-06-18/server/utilities/completion>

### Tasks and cancellation

The current MCP spec family also includes:

- cancellation via `notifications/cancelled`
- experimental task-oriented execution for durable, pollable work

Not every deployment will need task support immediately, but production replacements usually need cancellation, and long-running work tends to push quickly toward task semantics.

References:

- <https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/cancellation>
- <https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/tasks>

## Surface Area Summary

MCP replacement requires ownership of all of these categories:

| Area | Needed for real replacement |
| --- | --- |
| Base protocol | Yes |
| Lifecycle and negotiation | Yes |
| Session auth | Yes |
| Tools | Yes |
| Resources | Yes |
| Prompts | Yes |
| Roots | Yes |
| Sampling | Yes |
| Elicitation | Yes |
| Progress and cancellation | Practically yes |
| Logging and completion | Strongly yes |
| Pagination and change notifications | Yes |

The replacement bar is therefore much higher than "secure tool calling."
