# Gap Analysis

## Executive Summary

ARC is ahead of MCP on least privilege and auditability.

ARC is behind MCP on protocol completeness and ecosystem interoperability.

That means the work to `v1` is not primarily "invent stronger security." It is "wrap the existing security model in a complete, adoptable protocol surface."

After the recent E3-E7 work, the dominant gaps are no longer basic nested-flow/session behavior or the absence of a distributed trust plane. They are hosted-runtime maturity, stronger replicated-control semantics, published interoperability proof, and native authoring ergonomics.

## Parity Matrix

| Area | MCP expectation | Current ARC state | Gap | Priority |
| --- | --- | --- | --- | --- |
| Base wire protocol | JSON-RPC 2.0 session semantics | Custom framed kernel protocol plus MCP-compatible stdio edge and authenticated Streamable HTTP edge | The native ARC wire is still distinct from MCP JSON-RPC, and the remote edge still lacks resumability plus standalone GET/SSE streams | P1 |
| Initialization | Version negotiation and declared capabilities | Implemented on the MCP edge across stdio and remote Streamable HTTP hosting | Remote lifecycle hardening like resumability and richer reconnect semantics still missing | P1 |
| Tools | Full tool metadata and invocation | Implemented on the MCP edge and wrapped subprocess path; explicit cancelled/incomplete terminal outcomes now exist for tool requests; the native ARC wire now supports chunked streamed tool frames and terminal streamed statuses; streamed receipts now carry content hashes and chunk-hash metadata, and the kernel enforces stream duration and total-byte limits; the MCP edge now exposes an opt-in experimental `notifications/arc/tool_call_chunk` bridge for native streamed tool output; the edge supports a task-augmented `tools/call` slice with `tasks/list|get|result|cancel`, bounded background progression on idle and ordinary request turns, optional `notifications/tasks/status`, and related-task metadata on nested task-associated messages | Broader fully concurrent ownership is still missing | P0 |
| Resources | List, read, templates, subscriptions, updates | List/read/templates implemented in kernel, edge, and wrapped stdio path; edge-managed subscribe/unsubscribe and notification fanout now exist, and wrapped stdio servers can forward resource notifications during active tool calls and idle/background periods | Broader non-resource change coverage and richer stream semantics still missing | P0 |
| Prompts | List and retrieve prompt templates | Implemented in kernel, edge, and wrapped stdio path | Prompt-driven interactive workflows still need tighter elicitation integration | P1 |
| Roots | Client exposes filesystem boundaries | Session root snapshots, refresh, and wrapped `roots/list` propagation implemented | Root-aware enforcement still missing | P0 |
| Sampling | Server can request model calls via client | Direct edge and wrapped stdio propagation implemented with lineage and fail-closed policy checks; the wrapped stdio bridge now also supports task-augmented `sampling/createMessage` with `tasks/list|get|result|cancel` for nested client-side sampling work; nested child sampling requests now produce signed receipts with parent lineage and correct terminal states, and wrapped sampling tasks now progress even while the upstream server keeps sending nonterminal messages | Broader fully concurrent ownership still missing | P0 |
| Elicitation | Server can request structured user input | Form-mode and URL-mode `elicitation/create` are implemented on the direct edge and wrapped stdio path; task-augmented nested client-side elicitation work exists for form mode; accepted URL-mode elicitations now live in edge-owned pending state and wrapped stdio servers can later emit `notifications/elicitation/complete`; wrapped and direct tool servers can now also surface standard `-32042` URL-required outcomes, and native direct tool servers now have a kernel-drained async event source for late completion/change notifications; nested child elicitation requests now produce signed receipts with parent lineage and correct terminal states | Broader fully concurrent ownership still needs work | P0 |
| Progress | Long-running status notifications | Implemented for nested wrapped MCP client requests on the stdio edge | Not yet normalized across broader long-running work or streams | P1 |
| Cancellation | Stop in-flight work | Implemented for nested client requests, parent `tools/call` cancellation during nested work, and wrapped top-level `tools/call` cancellation while an upstream request is in flight | Broader async ownership beyond the wrapped stdio path and explicit race semantics still need work | P1 |
| Logging | Structured server-to-client logs | Implemented on the edge and wrapped stdio path | Upstream passthrough and richer log routing still missing | P2 |
| Completion | Prompt/resource template argument completion | Implemented for prompts/resources on the edge and wrapped stdio path | Broader utility parity still missing | P2 |
| Pagination | Cursor-based list methods | Implemented for tools/resources/templates/prompts on the MCP edge | Broader surface parity still missing | P2 |
| Subscriptions | Change notifications for resources/tools/prompts | Typed resource subscriptions plus edge-managed resource update fanout are implemented, including wrapped stdio passthrough during active tool calls and idle/background periods; wrapped tool/prompt `list_changed` passthrough is also implemented | No richer cross-surface subscription model beyond current resource subjects and catalog change passthrough | P1 |
| Transport auth | HTTP auth model for protected remote servers | Static bearer and Ed25519-signed JWT bearer admission are now shipped on the remote HTTP edge, with normalized session auth context capture, protected-resource metadata/challenges, separate admin-token support, colocated RFC 8414 authorization-server metadata discovery, a hosted local OAuth authorization server, `GET/POST /oauth/authorize`, `POST /oauth/token`, `GET /oauth/jwks.json`, authorization code with `S256` PKCE, and token exchange | Dynamic user federation, richer external IdP integration, and fuller OAuth deployment semantics are still missing | P1 |
| Capability authority | Strong issuance/revocation service | Pluggable capability-authority interface now exists with local, shared-SQLite, and shared HTTP control-service implementations; revocation can persist through SQLite or the trust-control service; the CLI exposes both local `trust revoke` / `trust status` and remote control-mode trust commands; stable issuance identity can be pinned with `--authority-seed-file`, shared through `--authority-db`, or centralized through `arc trust serve`; hosted HTTP runtimes now proxy authority/revocation admin through the control service when configured; authority verification now preserves trusted key history across future-session rotations; clustered trust-control nodes can now replicate authority state and fail over across nodes | Richer key hierarchy policy, attestation, and stronger multi-region/consensus replication semantics are still missing | P1 |
| Receipt log | Durable append-only or transparency backend | In-memory default plus shipped SQLite backend for durable tool and child-request receipts, and a shared HTTP control-service path for durable receipt ingestion/query across nodes | Still an operational audit plane, not a transparency service | P0 |
| Multi-node operation | Shared trust and budget state | Hosted nodes can now share an HA trust-control cluster for authority, revocations, receipts, and shared invocation budgets; control clients support comma-separated failover endpoints; distributed tests now prove centralized receipt queries, cross-node revocation enforcement, authority rotation propagation, budget convergence, and leader failover without correctness loss for subsequent requests | The HA model is still deterministic leader plus repair-sync rather than consensus or multi-region replication, and budget sharing is still invocation-count based rather than a richer quota system | P1 |
| Policy model | One canonical policy language | Single loaded runtime path from ARC YAML or HushSpec into the same kernel config and capability issuance flow | Dual source formats still exist | P1 |
| Migration | Drop-in adapters and compatibility | Wrapped stdio adapter now covers tools, resources, prompts, completion, logging, roots, and sampling | HTTP/auth/SDK parity still missing | P0 |

## The Most Important Gaps

## 1. Remote-hosting maturity gap

This is now the largest blocker.

ARC does ship authenticated remote hosting, Streamable HTTP, and multi-session ownership now. The remaining remote blocker is maturity: resumability, standalone GET/SSE streams, broader hosted-runtime ownership than one subprocess per session, and operational hardening beyond the current single-loop remote workers.

## 2. Nested workflow gap

This gap is smaller than it was.

ARC now supports roots snapshots, direct edge sampling, direct edge form-mode and URL-mode elicitation, and wrapped stdio propagation of `roots/list`, `sampling/createMessage`, and `elicitation/create` with parent-child lineage. Wrapped stdio servers can also emit `notifications/elicitation/complete` after the original tool response has finished because accepted URL-mode elicitation IDs now live in edge-owned pending state. Wrapped and direct tool servers can now surface standard `-32042` URL-required outcomes, native direct tool servers can emit late async completion/change events through a kernel-drained event source, and nested child requests now produce signed receipts with correct cancelled/incomplete terminal states. The idle-starvation variant of nested work is now fixed on both the outer edge and wrapped stdio bridge. The remaining nested-workflow blocker is broader fully concurrent ownership across transports.

## 3. Trust-plane gap

This gap is much smaller than it was.

ARC now has a real HA control cluster for authority, revocations, receipts, and shared invocation budgets. The remaining trust-plane gap is not "there is no distributed control plane." It is:

- stronger replication semantics than deterministic leader plus repair-sync
- richer key lifecycle and attestation policy
- broader shared control state beyond invocation budgets
- deeper external federation and identity-provider integration

## 4. Interop and product-surface gap

MCP is a developer standard because:

- people can build servers once
- clients know how to talk to them
- transports and session shape are familiar

ARC currently offers stronger security but still lacks published cross-language proof and a higher-level native authoring surface. That is now as much an adoption and ergonomics problem as a raw protocol problem.

## 5. Policy integration gap

The runtime gap is mostly closed.

ARC YAML and HushSpec both compile into the same loaded runtime state, and the kernel/CLI now consume that one path. The remaining issue is product-level format convergence, not a split execution path.

## What ARC Already Beats MCP At

This is the part worth preserving:

- explicit authority instead of ambient trust
- token attenuation and delegation model
- signed receipts for allow and deny decisions
- cleaner place to enforce pre-execution policy
- stronger path to formal reasoning

These are not small advantages. They are the reasons to do the project at all.

## Bottom Line

To become a true MCP replacement, ARC must:

- match MCP's usable protocol surface
- exceed MCP's trust and enforcement guarantees
- preserve adoption through compatibility and migration tooling

If any one of those three fails, ARC becomes either:

- a research protocol
- a niche secure proxy
- or a better internal architecture that never becomes the ecosystem default
