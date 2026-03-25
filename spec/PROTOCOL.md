# PACT Protocol

**Version:** 2.0
**Date:** 2026-03-25
**Status:** Shipped repository profile

---

## 1. Purpose

PACT is a capability-scoped mediation and evidence system for agent tool use.
In this repository it ships as:

- a native agent-to-kernel protocol for signed capability evaluation
- a kernel that emits signed receipts for allow, deny, cancelled, and
  incomplete outcomes
- trust-control services for authority, revocation, receipt, budget, and
  federation state
- hosted MCP-compatible edges and adapters that keep the same trust contract
- portable trust artifacts for `did:pact`, passports, verifier policies,
  challenge/response presentation, evidence export, and certification

This document describes the protocol and artifact contract that the code in
this repository actually ships. It is intentionally narrower than the older
research draft that described aspirational networking and deployment topology.

## 2. Scope And Compatibility

The shipped `v2` contract covers:

- native capability and receipt validation
- wrapped and hosted MCP mediation
- trust-control HTTP APIs for authority, receipts, revocation, budgets,
  federation, reputation comparison, and certification
- `did:pact`
- Agent Passport artifacts and verifier-policy distribution
- federated evidence export/import and cross-org delegation continuation
- A2A v1.0.0 mediation through `pact-a2a-adapter`
- signed certification checks plus a local or trust-control-backed registry

The shipped `v2` contract does not claim:

- multi-region consensus or Byzantine replication
- a public certification marketplace
- automatic SCIM provisioning lifecycle
- synthetic cross-issuer passport scoring
- full theorem-prover completion for every security property
- a replacement of MCP or A2A at the wire-protocol ecosystem level

Compatibility rule:

- additive fields may appear in JSON responses and signed artifacts
- unknown schema identifiers for schema-tagged artifacts must be rejected
- fail-closed behavior is part of the protocol contract, not an implementation
  detail

## 3. Components And Trust Boundaries

PACT in this repository uses these roles:

| Component | Role |
| --- | --- |
| Agent | Untrusted caller that presents a capability or authenticates to a hosted edge |
| Kernel | Trusted enforcement layer that validates capabilities, runs guards, dispatches calls, and signs receipts |
| Tool server | Native or wrapped implementation of tools/resources/prompts |
| Trust-control | Operator-facing authority, receipt, revocation, budget, federation, and certification service |
| Hosted MCP edge | `pact mcp serve-http`, which exposes an MCP-compatible HTTP surface with remote session lifecycle and admin APIs |
| Operator stores | SQLite stores and file-backed registries for authoritative local state |

The security boundary that matters is constant across these surfaces:

- the agent never receives ambient authority
- every mediated action is bound to explicit capability or authenticated hosted
  session state
- denials are explicit, signed, and auditable
- registry and artifact mismatches fail closed instead of degrading silently

## 4. Serialization And Identity

### 4.1 Canonical JSON

Signed PACT artifacts use canonical JSON serialization before Ed25519 signing.
This includes capability tokens, receipts, manifests, checkpoints, verifier
policies, passport presentations, and certification artifacts.

### 4.2 Native Wire Format

The native agent-to-kernel protocol uses length-prefixed JSON messages with a
`type` discriminator. The core messages are defined by `AgentMessage` and
`KernelMessage` in `crates/pact-core/src/message.rs`.

Request examples:

- `tool_call_request`
- `list_capabilities`
- `heartbeat`

Response examples:

- `tool_call_chunk`
- `tool_call_response`
- `capability_list`
- `capability_revoked`
- `heartbeat`

### 4.3 Hosted Wire Format

The hosted edge uses MCP-compatible HTTP semantics rather than the native
length-prefixed transport:

- JSON-RPC over HTTP POST
- standalone GET/SSE streams where supported by the hosted edge
- bearer-token or JWT-backed session admission
- remote admin APIs under `/admin/...`

### 4.4 Identity

PACT uses Ed25519 keys as the primary cryptographic identity primitive.

`did:pact` is the shipped self-certifying DID method for those keys:

```text
did:pact:{64-hex-ed25519-public-key}
```

Resolution is local and self-certifying. Optional service endpoints, such as a
receipt-log URL, may be attached by the resolving environment.

## 5. Capability Contract

The shipped capability token is `CapabilityToken` from
`crates/pact-core/src/capability.rs`.

Unlike several other PACT artifacts, capability tokens do not carry a `schema`
field today. The signed body is:

| Field | Meaning |
| --- | --- |
| `id` | Stable capability identifier used for revocation |
| `issuer` | Ed25519 public key of the authority or delegating issuer |
| `subject` | Ed25519 public key bound to the caller |
| `scope` | Tool, resource, and prompt grants |
| `issued_at` | Unix timestamp seconds |
| `expires_at` | Unix timestamp seconds |
| `delegation_chain` | Ordered chain of delegation links |

### 5.1 Scope

The shipped scope model includes:

- `grants: Vec<ToolGrant>`
- `resource_grants: Vec<ResourceGrant>`
- `prompt_grants: Vec<PromptGrant>`

`ToolGrant` includes:

- `server_id`
- `tool_name`
- `operations`
- `constraints`
- `max_invocations`
- `max_cost_per_invocation`
- `max_total_cost`
- optional `dpop_required`

### 5.2 Verification Rules

The kernel and trust surfaces verify, at minimum:

1. Ed25519 signature validity
2. current time is within `issued_at <= now < expires_at`
3. the requested target is contained by the grant set
4. attenuation stays within the parent scope
5. revocation state is clear
6. DPoP proof is valid when the selected grant requires it
7. policy guards pass

Any failure denies or rejects the action instead of widening access.

## 6. Receipt Contract

The shipped receipt envelope is `PactReceipt` from
`crates/pact-core/src/receipt.rs`.

| Field | Meaning |
| --- | --- |
| `id` | Stable receipt identifier |
| `timestamp` | Unix timestamp seconds |
| `capability_id` | Capability exercised or presented |
| `tool_server` | Target server id |
| `tool_name` | Target tool |
| `action` | Canonicalized tool parameters plus `parameter_hash` |
| `decision` | `allow`, `deny`, `cancelled`, or `incomplete` |
| `content_hash` | Hash of the evaluated content or outcome payload |
| `policy_hash` | Hash of the policy material used |
| `evidence` | Per-guard evidence |
| `metadata` | Optional structured metadata |
| `kernel_key` | Verifying public key |
| `signature` | Ed25519 signature |

### 6.1 Decisions

The decision enum is part of the contract:

- `Allow`
- `Deny { reason, guard }`
- `Cancelled { reason }`
- `Incomplete { reason }`

The protocol guarantee is that cancelled and incomplete outcomes are preserved
explicitly rather than collapsed into an undifferentiated error state.

### 6.2 Child Receipts

Nested flows such as sampling, elicitation, and resource reads use
`ChildRequestReceipt`, which records:

- `session_id`
- `parent_request_id`
- `request_id`
- `operation_kind`
- `terminal_state`
- `outcome_hash`
- `policy_hash`
- optional metadata

### 6.3 Receipt Metadata

The shipped metadata surface is extensible JSON. Current first-class uses
include:

- financial attribution and settlement metadata
- subject and issuer attribution
- streamed-output chunk metadata
- portable-trust and federation provenance

### 6.4 Checkpoints

Receipt batches can be committed to a Merkle checkpoint with schema:

```text
pact.checkpoint_statement.v1
```

Checkpoint verification is part of exported evidence and compliance-oriented
operator reporting.

## 7. Manifest Contract

Tool discovery uses the signed manifest schema:

```text
pact.manifest.v1
```

The manifest defines:

- server identity
- one or more tool definitions
- per-tool input and optional output schemas
- operator-facing descriptions and metadata

This manifest is the authoritative discovery contract for native tool servers
and for mediated adapters that synthesize a PACT tool surface from another
protocol.

## 8. Runtime Surfaces

### 8.1 Local CLI And Kernel

The repository ships these primary runtime entrypoints:

- `pact check`
- `pact run`
- `pact mcp serve`
- `pact mcp serve-http`
- `pact trust serve`

These surfaces intentionally share the same core receipt, capability,
revocation, and policy primitives rather than defining separate trust models.

### 8.2 MCP Compatibility

PACT does not claim to replace MCP. It ships an MCP-compatible mediation layer
that currently covers:

- tools
- resources
- prompts
- completions
- logging
- tasks
- progress notifications
- nested sampling, elicitation, and roots callbacks
- remote HTTP auth discovery and hosted authorization-server flows

Compatibility claims are grounded in checked-in conformance scenarios, live JS
and Python peers, and the release-qualification wave corpus.

### 8.3 Hosted Remote Admin

`pact mcp serve-http` ships operator-facing admin APIs, including:

- `/admin/health`
- `/admin/authority`
- `/admin/sessions`
- `/admin/sessions/{session_id}/trust`
- `/admin/receipts/...`
- `/admin/revocations`
- `/admin/budgets`

These surfaces are part of the supported production-diagnostics contract for
the hosted edge.

## 9. Trust-Control Contract

`pact trust serve` is the shipped trust-control HTTP service.

Core operator and cluster surfaces include:

- `/health`
- `/v1/authority`
- `/v1/internal/cluster/status`
- `/v1/receipts/query`
- `/v1/reports/operator`
- `/v1/federation/evidence-shares`
- `/v1/reputation/compare/{subject_key}`

Federation and certification administration includes:

- `/v1/federation/providers`
- `/v1/federation/providers/{provider_id}`
- `/v1/certifications`
- `/v1/certifications/{artifact_id}`
- `/v1/certifications/resolve/{tool_server_id}`
- `/v1/certifications/{artifact_id}/revoke`

The health contract is additive JSON and currently includes authority, store,
federation, and cluster summaries rather than a single opaque boolean.

## 10. Portable Trust And Federation

### 10.1 Agent Passport

PACT ships these portable-trust schema identifiers:

| Artifact | Schema |
| --- | --- |
| Agent passport | `pact.agent-passport.v1` |
| Verifier policy | `pact.passport-verifier-policy.v1` |
| Presentation challenge | `pact.agent-passport-presentation-challenge.v1` |
| Presentation response | `pact.agent-passport-presentation-response.v1` |

The current shipped semantics are:

- issuer and subject identities are `did:pact`
- a passport may contain multiple credentials from different issuers as long as
  they all bind to one subject
- verifier evaluation remains per credential
- acceptance requires at least one credential to satisfy the verifier policy
- replay-safe challenge verification can be backed by durable SQLite state

### 10.2 Federation Artifacts

The shipped cross-org artifact schemas are:

| Artifact | Schema |
| --- | --- |
| Evidence export manifest | `pact.evidence_export_manifest.v1` |
| Federation policy | `pact.federation-policy.v1` |
| Federated evidence share | `pact.federated-evidence-share.v1` |
| Federated delegation policy | `pact.federated-delegation-policy.v1` |

The supported contract includes:

- signed bilateral evidence-export policy documents
- verified import of exported evidence packages
- shared-evidence reporting without pretending foreign receipts are native local
  receipts
- parent-bound continuation from an imported upstream capability into a new
  local delegation anchor

### 10.3 Enterprise Identity Federation

Bearer-authenticated hosted sessions may normalize enterprise identity context
into:

- `authContext.method.federatedClaims`
- `authContext.method.enterpriseIdentity`

The current shipped provider-admin registry supports `oidc_jwks`,
`oauth_introspection`, `scim`, and `saml` record kinds. Invalid provider
records stay visible for operator diagnostics but are not eligible for
admission.

## 11. A2A Adapter Contract

`pact-a2a-adapter` is a thin bridge for A2A v1.0.0, not a new A2A wire
standard.

The current shipped behavior includes:

- Agent Card discovery
- `JSONRPC` and `HTTP+JSON` interface bindings
- `SendMessage`
- `SendStreamingMessage`
- `GetTask`
- `SubscribeToTask`
- `CancelTask`
- push-notification config create/get/list/delete
- fail-closed auth negotiation for bearer, OAuth/OpenID, HTTP Basic, API key,
  and mTLS
- optional durable task correlation through a file-backed registry
- explicit partner-admission policy by tenant, skill, security scheme, and
  allowed interface origin

PACT uses an adapter-local metadata convention to route a call to one A2A
skill:

```json
{
  "pact": {
    "targetSkillId": "research",
    "targetSkillName": "Research"
  }
}
```

That convention is explicit and is not presented as a core A2A protocol field.

## 12. Certification Contract

PACT ships signed certification checks with schema:

```text
pact.certify.check.v1
```

The local or trust-control-backed registry uses:

```text
pact.certify.registry.v1
```

The certification contract covers:

- evaluation of a declared conformance result corpus
- one fail-closed criteria profile today: `conformance-all-pass-v1`
- signed artifacts with verdict, corpus digests, and findings
- registry publication, listing, get, resolve, and revoke
- operator-facing resolution states: `active`, `revoked`, `superseded`,
  `not-found`

This is a signed operator evidence layer, not a public marketplace or global
trust network.

## 13. Observability Contract

Production observability is part of the shipped contract.

Stable operator surfaces include:

- trust-control `/health` and `/v1/internal/cluster/status`
- hosted edge `/admin/health`, `/admin/sessions`, and session trust views
- provider-admin registry inspection surfaces
- certification registry status surfaces
- operator report and shared-evidence analytics
- durable A2A task-registry rejection when follow-up correlation is unsafe

Field additions are allowed. Silent fail-open downgrades are not.

For operational guidance, see:

- `docs/release/OBSERVABILITY.md`
- `docs/release/OPERATIONS_RUNBOOK.md`

## 14. Explicit Gaps

The following are intentionally outside the shipped `v2` contract:

- public federation or certification discovery beyond configured local or
  operator-controlled trust surfaces
- automatic enterprise identity propagation into every portable artifact
- custom A2A auth schemes beyond the shipped matrix
- full automatic wallet/distribution semantics for passports
- performance claims beyond the qualification and documentation surfaces

These gaps are documented explicitly so operators and integrators do not have
to infer them from source code.
