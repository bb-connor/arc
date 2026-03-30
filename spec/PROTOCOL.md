# ARC Protocol

**Version:** 2.0
**Date:** 2026-03-25
**Status:** Shipped repository profile

---

## 1. Purpose

ARC is a capability-scoped mediation and evidence system for agent tool use.
In this repository it ships as:

- a native agent-to-kernel protocol for signed capability evaluation
- a kernel that emits signed receipts for allow, deny, cancelled, and
  incomplete outcomes
- trust-control services for authority, revocation, receipt, budget, and
  federation state
- hosted MCP-compatible edges and adapters that keep the same trust contract
- portable trust artifacts for `did:arc`, ARC-branded schema issuance,
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
- `did:arc`
- Agent Passport artifacts and verifier-policy distribution
- federated evidence export/import and cross-org delegation continuation
- A2A v1.0.0 mediation through `arc-a2a-adapter`
- signed certification checks plus operator-scoped registry and discovery-network
  surfaces

The shipped `v2` contract does not claim:

- multi-region consensus or Byzantine replication
- a public certification marketplace
- automatic SCIM provisioning lifecycle
- synthetic cross-issuer passport scoring
- full theorem-prover completion for every security property
- a replacement of MCP or A2A at the wire-protocol ecosystem level

Compatibility rule:

- additive fields may appear in JSON responses and signed artifacts
- unknown schema identifiers for schema-tagged artifacts must be rejected,
  except for explicitly supported legacy Pact-era aliases
- fail-closed behavior is part of the protocol contract, not an implementation
  detail

## 3. Components And Trust Boundaries

ARC in this repository uses these roles:

| Component | Role |
| --- | --- |
| Agent | Untrusted caller that presents a capability or authenticates to a hosted edge |
| Kernel | Trusted enforcement layer that validates capabilities, runs guards, dispatches calls, and signs receipts |
| Tool server | Native or wrapped implementation of tools/resources/prompts |
| Trust-control | Operator-facing authority, receipt, revocation, budget, federation, and certification service |
| Hosted MCP edge | `arc mcp serve-http`, which exposes an MCP-compatible HTTP surface with remote session lifecycle and admin APIs |
| Operator stores | SQLite stores and file-backed registries for authoritative local state |

The security boundary that matters is constant across these surfaces:

- the agent never receives ambient authority
- every mediated action is bound to explicit capability or authenticated hosted
  session state
- denials are explicit, signed, and auditable
- registry and artifact mismatches fail closed instead of degrading silently

## 4. Serialization And Identity

### 4.1 Canonical JSON

Signed ARC artifacts use canonical JSON serialization before Ed25519 signing.
This includes capability tokens, receipts, manifests, checkpoints, verifier
policies, passport presentations, and certification artifacts.

### 4.2 Native Wire Format

The native agent-to-kernel protocol uses length-prefixed JSON messages with a
`type` discriminator. The core messages are defined by `AgentMessage` and
`KernelMessage` in `crates/arc-core/src/message.rs`.

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

ARC uses Ed25519 keys as the primary cryptographic identity primitive.

`did:arc` remains the shipped self-certifying DID method for those keys in
this release:

```text
did:arc:{64-hex-ed25519-public-key}
```

Resolution is local and self-certifying. Optional service endpoints, such as a
receipt-log URL, may be attached by the resolving environment.

## 5. Capability Contract

The shipped capability token is `CapabilityToken` from
`crates/arc-core/src/capability.rs`.

Unlike several other ARC artifacts, capability tokens do not carry a `schema`
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

The shipped `constraints` surface includes ordinary argument constraints plus
governed-transaction controls such as `governed_intent_required`,
`require_approval_above`, and `seller_exact`.

### 5.2 Governed Transaction Extensions

Tool-call requests may attach two optional governed artifacts:

- `governed_intent`, a canonical request intent carrying `id`, `server_id`,
  `tool_name`, `purpose`, optional `max_amount`, optional seller-scoped
  `commerce { seller, shared_payment_token_id }`, optional
  `metered_billing { settlement_mode, quote, max_billed_units }`, optional
  `call_chain { chain_id, parent_request_id, parent_receipt_id?,
  origin_subject, delegator_subject }`, and optional structured context
- `approval_token`, a signed approval artifact bound to one subject, one
  request id, and one governed intent hash

The `metered_billing.quote` sub-block is the payment-rail-neutral pre-execution
estimate for non-rail tools. It carries:

- `quote_id`
- `provider`
- `billing_unit`
- `quoted_units`
- `quoted_cost { units, currency }`
- `issued_at`
- optional `expires_at`

`metered_billing.settlement_mode` expresses whether the governed action is
expected to use `must_prepay`, `hold_capture`, or `allow_then_settle` semantics.
This is evidence and operator context, not the hard enforcement boundary by
itself. The kernel still enforces issued budgets and explicit governed limits.

When a matched grant includes `governed_intent_required`, the kernel requires
`governed_intent`. When a matched grant includes
`require_approval_above { threshold_units }`, the kernel requires a valid
`approval_token` whenever the provisional charged amount meets or exceeds that
threshold. When a matched grant includes `seller_exact`, the kernel requires
seller-scoped commerce approval context and denies if the governed seller does
not match the grant seller scope.

Approval tokens are verified against trusted authority keys and are bound to:

- the request `request_id`
- the capability `subject`
- the canonical hash of the attached governed intent
- approval-token `issued_at` and `expires_at` time bounds

If `governed_intent.call_chain` is present, the kernel rejects empty fields and
self-referential `parent_request_id == request_id` bindings. ARC treats
delegated call-chain provenance as part of the approval-bound intent, not as a
mutable reporting annotation.

### 5.3 Verification Rules

The kernel and trust surfaces verify, at minimum:

1. Ed25519 signature validity
2. current time is within `issued_at <= now < expires_at`
3. the requested target is contained by the grant set
4. attenuation stays within the parent scope
5. revocation state is clear
6. DPoP proof is valid when the selected grant requires it
7. policy guards pass

Any failure denies or rejects the action instead of widening access.

### 5.4 Safety Properties And Evidence Boundary

The current launch-candidate safety inventory is:

- `P1` capability attenuation: delegation can only narrow scope relative to its
  parent
- `P2` revocation completeness: a revoked capability or revoked delegation
  ancestor is denied
- `P3` fail-closed evaluation: verification or policy failures deny or reject
  rather than widening access
- `P4` receipt integrity: signed receipts and checkpoints remain verifiable as
  evidence artifacts
- `P5` delegation-chain structural validity: delegation depth, connectivity,
  and timestamp monotonicity are enforced

ARC intentionally distinguishes evidence classes for these claims:

- executable differential tests in `formal/diff-tests` are the release gate for
  scope-attenuation semantics
- kernel, control-plane, and integration tests verify fail-closed runtime
  behavior for revocation, DPoP, governed approvals, monetary budgets, and
  runtime assurance
- conformance and release-qualification lanes verify mediated protocol
  behavior, packaging, and clustered operator workflows

ARC does not currently claim theorem-prover completion for every protocol
property. The Lean tree under `formal/lean4` is informative and useful for
ongoing proof work, but standalone proof modules that are not root-imported or
still contain `sorry` are not part of the shipped release gate or launch
claims.

## 6. Receipt Contract

The shipped receipt envelope is `ArcReceipt` from
`crates/arc-core/src/receipt.rs`.

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
- governed transaction intent and approval metadata
- subject and issuer attribution
- streamed-output chunk metadata
- portable-trust and federation provenance

Governed transaction receipts use a `governed_transaction` metadata block with
the canonical intent identifiers plus optional approval evidence. The current
block includes:

- `intent_id`
- `intent_hash`
- `purpose`
- `server_id`
- `tool_name`
- optional `max_amount`
- optional `commerce { seller, shared_payment_token_id }`
- optional
  `metered_billing { settlementMode, quote, maxBilledUnits, usageEvidence }`
- optional `approval { token_id, approver_key, approved }`
- optional
  `runtime_assurance { tier, verifier, evidence_sha256, workload_identity? }`
- optional `call_chain { chainId, parentRequestId, parentReceiptId?,
  originSubject, delegatorSubject }`

`governed_transaction.runtime_assurance.tier` records the accepted runtime
assurance tier after any configured verifier trust-policy rebinding, not just
the raw tier carried by the upstream attestation payload.

Settlement reconciliation state is intentionally not written back into the
signed receipt. Trust-control keeps mutable operator-side reconciliation state
keyed by `receipt_id` and reports it separately from the signed
`financial.settlement_status` so receipt truth remains immutable.

The `governed_transaction.metered_billing` block preserves the quoted estimate
and, when later available, a post-execution `usageEvidence` reference. This is
separate from `metadata.financial`, which continues to record the kernel's
charged or attempted amount. ARC does not collapse quoted cost, actual charge,
and external usage evidence into one field.

When post-execution metered evidence arrives from an external adapter, ARC
stores that record in a mutable sidecar keyed by `receipt_id`, carrying the
adapter identity, evidence record identity, observed units, billed amount, and
operator reconciliation state. That sidecar is queryable and exportable, but
it is not merged back into the signed receipt JSON.

### 6.4 Checkpoints

Receipt batches can be committed to a Merkle checkpoint with primary schema:

```text
arc.checkpoint_statement.v1
```

Legacy `arc.checkpoint_statement.v1` checkpoints remain valid for verification
and evidence import. Checkpoint verification is part of exported evidence and
compliance-oriented operator reporting.

## 7. Manifest Contract

Tool discovery currently uses the frozen manifest schema:

```text
arc.manifest.v1
```

The manifest defines:

- server identity
- one or more tool definitions
- per-tool input and optional output schemas
- operator-facing descriptions and metadata

This manifest is the authoritative discovery contract for native tool servers
and for mediated adapters that synthesize an ARC tool surface from another
protocol. `arc.manifest.v1` remains frozen in this release for compatibility.

## 8. Runtime Surfaces

### 8.1 Local CLI And Kernel

The repository ships these primary runtime entrypoints:

- `arc check`
- `arc run`
- `arc mcp serve`
- `arc mcp serve-http`
- `arc trust serve`

These surfaces intentionally share the same core receipt, capability,
revocation, and policy primitives rather than defining separate trust models.

### 8.2 MCP Compatibility

ARC does not claim to replace MCP. It ships an MCP-compatible mediation layer
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

`arc mcp serve-http` ships operator-facing admin APIs, including:

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

`arc trust serve` is the shipped trust-control HTTP service.

Core operator and cluster surfaces include:

- `/health`
- `/v1/authority`
- `/v1/capabilities/issue`
- `/v1/internal/cluster/status`
- `/v1/receipts/query`
- `/v1/reports/operator`
- `/v1/reports/behavioral-feed`
- `/v1/reports/underwriting-input`
- `/v1/reports/exposure-ledger`
- `/v1/reports/credit-scorecard`
- `/v1/reports/settlements`
- `/v1/reports/authorization-context`
- `/v1/reports/authorization-profile-metadata`
- `/v1/reports/authorization-review-pack`
- `/v1/settlements/reconcile`
- `/v1/federation/evidence-shares`
- `/v1/reputation/compare/{subject_key}`

Federation and certification administration includes:

- `/v1/federation/providers`
- `/v1/federation/providers/{provider_id}`
- `/v1/certifications`
- `/v1/certifications/{artifact_id}`
- `/v1/certifications/resolve/{tool_server_id}`
- `/v1/certifications/discovery/publish`
- `/v1/certifications/discovery/resolve/{tool_server_id}`
- `/v1/certifications/discovery/search`
- `/v1/certifications/discovery/transparency`
- `/v1/certifications/discovery/consume`
- `/v1/certifications/{artifact_id}/revoke`
- `/v1/certifications/{artifact_id}/dispute`
- `/v1/public/certifications/metadata`
- `/v1/public/certifications/resolve/{tool_server_id}`
- `/v1/public/certifications/search`
- `/v1/public/certifications/transparency`

The health contract is additive JSON and currently includes authority, store,
federation, and cluster summaries rather than a single opaque boolean.
`/v1/reports/operator` now also carries settlement backlog visibility and
explicit multi-dimensional budget profiles. Budget utilization rows expose
named `dimensions.invocations` and `dimensions.money` usage blocks, while
settlement backlog rows pair signed `financial.settlement_status` with mutable
sidecar reconciliation state keyed by `receipt_id`.
`/v1/reports/metered-billing` and `/v1/metered-billing/reconcile` apply the
same pattern to post-execution metered-cost evidence for governed
non-payment-rail tools.
`/v1/reports/authorization-context` exports a standards-legible projection of
governed receipts into:

- one or more derived `authorization_details` rows describing the governed
  tool action plus any explicit commerce or metered-billing scope
- a separate `transaction_context` block carrying the signed `intent_id`,
  `intent_hash`, approval token identifiers, runtime-assurance context,
  optional delegated `call_chain`, and one optional `identity_assertion`
  continuity envelope

That projection is always derived from the signed governed receipt metadata.
Trust-control does not accept a second independently editable authorization
document, because that would silently widen authority or billing scope outside
the approval-bound intent hash.

The report now declares ARC's first normative enterprise-facing profile over
that projection:

- report `schema`: `arc.oauth.authorization-context-report.v1`
- profile `schema`: `arc.oauth.authorization-profile.v1`
- profile `id`: `arc-governed-rar-v1`

This profile is intentionally narrow. ARC claims one RFC-9396-style
authorization-details mapping over governed receipt truth plus a separate
transaction-context block carrying the approval-bound intent hash, approval
evidence, runtime-assurance posture, delegated call-chain context, and one
optional identity assertion continuity object. If a governed receipt cannot be
projected into that profile truthfully, ARC fails closed and does not emit a
partial authorization-context report.

Each authorization-context row now also carries explicit sender-bound
semantics:

- `senderConstraint.subjectKey`
- `senderConstraint.subjectKeySource`
- `senderConstraint.matchedGrantIndex`
- `senderConstraint.proofRequired`
- optional `senderConstraint.proofType`
- optional `senderConstraint.proofSchema`
- `senderConstraint.runtimeAssuranceBound`
- `senderConstraint.delegatedCallChainBound`

ARC resolves that sender truth from receipt attribution plus persisted
capability lineage. If the capability snapshot is missing, the grant cannot be
resolved, the subject binding is inconsistent, or a required DPoP proof shape
cannot be represented, the report fails closed instead of degrading silently.

ARC's hosted authorization edge now publishes and enforces the same bounded
contract at request time. The published `arc_authorization_profile` includes:

- one request-time contract naming `authorization_details` and
  `arc_transaction_context` as the only supported ARC request parameters and
  access-token claims
- one resource-binding contract requiring the OAuth `resource` parameter to
  match the protected-resource metadata and requiring bearer admission to match
  the same protected resource through `aud`, `resource`, or both
- one artifact-boundary contract stating that access tokens are runtime
  authorization artifacts while approval tokens, ARC capabilities, and review
  evidence remain non-bearer artifacts

At request time, ARC only accepts the bounded governed detail family
`arc_governed_tool`, `arc_governed_commerce`, and
`arc_governed_metered_billing`, and at least one governed-tool row must be
present. Malformed transaction context, unsupported detail types, mismatched
resource indicators, stale identity assertions, mismatched verifier bindings,
request-binding mismatches, or ambiguous approval/runtime-assurance/call-chain
fragments fail closed before token issuance.

ARC also supports one bounded sender-constrained continuation contract on that
same hosted authorization path. The request may carry:

- `arc_sender_dpop_public_key`
- `arc_sender_mtls_thumbprint_sha256`
- `arc_sender_attestation_sha256`

If ARC approves the request, the resulting sender constraint is persisted on
the authorization code and then projected into access tokens through `cnf`:

- `cnf.arcSenderKey`
- `cnf["x5t#S256"]`
- `cnf.arcAttestationSha256`

Runtime admission then enforces the same bound sender proof continuity:

- DPoP-bound flows must present a valid proof during token exchange and again
  on protected-resource admission, including nonce, `jti`, `htm`, and `htu`
  checks over the actual runtime request
- mTLS-bound flows must present a matching
  `x-arc-mtls-thumbprint-sha256` header
- attestation-bound flows must present a matching
  `x-arc-runtime-attestation-sha256` header, and that digest must also match
  `arc_transaction_context.runtimeAssuranceEvidenceSha256`

Attestation alone never authorizes a sender. ARC only accepts the
attestation-bound profile when it is paired with DPoP or mTLS continuity over
the same request. Missing, stale, replayed, or mismatched sender proof fails
closed as `invalid_request`, `invalid_grant`, or bearer denial depending on
where the mismatch occurs.

The hosted edge now publishes the same profile through OAuth-family discovery
documents:

- `/.well-known/oauth-protected-resource/mcp`
- `/.well-known/oauth-authorization-server/{issuer-path}`

Both documents include `arc_authorization_profile`, which mirrors the
canonical profile id/schema, sender-constraint expectations, request-time
parameter names, resource-binding rules, and artifact-boundary expectations.
Discovery is informational only. ARC does not widen trust from discovery
documents alone, and the edge fails closed if protected-resource and
authorization-server metadata disagree about the advertised ARC profile or
authorization-server issuer.

`/v1/reports/authorization-profile-metadata` packages that same profile into a
machine-readable artifact for enterprise review. The report publishes:

- metadata `schema`: `arc.oauth.authorization-metadata.v1`
- canonical ARC profile `id` and `schema`
- the authorization-context report schema
- supported discovery paths
- explicit support boundaries
- example field mappings for authorization details, transaction context, and
  sender constraints
- request-time contract, resource-binding, and runtime-versus-audit artifact
  boundaries

`/v1/reports/authorization-review-pack` packages a reviewer-facing evidence
bundle over the same filter surface as `/v1/reports/authorization-context`.
Each returned record includes:

- the derived `authorization_context` row
- the typed `governed_transaction` metadata block
- the full signed `ArcReceipt`

This pack exists so enterprise IAM reviewers can trace one governed action from
approval-bound intent through standards-legible projection back to canonical
receipt truth without bespoke ARC-specific joins.

ARC also validates assurance-bound and delegated-call-chain projection
integrity fail closed. If a row claims runtime assurance, the projection must
also carry the accepted verifier and evidence digest. If a row claims
delegated call-chain context, the projection must carry non-empty `chainId`,
`parentRequestId`, `originSubject`, and `delegatorSubject` values, plus a
non-empty `parentReceiptId` when present. ARC does not emit partial or
degraded enterprise-profile rows when that projection cannot be represented
truthfully.

`/v1/capabilities/issue` accepts the same typed capability-issuance contract
used by the local CLI path, including optional `runtimeAttestation` evidence.
When trust-control is started with a policy containing
`extensions.runtime_assurance`, issuance resolves the highest satisfied runtime
assurance tier, enforces that tier's scope ceiling, and marks economically
sensitive grants with an explicit minimum runtime-assurance constraint for
later governed execution. `/health` also reports whether this runtime
assurance issuance policy is configured.

When the same policy also defines
`extensions.runtime_assurance.trusted_verifiers`, issuance and governed
execution treat runtime attestation as explicit trusted evidence rather than
opaque metadata. Each trusted-verifier rule binds one `{schema, verifier}`
pairs to an effective runtime-assurance tier plus optional verifier-family,
maximum evidence age, attestation-type, and required-assertion constraints. If
trusted-verifier rules are configured, carried attestation evidence must match
one rule and satisfy its freshness and claim constraints or the request fails
closed. If no
trusted-verifier rules are configured, ARC continues to use the normalized raw
attestation tier after validating evidence time bounds and workload-identity
binding.

When `runtimeAttestation` carries workload identity, ARC currently recognizes
one normalized mapping shape:

- explicit `workloadIdentity { scheme, credentialKind, uri, trustDomain, path }`
- `scheme: spiffe`
- `credentialKind: uri | x509_svid | jwt_svid`

If only the legacy raw `runtimeIdentity` field is present and it is a valid
SPIFFE URI, ARC derives the same normalized mapping for policy, governed
validation, and receipt metadata. If `runtimeIdentity` is non-SPIFFE, ARC
preserves it as opaque verifier metadata and does not invent a typed identity
projection. If an explicit `workloadIdentity` conflicts with `runtimeIdentity`,
or if a claimed SPIFFE identifier is malformed, issuance and governed
execution fail closed.

ARC's first concrete verifier bridge is Azure Attestation JWT normalization.
That bridge verifies a signed Azure MAA token against operator-supplied or
metadata-resolved RSA signing material, preserves vendor claims under
`claims.azureMaa`, optionally projects one configured
`x-ms-runtime.claims.*` SPIFFE URI through the same workload-identity mapping
rules above, and normalizes the raw verifier output to `attested`. That raw
output can only rebind to `verified` or another effective runtime tier through
explicit `trusted_verifiers` policy.

ARC's second concrete verifier bridge is AWS Nitro attestation document
verification. That bridge verifies an AWS Nitro `COSE_Sign1` document with
`ES384`, validates certificate anchoring against operator-configured trusted
roots, enforces `SHA384` PCR expectations, freshness, optional nonce matching,
and debug-mode denial by default, preserves vendor claims under
`claims.awsNitro`, and likewise normalizes the raw verifier output to
`attested` until later trust policy rebinding says otherwise.

ARC's third concrete verifier bridge is Google Confidential VM JWT
normalization. That bridge verifies a signed Google attestation token against
metadata-resolved `JWKS` material, enforces issuer, audience, hardware-model,
and secure-boot constraints, preserves vendor claims under
`claims.googleAttestation`, and also keeps the raw normalized verifier output
at `attested` until explicit `trusted_verifiers` policy rebinds it higher.

Verifier adapters now also emit a canonical runtime-attestation appraisal
artifact over the same evidence. The appraisal contract separates:

- evidence identity (`schema`, `verifier`, time bounds, evidence digest)
- verifier-family and adapter identity
- normalized assertions ARC is willing to compare across verifier families
- vendor-scoped claims preserved without claiming cross-vendor equivalence
- explicit reason codes and the effective runtime tier carried forward

ARC treats that appraisal contract as the stable adapter boundary. New
verifier families must project into the same appraisal shape instead of
inventing new policy-specific blobs.

When ARC emits governed receipt metadata or underwriting evidence derived from
trusted runtime attestation, it carries the accepted attestation `schema`,
optional `verifierFamily`, resolved effective tier, verifier identifier, and
evidence digest so downstream consumers can audit why a stronger trust posture
was available.

`POST /v1/reports/runtime-attestation-appraisal` is ARC's operator-facing
export surface for that same contract. It returns a signed appraisal report
containing:

- the canonical appraisal document over one carried runtime-attestation input
- one policy-visible outcome describing whether configured trusted-verifier
  rules accepted the evidence and which effective tier ARC resolved
- one immutable signature over the export body so operators and downstream
  reviewers can exchange the artifact without re-querying the live verifier

That report is intentionally narrower than a generic attestation-results or
EAT federation protocol. ARC claims one canonical appraisal contract plus
concrete Azure, AWS Nitro, and Google Confidential VM bridges, not universal
cross-vendor attestation interoperability.

`/v1/reports/behavioral-feed` is the insurer/risk export surface. It returns a
signed behavioral-feed document with:

- explicit filter scope (`capability_id`, `agent_subject`, tool filters,
  time window, receipt-detail limit)
- privacy/export boundary metadata derived from the canonical evidence-export
  contract
- separate decision, governed-action, settlement, and metered-billing
  reconciliation summaries
- optional subject reputation summary when the feed is scoped to one agent
- per-receipt detail rows carrying signed decision and governed metadata plus
  separate mutable metered-reconciliation state when applicable

The behavioral feed is a truthful evidence export, not an underwriting model.
It reuses canonical receipt, settlement, reputation, and shared-evidence state
instead of inventing a second telemetry pipeline.

`/v1/reports/underwriting-input` is the signed underwriting policy-input
surface. It reuses the same canonical receipt, reputation, certification,
runtime-assurance, settlement, metered-billing, and shared-evidence substrate
to emit:

- one explicit underwriting-query scope with required anchor filters and a
  bounded receipt-reference limit
- a stable `arc.underwriting.taxonomy.v1` vocabulary of risk classes and
  reason codes
- one canonical evidence snapshot covering receipt summaries plus optional
  reputation, certification, and runtime-assurance summaries
- derived risk signals that reference existing ARC evidence identifiers rather
  than inventing a second mutable telemetry stream

This underwriting-input artifact is a signed input contract, not yet a final
underwriting decision. It exists so later underwriting phases can evaluate one
typed, auditable evidence package instead of ad hoc partner JSON.

`/v1/reports/underwriting-decision` is the deterministic operator-facing
runtime underwriting surface. It evaluates the canonical underwriting-input
snapshot against ARC's default decision policy and returns:

- one bounded outcome in the vocabulary `approve`, `reduce_ceiling`,
  `step_up`, or `deny`
- one explicit decision-policy snapshot with receipt-history, reputation, and
  runtime-assurance thresholds
- explanation findings carrying normalized reason codes, optional originating
  underwriting-signal reasons, concrete receipt or reconciliation evidence
  references, and operator-remediation hints
- a suggested ceiling factor only when the bounded outcome is
  `reduce_ceiling`

This underwriting-decision report is intentionally separate from signed
receipts and from the signed underwriting-input snapshot. It is a deterministic
evaluation surface over canonical evidence, not the durable signed artifact
that operators later persist.

`POST /v1/underwriting/decisions/issue` signs and persists that durable
underwriting artifact. The signed decision envelope carries:

- one immutable decision artifact over the phase-50 evaluation snapshot
- one explicit lifecycle and review state at issuance time
- one budget recommendation in the bounded vocabulary
  `preserve`/`reduce`/`hold`/`deny`
- one premium state in the bounded vocabulary
  `quoted`/`withheld`/`not_applicable`, plus basis points and a quoted amount
  when ARC can truthfully price exposure; mixed-currency governed exposure
  withholds the amount quote rather than comparing raw units across currencies
- one optional `supersedesDecisionId` reference that links a replacement
  decision without rewriting the original signed record

`GET /v1/reports/underwriting-decisions` lists persisted signed decisions plus
their current lifecycle projection and latest appeal status. The list/report
surface does not mutate or re-sign prior decisions: the original signed
artifact remains immutable, while the store projects current lifecycle state
such as `active` or `superseded`. Premium totals are partitioned by currency
in the report summary; the legacy single total is populated only when the
matching quoted premiums share one currency.

`POST /v1/underwriting/appeals` and
`POST /v1/underwriting/appeals/resolve` manage explicit appeal records over
persisted underwriting decisions. Appeals may link to a replacement decision
only when the appeal is accepted, and they do not rewrite canonical execution
receipts or prior signed underwriting artifacts.

`POST /v1/reports/underwriting-simulation` is the non-mutating operator
simulation surface. It evaluates one operator-supplied underwriting policy
against the same canonical evidence snapshot used by the default runtime
evaluator and returns:

- the canonical underwriting-input evidence package used for the comparison
- the default ARC decision evaluation for that evidence
- the simulated decision evaluation for the supplied policy
- one explicit delta showing whether the outcome or risk class changed and
  which normalized reason labels were added or removed

The simulation surface does not persist or supersede any underwriting
decision. It exists so operators can inspect policy changes before or after
deployment without mutating signed decision artifacts.

`GET /v1/reports/exposure-ledger` is ARC's signed economic-position surface
over the same governed receipt, settlement, metered-billing, and persisted
underwriting-decision truth. It returns:

- one bounded query with required anchor filters and capped receipt/decision
  limits
- per-receipt position rows carrying governed ceiling, reserve, settlement,
  provisional-loss, and evidence-reference detail
- persisted underwriting decision rows so premium and supersession truth can
  be reviewed alongside receipt-side exposure
- per-currency aggregate positions covering governed maximum exposure,
  reserved, settled, pending, failed, provisional-loss, recovered, quoted
  premium, and active quoted-premium totals
- one explicit support-boundary block describing what ARC does and does not
  claim about the projected ledger

This ledger is intentionally narrower than a full claims or recovery system.
ARC does not currently claim cross-currency netting, claim-adjudication
closure, or finalized recovery lifecycle semantics in the signed export.
Mixed or contradictory row truth fails closed: if ARC cannot represent one
receipt row truthfully inside one currency position, it rejects the report
instead of fabricating a blended exposure row.

`GET /v1/reports/credit-scorecard` is ARC's signed, subject-scoped credit
posture surface built from that same exposure ledger plus the canonical local
reputation inspection. It returns:

- one bounded subject-scoped query over exposure and persisted underwriting
  decision history
- one explicit weighted dimension model covering reputation support, settlement
  discipline, loss pressure, and exposure stewardship
- one bounded overall score, confidence level, and score band
- one explicit probation block carrying the receipt/day thresholds that kept
  the score in probationary posture
- one typed anomaly list with concrete evidence references back to receipts,
  settlement rows, underwriting-decision coverage, or reputation inspection

This scorecard is intentionally narrower than capital-allocation or facility
policy on its own. Missing subject scope or missing matching exposure fails
closed. Sparse history can still produce a scorecard, but only as explicit
low-confidence probationary posture rather than a confident facility-ready
decision.

`GET /v1/reports/facility-policy` evaluates that scorecard plus runtime
assurance and optional tool-server certification posture into one bounded
capital-allocation report. `POST /v1/facilities/issue` signs and persists that
same report as a facility artifact, and `GET /v1/reports/facilities` projects
current lifecycle state over persisted facility rows. These surfaces make the
following operator claims explicit:

- ARC can grant one bounded single-currency credit limit with utilization,
  reserve, concentration, and TTL terms when score, assurance, and
  certification posture are sufficient
- ARC can deny allocation explicitly when runtime assurance or required
  certification evidence is missing
- ARC can force manual review when the book is mixed-currency or still carries
  settlement-risk posture that ARC will not auto-net or auto-price away
- supersession and expiry change operator-visible lifecycle state without
  rewriting the previously signed facility artifact

This is still a bounded policy surface, not a live capital market. ARC does
not lock collateral, execute bonds, slash reserves, clear external capital, or
claim autonomous insurer pricing from this phase alone.

`GET /v1/reports/credit-backtest` is ARC's replay and qualification surface for
that same credit layer. It evaluates one subject-scoped historical window set
over signed exposure, scorecard, and facility-policy logic and returns:

- one bounded set of replay windows with stable `since`/`until` timestamps
- one explicit drift vocabulary covering score-band shifts, facility
  disposition changes, stale evidence, over-utilization, missing runtime
  assurance, missing active certification, pending backlog, failed backlog,
  and mixed-currency books
- one aggregate summary of drift, denial, manual-review, and stale-evidence
  counts suitable for qualification reports and milestone audits

Backtests are intentionally deterministic and fail closed on missing subject
scope or invalid window ranges. They replay ARC's current bounded policy over
historical evidence; they do not invent a second mutable actuarial store.

`GET /v1/reports/provider-risk-package` is ARC's signed provider-facing capital
review package. It returns:

- one signed exposure ledger and one signed credit scorecard over the same
  scoped evidence set
- one current facility-policy evaluation plus the latest persisted facility
  snapshot when one exists
- one runtime-assurance and certification posture summary for the scoped book
- one recent-loss history derived from the newest matching failed or still
  action-required settlement rows rather than from an arbitrary paged exposure
  slice
- one provider-facing evidence reference set suitable for external capital
  review without re-querying live operator state

This package is still a bounded review artifact rather than a live financing
contract. ARC can now package honest credit posture for external capital review,
but it still does not bind external capital, execute reserves, or run a
liability market from `v2.18` alone.

`GET /v1/reports/bond-policy` evaluates canonical exposure plus the latest
active granted facility into one reserve-state report. `POST /v1/bonds/issue`
signs and persists that same report as a bond artifact, and
`GET /v1/reports/bonds` projects current lifecycle state over persisted bond
rows. These surfaces make the following operator claims explicit:

- ARC can express reserve posture as one typed `lock`, `hold`, `release`, or
  `impair` decision over canonical exposure and the latest active facility
- bond artifacts preserve collateral amount, reserve requirement, outstanding
  exposure, coverage ratio, and capital-source provenance back to the active
  facility terms
- mixed-currency reserve accounting fails closed with `409 Conflict` instead
  of auto-netting or inventing blended collateral state
- supersession changes operator-visible lifecycle state without rewriting the
  previously signed bond artifact

This is now reserve-backed runtime autonomy gating with an intentionally
bounded execution scope. ARC can require an explicit autonomy context plus an
active signed delegation bond before delegated or autonomous governed
execution proceeds, and it fails closed when bond lifecycle, support boundary,
reserve disposition, call-chain, or runtime-assurance prerequisites are
missing. ARC still does not slash reserves, execute external escrow, or claim
complete loss or recovery lifecycle semantics from phases `85` and `86`
alone.

`GET /v1/reports/bond-loss-policy` now evaluates one explicit bond-loss
lifecycle step over the persisted bond plus canonical recent-loss evidence.
`POST /v1/bond-losses/issue` signs and persists that same evaluation as an
immutable lifecycle artifact, and `GET /v1/reports/bond-losses` projects the
current event stream for operator review. These surfaces make the following
claims explicit:

- ARC records delinquency, recovery, reserve-release, and write-off as
  separate immutable signed artifacts instead of mutating bond, facility, or
  receipt rows in place
- delinquency booking is derived from the newest matching failed-loss evidence
  rather than from a truncated exposure page
- recovery and write-off amounts are bounded by previously recorded
  outstanding delinquency, with currency mismatches failing closed
- reserve release requires both cleared delinquency and no unbooked remaining
  outstanding exposure

This is still bounded lifecycle accounting rather than a claims network or
live escrow engine. ARC now makes bond-backed loss and recovery state
auditable, but it still does not execute external collateral movement, insurer
placement, or cross-organization claim adjudication from phase `87` alone.

### 9.1 Launch And Standards Boundary

The current launch and standards-facing ARC profile is intentionally bounded to
shipping evidence plus deterministic operator-visible runtime evaluation:

- signed receipts, checkpoints, and evidence-export primitives
- ARC portable-trust and certification surfaces
- signed behavioral-feed export
- signed underwriting-input snapshot
- deterministic underwriting-decision report over canonical evidence
- signed underwriting decisions with explicit budget, premium, and appeal
  linkage semantics
- non-mutating underwriting simulation over canonical evidence
- signed exposure-ledger export with per-currency economic-position totals
- signed credit-scorecard export with explicit probation and anomaly semantics
- bounded facility-policy evaluation plus signed facility artifacts and
  lifecycle reporting
- deterministic credit backtests over historical evidence windows
- signed provider-facing risk packages for external capital review
- reserve-backed autonomy-tier gating over explicit delegation-bond posture
- immutable bond-loss lifecycle artifacts over delinquency, recovery,
  reserve-release, and write-off state
- non-mutating bonded-execution simulation with operator control policy,
  kill-switch semantics, and sandbox qualification over signed bond truth
- curated liability-provider registry artifacts with explicit jurisdiction,
  coverage-class, currency, and evidence-requirement policy plus fail-closed
  provider resolution
- provider-neutral liability quote-request, quote-response, placement, and
  bound-coverage artifacts over one signed provider-risk package, with
  fail-closed stale-provider, expiry, mismatch, and unsupported-policy checks
- immutable liability claim-package, provider-response, dispute, and
  adjudication artifacts linked back to bound coverage, exposure, bond, loss,
  and receipt evidence, with fail-closed oversized-claim and invalid-dispute
  state checks
- runtime-assurance-aware issuance and governed-execution constraints

The current liability-market claim is intentionally bounded: ARC now proves a
curated provider-admission, quote/bind, and claim/dispute/adjudication
orchestration layer over canonical evidence, but not an insurer network,
claims-payment rail, autonomous pricing engine, or permissionless market.

External launch, partner, or standards materials should derive claims from this
protocol document, the release-qualification corpus, and the release audit.
They must not imply liability-market capital allocation, autonomous insurer
pricing beyond the documented underwriting policy surface, claim or dispute
adjudication beyond the documented liability-market surface, or theorem-prover
completion beyond the boundary defined in Section 5.4.

## 10. Portable Trust And Federation

### 10.1 Agent Passport

ARC now issues these primary portable-trust schema identifiers while still
accepting legacy `arc.*` artifacts:

| Artifact | Schema |
| --- | --- |
| Agent passport | `arc.agent-passport.v1` |
| Verifier policy | `arc.passport-verifier-policy.v1` |
| Presentation challenge | `arc.agent-passport-presentation-challenge.v1` |
| Presentation response | `arc.agent-passport-presentation-response.v1` |

The current shipped semantics are:

- issuer and subject identities currently remain `did:arc`
- a passport may contain multiple credentials from different issuers as long as
  they all bind to one subject
- verifier evaluation remains per credential
- acceptance requires at least one credential to satisfy the verifier policy
- replay-safe challenge verification can be backed by durable SQLite state
- ARC may expose one public holder transport over stored challenge state:
  `GET /v1/public/passport/challenges/{challenge_id}` and
  `POST /v1/public/passport/challenges/verify`
- legacy `arc.*` passport, verifier-policy, challenge, and response documents
  remain valid for verification

### 10.1.1 OID4VCI-Compatible Passport Issuance

ARC now ships one conservative OID4VCI-compatible issuance lane for the
existing passport artifact. The transport surface is:

- `GET /.well-known/openid-credential-issuer`
- `POST /v1/passport/issuance/offers`
- `POST /v1/passport/issuance/token`
- `POST /v1/passport/issuance/credential`

The profile is intentionally narrow:

- `POST /v1/passport/issuance/offers` is operator-authenticated and creates one
  replay-safe offer over an existing ARC passport artifact
- the always-available native credential profile is configuration id
  `arc_agent_passport` with format `arc-agent-passport+json`
- when the issuer has an explicit signing key, it may also advertise two
  projected portable profiles:
  `arc_agent_passport_sd_jwt_vc` with format `application/dc+sd-jwt`, and
  `arc_agent_passport_jwt_vc_json` with format `jwt_vc_json`
- when any projected portable profile is advertised, the issuer also exposes
  `GET /.well-known/jwks.json`,
  `GET /.well-known/arc-passport-sd-jwt-vc`, and
  `GET /.well-known/arc-passport-jwt-vc-json`
- issuer metadata may advertise `arcProfile.passportStatusDistribution` when
  the operator has configured a public read-only lifecycle resolve plane
- the native delivered credential remains the existing ARC `AgentPassport`
  artifact, so issuer and subject identities inside the credential stay
  `did:arc`
- the projected portable credential is derived from the same verified passport
  truth and does not establish a second ARC identity root
- the projected `application/dc+sd-jwt` profile keeps `iss`, `sub`, `vct`,
  `cnf`, `arc_passport_id`, `arc_subject_did`, and `arc_credential_count`
  anchored in the signed payload and only permits `arc_issuer_dids`,
  `arc_merkle_roots`, and `arc_enterprise_identity_provenance` as supported
  disclosures
- the projected `jwt_vc_json` profile keeps `iss`, `sub`, `cnf.jwk`,
  `vc.type`, `vc.credentialSubject.id`,
  `vc.credentialSubject.arcPassportId`,
  `vc.credentialSubject.arcCredentialCount`,
  `vc.credentialSubject.arcIssuerDids`,
  `vc.credentialSubject.arcMerkleRoots`, and
  `vc.credentialSubject.arcEnterpriseIdentityProvenance` anchored in the
  signed JWT VC payload, and it declares the same ARC claim catalog with
  `supportsSelectiveDisclosure=false` so those ARC claims are always disclosed
  in this profile
- credential delivery may include an
  `arcCredentialContext.passportStatus` sidecar that binds the delivered
  passport id to one or more lifecycle resolve URLs plus a cache hint
- the HTTPS `credential_issuer` is a transport and discovery identifier; it is
  not a new trust root
- pre-authorized codes and issuance access tokens are single-use and
  short-lived
- if an issuer advertises portable lifecycle support, offer creation and
  credential delivery fail closed unless the target passport is already
  published active with at least one resolve URL
- unsupported profile ids, mismatched subjects, mismatched formats, or issuer
  metadata conflicts fail closed

Portable lifecycle resolution itself remains ARC-native and operator-scoped:

- the default trust-control public read surface is
  `GET /v1/public/passport/statuses/resolve/{passport_id}`
- each distributed `resolve_url` is a base endpoint; portable consumers
  resolve one passport by appending `/{passport_id}`
- any distributed `resolve_url` must be paired with an explicit
  `cache_ttl_secs`; advertising public lifecycle discovery without a freshness
  bound is invalid
- the resolution document remains the richer ARC lifecycle shape with
  `active`, `stale`, `superseded`, `revoked`, and `notFound`, plus
  `updated_at` on every non-`notFound` response
- only `active` is a healthy portable lifecycle state
- `stale` means the artifact is still the current published passport, but the
  last lifecycle update is older than the advertised TTL and must be denied
  fail closed
- `superseded` is not silently collapsed into revocation
- `notFound`, malformed lifecycle responses, stale lifecycle state, and
  lifecycle distributions that omit TTL are not healthy states for portable
  consumers

This protocol does not yet claim support for generic `ldp_vc`, generic JWT VC
interoperability beyond ARC's documented passport profile family, generic
SD-JWT VC interoperability beyond ARC's documented passport profile family,
public issuer discovery, or wallet qualification beyond this ARC-specific
profile set.

### 10.1.2 OID4VP Verifier Interop

ARC now ships one narrow verifier-side OID4VP bridge over the projected
passport credential lane. The public transport surface is:

- `GET /.well-known/arc-oid4vp-verifier`
- `GET /.well-known/jwks.json`
- `POST /v1/passport/oid4vp/requests`
- `GET /v1/public/passport/wallet-exchanges/{request_id}`
- `GET /v1/public/passport/oid4vp/requests/{request_id}`
- `GET /v1/public/passport/oid4vp/launch/{request_id}`
- `POST /v1/public/passport/oid4vp/direct-post`

`POST /v1/passport/oid4vp/requests` now returns three coordinated views of
the same verifier transaction:

- the signed OID4VP request object
- the OID4VP request transport bundle
- one transport-neutral wallet exchange descriptor plus one canonical
  transaction-state object

The verifier may also opt into one bounded `identityAssertion` object on that
request. When present, ARC treats it as continuity metadata rather than proof
of new authority:

- `verifierId` must match the HTTPS verifier `client_id`
- `boundRequestId` must match the canonical ARC wallet exchange id and OID4VP
  `request_id`
- `subject` and `continuityId` carry verifier-local continuity context
- optional `provider` and `sessionHint` may describe the source of that
  continuity
- `issuedAt` and `expiresAt` must remain fresh and must not outlive the parent
  OID4VP request
- the same canonical object is echoed through the wallet-exchange projection,
  OID4VP verification result, and hosted `arc_transaction_context` lane when
  the verifier chooses to reuse it there

`GET /v1/public/passport/wallet-exchanges/{request_id}` exposes that neutral
descriptor and current transaction state without widening verifier admin
authority. The descriptor keeps ARC's trust roots aligned:

- `exchange_id` is the canonical ARC wallet transaction identifier and is
  currently aligned to the OID4VP `request_id`
- replay anchors are the existing signed verifier request id, nonce, state,
  and request-object hash
- same-device launch remains one `openid4vp://authorize?request_uri=...`
  artifact
- cross-device and relay delivery currently reuse one HTTPS verifier launch
  URL instead of inventing a second public verifier authority
- canonical transaction states are `issued`, `consumed`, and `expired`
- optional identity assertions stay derived from that same canonical request
  id and do not create a second mutable session store

The profile is intentionally narrow:

- verifier identity is one HTTPS `client_id` with
  `client_id_scheme=redirect_uri`
- request objects are signed with EdDSA and fetched by `request_uri`
- same-device launch uses `openid4vp://authorize?request_uri=...`
- cross-device launch is one HTTPS URL that resolves back to that same
  `request_uri`-based verifier transaction
- relay-capable delivery reuses that same HTTPS verifier transaction rather
  than introducing a second launch trust root
- holder responses use `response_type=vp_token` and
  `response_mode=direct_post.jwt`
- ARC currently supports exactly one requested credential with format
  `application/dc+sd-jwt` and type
  `https://arc.dev/credentials/types/arc-passport-sd-jwt-vc/v1`
- verifier trust bootstrap is one ARC verifier metadata document plus one
  verifier `JWKS`
- verifier or issuer key rotation may preserve active request and credential
  validation only when the rotated trusted keyset is still published through
  that `JWKS`
- any identity assertion remains optional and verifier-scoped; ARC does not
  make external identity providers mandatory for wallet presentation
- missing metadata, stale requests, replayed or contradictory wallet exchange
  state, stale or mismatched identity assertions, unsupported request shapes,
  stale lifecycle state, mismatched issuers, or untrusted keys fail closed

This protocol does not yet claim generic OID4VP wallet compatibility, SIOP,
DIDComm, or public verifier marketplace semantics beyond this ARC-specific
profile.

### 10.1.3 Holder Presentation Transport

ARC now ships one conservative holder-facing transport over the existing
passport presentation artifacts. The proof objects do not change:

- the verifier/admin still creates the signed
  `arc.agent-passport-presentation-challenge.v1`
- the holder still signs the existing
  `arc.agent-passport-presentation-response.v1`
- verifier replay truth still lives in the durable challenge store

The transport surface is intentionally narrow:

- admin or verifier challenge creation remains on
  `POST /v1/passport/challenges`
- admin or verifier challenge verification remains on
  `POST /v1/passport/challenges/verify`
- optional public holder fetch is
  `GET /v1/public/passport/challenges/{challenge_id}`
- optional public holder submit is
  `POST /v1/public/passport/challenges/verify`

When trust-control returns transport metadata for a created challenge, it uses
one ARC-native contract with:

- `challengeId`
- `challengeUrl`
- `submitUrl`

The contract is challenge-bound, not session-marketplace state:

- public fetch is read-only and resolves one already-stored verifier challenge
  by `challengeId`
- public submit verifies the holder response against stored verifier truth and
  consumes the replay-safe challenge record on success
- public routes do not expose verifier policy CRUD, challenge creation, or
  other admin mutation
- missing `challengeId`, expired challenges, consumed challenges, malformed
  stored challenge state, or holder submissions that do not match stored
  verifier truth fail closed

This transport is ARC-specific. It coexists with the separate OID4VP verifier
profile above, but it does not itself imply generic OID4VP, DIDComm, or other
wallet transport compatibility claims.

### 10.2 Federation Artifacts

The shipped cross-org artifact schemas now use ARC-primary identifiers:

| Artifact | Schema |
| --- | --- |
| Evidence export manifest | `arc.evidence_export_manifest.v1` |
| Federation policy | `arc.federation-policy.v1` |
| Federated evidence share | `arc.federated-evidence-share.v1` |
| Federated delegation policy | `arc.federated-delegation-policy.v1` |

The supported contract includes:

- signed bilateral evidence-export policy documents
- verified import of exported evidence packages
- shared-evidence reporting without pretending foreign receipts are native local
  receipts
- parent-bound continuation from an imported upstream capability into a new
  local delegation anchor
- legacy `arc.*` evidence and delegation artifacts remain valid for import and
  verification

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

`arc-a2a-adapter` is a thin bridge for A2A v1.0.0, not a new A2A wire
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

ARC currently uses a frozen adapter-local metadata convention to route a call
to one A2A
skill:

```json
{
  "arc": {
    "targetSkillId": "research",
    "targetSkillName": "Research"
  }
}
```

That convention is explicit and is not presented as a core A2A protocol field.

## 12. Certification Contract

ARC ships signed certification checks with primary schema:

```text
arc.certify.check.v1
```

The local or trust-control-backed registry uses:

```text
arc.certify.registry.v1
```

The multi-operator discovery network uses:

```text
arc.certify.discovery-network.v1
```

The certification contract covers:

- evaluation of a declared conformance result corpus
- one fail-closed criteria profile today: `conformance-all-pass-v1`
- one fail-closed evidence profile today: `conformance-report-bundle-v1`
- signed artifacts with verdict, criteria profile, evidence profile, corpus
  digests, findings, and signer-bound evidence provenance
- registry publication, listing, get, resolve, revoke, and dispute recording
- public read-only metadata, resolve, search, and transparency surfaces per
  operator
- authenticated multi-operator publication, discovery aggregation, search,
  transparency, and policy-bound consume flows
- operator-facing resolution states: `active`, `revoked`, `superseded`,
  `not-found`
- dispute states: `open`, `under-review`, `resolved-no-change`,
  `resolved-revoked`
- legacy `arc.certify.check.v1` and `arc.certify.registry.v1` remain valid
  for verification and load
- registry/discovery results that remain explicitly scoped to the operator that
  published them
- public discovery metadata that must fail closed when stale, mismatched, or
  malformed
- public listing consumption that remains explicitly policy-controlled and
  does not widen runtime trust from visibility alone

This is a governed public certification marketplace surface backed by signed
operator evidence. It is not a permissionless trust oracle, global mutable
trust network, or automatic runtime-admission mechanism.

## 13. Observability Contract

Production observability is part of the shipped contract.

Stable operator surfaces include:

- trust-control `/health` and `/v1/internal/cluster/status`
- hosted edge `/admin/health`, `/admin/sessions`, and session trust views
- provider-admin registry inspection surfaces
- certification registry status surfaces
- certification marketplace metadata, search, transparency, and dispute
  surfaces
- operator report and shared-evidence analytics
- durable A2A task-registry rejection when follow-up correlation is unsafe

Field additions are allowed. Silent fail-open downgrades are not.

For operational guidance, see:

- `docs/release/OBSERVABILITY.md`
- `docs/release/OPERATIONS_RUNBOOK.md`

## 14. Explicit Gaps

The following are intentionally outside the shipped `v2` contract:

- permissionless or auto-trusting public federation or certification
  marketplace semantics
- public federation beyond configured local or operator-controlled trust
  surfaces
- automatic enterprise identity propagation into every portable artifact
- custom A2A auth schemes beyond the shipped matrix
- full automatic wallet/distribution semantics for passports
- performance claims beyond the qualification and documentation surfaces

These gaps are documented explicitly so operators and integrators do not have
to infer them from source code.
